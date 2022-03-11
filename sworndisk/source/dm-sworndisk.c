#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/jiffies.h>
#include <linux/mempool.h>
#include <linux/rwsem.h>
#include <crypto/skcipher.h>
#include <linux/bitmap.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>
#include <linux/scatterlist.h> 

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/memtable.h"
#include "../include/bio_operate.h"
#include "../include/segment_buffer.h"

/* For underlying device */
struct dm_sworndisk_target {
    struct dm_dev *data_dev;
    struct dm_dev *metadata_dev;
    sector_t start;
    struct workqueue_struct *wq;
    struct work_struct deferred_bio_worker;
    struct bio_list deferred_bios;
	struct dm_sworndisk_metadata *cmd;
    struct segment_buffer *seg_buffer;
    struct bio_set* bio_set; 
    spinlock_t lock;
};


static void defer_bio(struct dm_sworndisk_target *mdt, struct bio *bio) {
	unsigned long flags;

	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_add(&mdt->deferred_bios, bio);
	spin_unlock_irqrestore(&mdt->lock, flags);

	queue_work(mdt->wq, &mdt->deferred_bio_worker);
}


static void process_deferred_bios(struct work_struct *ws) {
	struct dm_sworndisk_target *mdt = container_of(ws, struct dm_sworndisk_target, deferred_bio_worker);

	unsigned long flags;
	struct bio_list bios;
	struct bio* bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_merge(&bios, &mdt->deferred_bios);
	bio_list_init(&mdt->deferred_bios);
	spin_unlock_irqrestore(&mdt->lock, flags);

	while ((bio = bio_list_pop(&bios))) {
        mdt->seg_buffer->push_bio(mdt->seg_buffer, bio);
	}
}


static int dm_sworndisk_target_map(struct dm_target *target, struct bio *bio)
{
    int r;
    sector_t lba;
    struct mt_value *mv;
    struct bio* crypt_bio;
    struct bio_crypt_context* ctx;
    struct default_segment_buffer* buf_instance;
    struct dm_sworndisk_target* mdt;

    mdt = target->private;
    bio_set_dev(bio, mdt->data_dev->bdev);
    if (bio_sectors(bio) > BIO_CRYPT_SECTOR_LIMIT)
        dm_accept_partial_bio(bio, BIO_CRYPT_SECTOR_LIMIT);

    lba = bio_get_sector(bio);
    crypt_bio = bio_copy(bio, GFP_NOIO, mdt->bio_set);
    if (IS_ERR_OR_NULL(crypt_bio)) {
        DMINFO("dm_sworndisk_target_map deepcopy bio error");
        goto exit;
    }

    if (bio_op(bio) == REQ_OP_WRITE) {
        ctx = bio_crypt_context_create(lba, NULL, NULL, NULL, bio, NULL);
        if (IS_ERR_OR_NULL(ctx))
            goto exit;
        crypt_bio->bi_private = ctx;
        defer_bio(mdt, crypt_bio);
    }

    if (bio_op(bio) == REQ_OP_READ) {
        buf_instance = (struct default_segment_buffer*)(mdt->seg_buffer->implementer(mdt->seg_buffer));
        if (IS_ERR_OR_NULL(buf_instance))
            goto exit;
        r = buf_instance->mt->get(buf_instance->mt, lba, &mv);
        if (r) 
            goto exit;
        ctx = bio_crypt_context_create(lba, mv->key, mv->iv, mv->mac, bio, buf_instance->cipher);
        if (IS_ERR_OR_NULL(ctx))
            goto exit;
        crypt_bio->bi_private = ctx;
        bio_set_sector(crypt_bio, mv->pba);
        submit_bio(crypt_bio);
    }

    return DM_MAPIO_SUBMITTED;

exit:
    return DM_MAPIO_REMAPPED;
}

/*
 * This is constructor function of target gets called when we create some device of type 'dm_sworndisk_target'.
 * i.e on execution of command 'dmsetup create'. It gets called per device.
 */
static int dm_sworndisk_target_ctr(struct dm_target *target,
			    unsigned int argc, char **argv)
{
    bool may_format;
    struct dm_sworndisk_target *mdt;
    unsigned long long start;
    char dummy;
    int ret;
    struct dm_sworndisk_metadata *cmd;

    if (argc != 3) {
        DMERR("Invalid no. of arguments.");
        target->error = "Invalid argument count";
        ret =  -EINVAL;
        goto bad;
    }

    mdt = kmalloc(sizeof(struct dm_sworndisk_target), GFP_KERNEL);
    if (!mdt) {
        DMERR("Error in kmalloc");
        target->error = "Cannot allocate linear context";
        ret = -ENOMEM;
        goto bad;
    }

    if (sscanf(argv[2], "%llu%c", &start, &dummy)!=1) {
        target->error = "Invalid device sector";
        ret = -EINVAL;
        goto bad;
    }

    mdt->start=(sector_t)start;

    if (dm_get_device(target, argv[0], dm_table_get_mode(target->table), &mdt->data_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto bad;
    }
    if (dm_get_device(target, argv[1], dm_table_get_mode(target->table), &mdt->metadata_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto bad;
    }

    may_format = false;
    cmd = dm_sworndisk_metadata_open(mdt->metadata_dev->bdev, DM_SWORNDISK_METADATA_BLOCK_SIZE, may_format, 1, NR_SEGMENT, SEC_PER_SEG);
    if (IS_ERR_OR_NULL(cmd)) {
        DMERR("open metadata device error");
        goto bad;
    }
    mdt->cmd = cmd;
    mdt->wq = alloc_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM, 0);
	if (!mdt->wq) {
		target->error = "could not create workqueue for metadata object";
		goto bad;
	}

	INIT_WORK(&mdt->deferred_bio_worker, process_deferred_bios);
    target->private = mdt;
    spin_lock_init(&mdt->lock);
	bio_list_init(&mdt->deferred_bios);
    mdt->seg_buffer = segbuf_init(kmalloc(sizeof(struct default_segment_allocator), GFP_KERNEL), cmd, NR_SEGMENT);
    if (!mdt->seg_buffer) {
        ret = -ENOMEM;
        goto bad;
    }
    mdt->bio_set = bioset_create(BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
    if (IS_ERR_OR_NULL(mdt->bio_set)) {
        ret = -ENOMEM;
        goto bad;
    }
    return 0;

bad:
    if (mdt->cmd)
        dm_sworndisk_metadata_close(mdt->cmd);
    if (mdt->bio_set)
        bioset_free(mdt->bio_set);
    if (mdt->seg_buffer)
        mdt->seg_buffer->destroy(mdt->seg_buffer);
    if (mdt->wq) 
        destroy_workqueue(mdt->wq);
    if (mdt)
        kfree(mdt);
    DMERR("Exit : %s with ERROR", __func__);
    return ret;
}

/*
 *  This is destruction function, gets called per device.
 *  It removes device and decrement device count.
 */
static void dm_sworndisk_target_dtr(struct dm_target *ti)
{
    struct dm_sworndisk_target *mdt = (struct dm_sworndisk_target *) ti->private;
    if (mdt->cmd)
        dm_sworndisk_metadata_close(mdt->cmd);
    dm_put_device(ti, mdt->data_dev);
    dm_put_device(ti, mdt->metadata_dev);
    if (mdt->bio_set)
        bioset_free(mdt->bio_set);
    if (mdt->seg_buffer)
        mdt->seg_buffer->destroy(mdt->seg_buffer);
    if (mdt->wq) 
        destroy_workqueue(mdt->wq);
    if (mdt)
        kfree(mdt);
}
/*  This structure is fops for dm_sworndisk target */
static struct target_type dm_sworndisk_target = {

    .name = "sworndisk",
    .version = {1,0,0},
    .module = THIS_MODULE,
    .ctr = dm_sworndisk_target_ctr,
    .dtr = dm_sworndisk_target_dtr,
    .map = dm_sworndisk_target_map,
};

/*---------Module Functions -----------------*/

static int init_dm_sworndisk_target(void)
{
    int result;
    result = dm_register_target(&dm_sworndisk_target);
    if (result < 0) {
        DMERR("Error in registering target");
    } else {
        DMINFO("Target registered");
    }
    return 0;
}


static void cleanup_dm_sworndisk_target(void)
{
    dm_unregister_target(&dm_sworndisk_target);
}

module_init(init_dm_sworndisk_target);
module_exit(cleanup_dm_sworndisk_target);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("lnhoo");
