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
#include <linux/fs.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/bio_operate.h"
#include "../include/segment_buffer.h"
#include "../include/cache.h"

#include "../include/lsm_tree_test.h"

void defer_bio(struct dm_sworndisk_target *sworndisk, struct bio *bio) {
	unsigned long flags;

    spin_lock_irqsave(&sworndisk->lock, flags);
    bio_list_add(&sworndisk->deferred_bios, bio);
    spin_unlock_irqrestore(&sworndisk->lock, flags);
    queue_work(sworndisk->wq, &sworndisk->deferred_bio_worker);
}

struct sworndisk_read_work {
    struct bio* bio;
    struct record record;
    struct dm_sworndisk_target* sworndisk;
    struct work_struct work;
};

void sworndisk_read_work_fn(struct work_struct* ws);
struct sworndisk_read_work* sworndisk_read_work_create(struct dm_sworndisk_target* sworndisk, struct bio* bio, struct record record) {
    struct sworndisk_read_work* read_work = kmalloc(sizeof(struct sworndisk_read_work), GFP_KERNEL);

    if (!read_work)
        return NULL;

    *read_work = (struct sworndisk_read_work) {
        .sworndisk = sworndisk,
        .bio = bio,
        .record = record
    };
    INIT_WORK(&read_work->work, sworndisk_read_work_fn);
    return read_work;
}

void sworndisk_read_work_fn(struct work_struct* ws) {
    int err = 0;
    struct sworndisk_read_work* ctx = container_of(ws, struct sworndisk_read_work, work);
    struct dm_sworndisk_target* sworndisk = ctx->sworndisk;
    struct bio* bio = ctx->bio;
    struct record record = ctx->record;
    loff_t addr = record.pba * DATA_BLOCK_SIZE;
    void* buffer = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);

    kernel_read(sworndisk->data_region, buffer, DATA_BLOCK_SIZE, &addr);
    err = sworndisk->cipher->decrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE, record.key, record.iv, record.mac, record.pba, buffer);
    if (!err)
        bio_set_data(bio, buffer + bio_block_sector_offset(bio) * SECTOR_SIZE, bio_get_data_len(bio));

    if (buffer)
        kfree(buffer);
    if (ctx)
        kfree(ctx);
    bio_endio(bio);
    up_read(&sworndisk->rwsem);
}

void process_deferred_bios(struct work_struct *ws) {
    int r; 
	unsigned long flags;
	struct bio_list bios;
	struct bio* bio;
    struct dm_sworndisk_target *sworndisk;

    sworndisk = container_of(ws, struct dm_sworndisk_target, deferred_bio_worker);
	bio_list_init(&bios);
	spin_lock_irqsave(&sworndisk->lock, flags);
	bio_list_merge(&bios, &sworndisk->deferred_bios);
	bio_list_init(&sworndisk->deferred_bios);
	spin_unlock_irqrestore(&sworndisk->lock, flags);

	while ((bio = bio_list_pop(&bios))) {
        if (bio_op(bio) == REQ_OP_READ) {
            struct record record = {0};
            struct sworndisk_read_work* read_work;

            down_read(&sworndisk->rwsem);
            r = sworndisk->lsm_tree->search(sworndisk->lsm_tree, bio_get_block_address(bio), &record);
            if (r) {
                up_read(&sworndisk->rwsem);
                goto bad;
            }
                
            bio_set_sector(bio, record.pba * SECTORS_PER_BLOCK + bio_block_sector_offset(bio));
            r = sworndisk->seg_buffer->query_bio(sworndisk->seg_buffer, bio);
            if (!r) {
                bio_endio(bio);
                up_read(&sworndisk->rwsem);
                goto next;
            }

            read_work = sworndisk_read_work_create(sworndisk, bio, record);
            if (read_work)
                queue_work(sworndisk->wq, &read_work->work);
            else {
                up_read(&sworndisk->rwsem);
            }
        }

        if (bio_op(bio) == REQ_OP_WRITE) {
            down_write(&sworndisk->rwsem);
            sworndisk->seg_buffer->push_bio(sworndisk->seg_buffer, bio);
            bio_endio(bio);
            up_write(&sworndisk->rwsem);
        }

next:
        continue;
bad:    
        bio_endio(bio);
	}
}


static int dm_sworndisk_target_map(struct dm_target *target, struct bio *bio)
{
    sector_t block_aligned;
    struct dm_sworndisk_target* sworndisk;

    sworndisk = target->private;    
    bio_set_dev(bio, sworndisk->data_dev->bdev);

    block_aligned = SECTORS_PER_BLOCK - bio_block_sector_offset(bio);
    if (bio_sectors(bio) > block_aligned)
        dm_accept_partial_bio(bio, block_aligned);

    switch (bio_op(bio)) {
        case REQ_OP_READ:
        case REQ_OP_WRITE:
            defer_bio(sworndisk, bio);
            break;
        default:
            goto exit;
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
    struct dm_sworndisk_target *sworndisk = NULL;
    unsigned long long start;
    char dummy;
    int ret;

    if (argc != 3) {
        DMERR("Invalid no. of arguments.");
        target->error = "Invalid argument count";
        ret =  -EINVAL;
        goto bad;
    }

    sworndisk = kzalloc(sizeof(struct dm_sworndisk_target), GFP_KERNEL);
    if (!sworndisk) {
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

    sworndisk->start=(sector_t)start;

    if (dm_get_device(target, argv[0], dm_table_get_mode(target->table), &sworndisk->data_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto bad;
    }
    if (dm_get_device(target, argv[1], dm_table_get_mode(target->table), &sworndisk->metadata_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto bad;
    }

    sworndisk->data_region = filp_open(argv[0], O_RDWR | O_LARGEFILE, 0);
    if (!sworndisk->data_region) {
        target->error = "could not open sworndisk data region";
        ret = -EAGAIN;
		goto bad;
    }

    sworndisk->metadata = metadata_create(sworndisk->metadata_dev->bdev);
    if (!sworndisk->metadata) {
        target->error = "could not create sworndisk metadata";
        ret = -EAGAIN;
		goto bad;
    }

    sworndisk->wq = alloc_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM, 0);
	if (!sworndisk->wq) {
		target->error = "could not create workqueue for sworndisk";
        ret = -EAGAIN;
		goto bad;
	}

    sworndisk->cipher = aes_gcm_cipher_create();
    if (!sworndisk->cipher) {
        target->error = "could not create sworndisk cipher";
        ret = -EAGAIN;
		goto bad;
    }

    sworndisk->lsm_tree = lsm_tree_create(argv[1], &sworndisk->metadata->bit_catalogue->lsm_catalogue, sworndisk->cipher);
    if (!sworndisk->lsm_tree) {
        target->error = "could not create sworndisk lsm tree";
        ret = -EAGAIN;
		goto bad;
    }

    sworndisk->seg_allocator = sa_create(sworndisk);
    if (!sworndisk->seg_allocator) {
        target->error = "could not create sworndisk segment allocator";
        ret = -EAGAIN;
		goto bad;
    }

    init_rwsem(&sworndisk->rwsem);
    spin_lock_init(&sworndisk->lock);
	bio_list_init(&sworndisk->deferred_bios);
    sworndisk->seg_buffer = segbuf_create(sworndisk);
    if (!sworndisk->seg_buffer) {
        target->error = "could not create sworndisk segment buffer";
        ret = -EAGAIN;
        goto bad;
    } 
    
    INIT_WORK(&sworndisk->deferred_bio_worker, process_deferred_bios);
    target->private = sworndisk;
    return 0;

bad:
    if (sworndisk->seg_buffer)
        sworndisk->seg_buffer->destroy(sworndisk->seg_buffer);
    if (sworndisk->wq) 
        destroy_workqueue(sworndisk->wq);
    if (sworndisk->seg_allocator)
        sworndisk->seg_allocator->destroy(sworndisk->seg_allocator);
    if (sworndisk->data_region)
        filp_close(sworndisk->data_region, NULL);
    if (sworndisk->lsm_tree) 
        sworndisk->lsm_tree->destroy(sworndisk->lsm_tree);
    if (sworndisk->metadata)
        metadata_destroy(sworndisk->metadata);
    if (sworndisk->cipher)
        sworndisk->cipher->destroy(sworndisk->cipher);

    dm_put_device(target, sworndisk->data_dev);
    dm_put_device(target, sworndisk->metadata_dev);
    if (sworndisk)
        kfree(sworndisk);
    DMERR("Exit : %s with ERROR", __func__);
    return ret;
}

/*
 *  This is destruction function, gets called per device.
 *  It removes device and decrement device count.
 */
static void dm_sworndisk_target_dtr(struct dm_target *ti)
{
    struct dm_sworndisk_target *sworndisk = (struct dm_sworndisk_target *) ti->private;
    if (sworndisk->seg_buffer)
        sworndisk->seg_buffer->destroy(sworndisk->seg_buffer);
    if (sworndisk->wq) 
        destroy_workqueue(sworndisk->wq);
    if (sworndisk->seg_allocator)
        sworndisk->seg_allocator->destroy(sworndisk->seg_allocator);
    if (sworndisk->data_region)
        filp_close(sworndisk->data_region, NULL);
    if (sworndisk->lsm_tree) 
        sworndisk->lsm_tree->destroy(sworndisk->lsm_tree);
    if (sworndisk->metadata)
        metadata_destroy(sworndisk->metadata);
    if (sworndisk->cipher)
        sworndisk->cipher->destroy(sworndisk->cipher);

    dm_put_device(ti, sworndisk->data_dev);
    dm_put_device(ti, sworndisk->metadata_dev);
    if (sworndisk)
        kfree(sworndisk);
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
