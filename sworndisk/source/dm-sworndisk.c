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

void defer_bio(struct dm_sworndisk_target *sworndisk, struct bio *bio) {
	unsigned long flags;

    spin_lock_irqsave(&sworndisk->lock, flags);
    bio_list_add(&sworndisk->deferred_bios, bio);
    spin_unlock_irqrestore(&sworndisk->lock, flags);
    queue_work(sworndisk->wq, &sworndisk->deferred_bio_worker);
}

void process_deferred_bios(struct work_struct *ws) {
    int r; 
	unsigned long flags;
	struct bio_list bios;
	struct bio* bio;
    
    struct record* record;
    struct dm_sworndisk_target *sworndisk;

    sworndisk = container_of(ws, struct dm_sworndisk_target, deferred_bio_worker);
	bio_list_init(&bios);
	spin_lock_irqsave(&sworndisk->lock, flags);
	bio_list_merge(&bios, &sworndisk->deferred_bios);
	bio_list_init(&sworndisk->deferred_bios);
	spin_unlock_irqrestore(&sworndisk->lock, flags);

	while ((bio = bio_list_pop(&bios))) {
        if (bio_op(bio) == REQ_OP_READ) {
            r = sworndisk->memtable->get(sworndisk->memtable, bio_get_block_address(bio), (void**)&record);
            if (r)
                goto bad;
            bio_set_sector(bio, record->pba * SECTORS_PER_BLOCK + bio_block_sector_offset(bio));
            r = sworndisk->seg_buffer->query_bio(sworndisk->seg_buffer, bio);
            if (!r) {
                bio_endio(bio);
                goto next;
            }
            submit_bio(bio);
        }

        if (bio_op(bio) == REQ_OP_WRITE) {
            sworndisk->seg_buffer->push_bio(sworndisk->seg_buffer, bio);
            bio_endio(bio);
        }

        if (bio_op(bio) == REQ_OP_DISCARD) {
            r = sworndisk->memtable->get(sworndisk->memtable, bio_get_block_address(bio), (void**)&record);
            if (r)
                goto bad;
            r = sworndisk->metadata->data_segment_table->return_block(sworndisk->metadata->data_segment_table, record->pba);
            if (r)
                goto bad;
            bio_endio(bio);
        }
next:
        continue;
bad:    
        bio_endio(bio);
	}
}


static int dm_sworndisk_target_map(struct dm_target *target, struct bio *bio)
{
    struct dm_sworndisk_target* sworndisk;

    sworndisk = target->private;    
    bio_set_dev(bio, sworndisk->data_dev->bdev);
    if (bio_sectors(bio) > SECTORS_PER_BLOCK)
        dm_accept_partial_bio(bio, SECTORS_PER_BLOCK);

    switch (bio_op(bio)) {
        case REQ_OP_READ:
        case REQ_OP_WRITE:
        case REQ_OP_DISCARD:
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

    sworndisk->metadata = metadata_create(sworndisk->metadata_dev->bdev);
    if (!sworndisk->metadata) {
        target->error = "could not create sworndisk metadata";
		goto bad;
    }

    sworndisk->wq = alloc_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM, 0);
	if (!sworndisk->wq) {
		target->error = "could not create workqueue for sworndisk";
		goto bad;
	}

    sworndisk->memtable = rbtree_memtable_create();
    if (!sworndisk->memtable) {
        target->error = "could not create sworndisk memtable";
        ret = -EAGAIN;
		goto bad;
    }
    sworndisk->cipher = aes_gcm_cipher_init(kmalloc(sizeof(struct aes_gcm_cipher), GFP_KERNEL));
    if (!sworndisk->cipher) {
        target->error = "could not create sworndisk cipher";
		goto bad;
    }
    sworndisk->seg_allocator = sa_create(sworndisk);
    if (!sworndisk->seg_allocator) {
        target->error = "could not create sworndisk segment allocator";
        ret = -EAGAIN;
		goto bad;
    }

    spin_lock_init(&sworndisk->lock);
	bio_list_init(&sworndisk->deferred_bios);
    sworndisk->seg_buffer = segbuf_create(sworndisk);
    if (!sworndisk->seg_buffer) {
        target->error = "could not create sworndisk segment allocator";
        ret = -EAGAIN;
        goto bad;
    } 

    INIT_WORK(&sworndisk->deferred_bio_worker, process_deferred_bios);
    target->private = sworndisk;
    return 0;

bad:
    if (sworndisk->metadata)
        metadata_destroy(sworndisk->metadata);
    if (sworndisk->seg_buffer)
        sworndisk->seg_buffer->destroy(sworndisk->seg_buffer);
    if (sworndisk->wq) 
        destroy_workqueue(sworndisk->wq);
    if (sworndisk->memtable) 
        sworndisk->memtable->destroy(sworndisk->memtable);
    if (sworndisk->seg_allocator)
        sworndisk->seg_allocator->destroy(sworndisk->seg_allocator);
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
    if (sworndisk->metadata)
        metadata_destroy(sworndisk->metadata);
    if (sworndisk->seg_buffer)
        sworndisk->seg_buffer->destroy(sworndisk->seg_buffer);
    if (sworndisk->wq) 
        destroy_workqueue(sworndisk->wq);
    if (sworndisk->memtable) 
        sworndisk->memtable->destroy(sworndisk->memtable);
    if (sworndisk->seg_allocator)
        sworndisk->seg_allocator->destroy(sworndisk->seg_allocator);

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
