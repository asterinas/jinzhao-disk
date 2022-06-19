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
#include <linux/scatterlist.h> 
#include <linux/fs.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/bio_operate.h"
#include "../include/segment_buffer.h"
#include "../include/cache.h"
#include "../include/segment_allocator.h"
#include "../include/async.h"

size_t NR_SEGMENT;
struct dm_sworndisk* sworndisk = NULL;

void bio_list_add_safe(struct dm_sworndisk* sworndisk, struct bio_list* list, struct bio* bio) {
    unsigned long flags;

    spin_lock_irqsave(&sworndisk->req_lock, flags);
    bio_list_add(list, bio);
    spin_unlock_irqrestore(&sworndisk->req_lock, flags);
}

void bio_list_take_safe(struct dm_sworndisk* sworndisk, struct bio_list* dst, struct bio_list* src) {
    unsigned long flags;

    bio_list_init(dst);
	spin_lock_irqsave(&sworndisk->req_lock, flags);
	bio_list_merge(dst, src);
	bio_list_init(src);
	spin_unlock_irqrestore(&sworndisk->req_lock, flags);
}

void defer_bio(struct dm_sworndisk* sworndisk, struct bio* bio) {
    bio_list_add_safe(sworndisk, &sworndisk->deferred_bios, bio);
    schedule_work(&sworndisk->deferred_bio_worker);
}

void sworndisk_block_io(dm_block_t blkaddr, size_t count, void* buffer, enum dm_io_mem_type mem_type, int bi_op) {
    unsigned long sync_error_bits;
    struct dm_io_request req = {
        .bi_op = req.bi_op_flags = bi_op,
        .mem.type = mem_type,
        .mem.offset = 0,
        .mem.ptr.addr = buffer,
        .notify.fn = NULL,
        .client = sworndisk->io_client
    };
    struct dm_io_region region = {
        .bdev = sworndisk->data_dev->bdev,
        .sector = blkaddr * SECTORS_PER_BLOCK,
        .count = SECTORS_PER_BLOCK * count
    };

    dm_io(&req, 1, &region, &sync_error_bits);
    if (sync_error_bits) 
        DMERR("segment buffer io error\n");
}


void sworndisk_read_blocks(dm_block_t blkaddr, size_t count, void* buffer, enum dm_io_mem_type mem_type) {
    sworndisk_block_io(blkaddr, count, buffer, mem_type, REQ_OP_READ);
    // read data block from segment buffer
    segbuf_query_encrypted_blocks(sworndisk->seg_buffer, blkaddr, count, buffer);
}

void sworndisk_write_blocks(dm_block_t blkaddr, size_t count, void* buffer, enum dm_io_mem_type mem_type) {
    sworndisk_block_io(blkaddr, count, buffer, mem_type, REQ_OP_WRITE);
}

#define THREAD_LOGGING_AHEAD 1
bool sworndisk_should_threaded_logging(void) {
    struct default_segment_allocator* allocator = 
        container_of(sworndisk->seg_allocator, struct default_segment_allocator, segment_allocator);

    if (allocator->nr_valid_segment < GC_THREADHOLD - THREAD_LOGGING_AHEAD)
        return false;
    return should_threaded_logging(sworndisk->meta->dst);
}


void bio_prefetcher_init(struct bio_prefetcher* this) {
    this->_buffer = vmalloc(MAX_NR_FETCH * DATA_BLOCK_SIZE);
    this->begin = 0;
    this->end = 0;
    this->last_blkaddr = 0;
    this->nr_fetch = MIN_NR_FETCH + 1;
    
    mutex_init(&this->lock);
}

bool bio_prefetcher_empty(struct bio_prefetcher* this) {
    return (this->begin >= this->end);
}

bool __bio_prefetcher_incache(struct bio_prefetcher* this, dm_block_t blkaddr) {
    return blkaddr >= this->begin && blkaddr < this->end;
}

bool bio_prefetcher_incache(struct bio_prefetcher* this, dm_block_t blkaddr) {
    bool result;

    mutex_lock(&this->lock);
    result = __bio_prefetcher_incache(this, blkaddr);
    mutex_unlock(&this->lock);
    return result;
}

void bio_prefetcher_clear(struct bio_prefetcher* this) {
    mutex_lock(&this->lock);
    this->begin = this->end = 0;
    mutex_unlock(&this->lock);
}

void __bio_prefetcher_destroy(struct bio_prefetcher* this) {
    vfree(this->_buffer);
}

int bio_prefetcher_get(struct bio_prefetcher* this, dm_block_t blkaddr, void* buffer, enum dm_io_mem_type mem_type) {
    int err = 0;

    mutex_lock(&this->lock);
    if (!__bio_prefetcher_incache(this, blkaddr)) {
        size_t remain_block = NR_SEGMENT * BLOCKS_PER_SEGMENT - blkaddr;
        size_t fetched = min(this->nr_fetch, remain_block);

        sworndisk_read_blocks(blkaddr, fetched, this->_buffer, DM_IO_VMA);
        this->end = blkaddr + fetched;
        if (this->last_blkaddr - this->begin < (this->nr_fetch / 4 * 3))
            this->nr_fetch = max(this->nr_fetch >> 1, MIN_NR_FETCH + 1);
        this->begin = blkaddr;
    } else {
        if ((blkaddr - this->begin) >= (this->nr_fetch >> 1))
            this->nr_fetch = min(this->nr_fetch << 1, MAX_NR_FETCH);
        this->last_blkaddr = blkaddr;
    }
    
    memcpy(buffer, this->_buffer + (blkaddr - this->begin) * DATA_BLOCK_SIZE, DATA_BLOCK_SIZE);
    mutex_unlock(&this->lock);
    return err;
}

void sworndisk_do_read(struct bio* bio) {
    int err = 0;
    struct record record;
    void* buffer = kmalloc(DATA_BLOCK_SIZE, GFP_KERNEL);

    down_read(&sworndisk->rw_lock);
    err = sworndisk->lsm_tree->search(sworndisk->lsm_tree, bio_get_block_address(bio), &record);
    if (err) {
        bio_endio(bio);
        up_read(&sworndisk->rw_lock);
        goto exit;
    }
    
    bio_set_sector(bio, record.pba * SECTORS_PER_BLOCK + bio_block_sector_offset(bio));
    err = sworndisk->seg_buffer->query_bio(sworndisk->seg_buffer, bio);
    if (!err) {
        bio_endio(bio);
        up_read(&sworndisk->rw_lock);
        goto exit;
    }

    bio_prefetcher_get(&sworndisk->prefetcher, record.pba, buffer, DM_IO_KMEM);
    err = sworndisk->cipher->decrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE, record.key, record.iv, record.mac, record.pba, buffer);
    if (!err)
        bio_set_data(bio, buffer + bio_block_sector_offset(bio) * SECTOR_SIZE, bio_get_data_len(bio));
    bio_endio(bio);
    up_read(&sworndisk->rw_lock);

exit:
    if (buffer)
        kfree(buffer);
}

void async_read(void* context) {
    sworndisk_do_read(context);
    up(&sworndisk->max_reader);
}

void sworndisk_do_write(struct bio* bio) {
    down_write(&sworndisk->rw_lock);
    sworndisk->seg_buffer->push_bio(sworndisk->seg_buffer, bio);
    bio_endio(bio);
    bio_prefetcher_clear(&sworndisk->prefetcher);
    up_write(&sworndisk->rw_lock);
}

void async_write(void* context) {
    sworndisk_do_write(context);
}

void process_deferred_bios(struct work_struct *ws) {
    struct bio* bio;
	struct bio_list bios;

    bio_list_take_safe(sworndisk, &bios, &sworndisk->deferred_bios);
	while ((bio = bio_list_pop(&bios))) {
        bool timeout = false;
        switch (bio_op(bio)) {
            case REQ_OP_READ:
                timeout = down_timeout(&sworndisk->max_reader, msecs_to_jiffies(300));
                go(async_read, bio);
                break;
            case REQ_OP_WRITE:
                sworndisk_do_write(bio);
                break;
        }
	}
}


static int dm_sworndisk_target_map(struct dm_target *target, struct bio *bio)
{
    sector_t block_aligned;
    struct dm_sworndisk* sworndisk;

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
            goto remapped;
    }

    return DM_MAPIO_SUBMITTED;

remapped:
    return DM_MAPIO_REMAPPED;
}

sector_t dm_devsize(struct dm_dev *dev) {
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

/*
 * This is constructor function of target gets called when we create some device of type 'dm_sworndisk'.
 * i.e on execution of command 'dmsetup create'. It gets called per device.
 */
static int dm_sworndisk_target_ctr(struct dm_target *target,
			    unsigned int argc, char **argv)
{
    unsigned long long start;
    char dummy;
    int ret;

    if (argc != 3) {
        DMERR("Invalid no. of arguments.");
        target->error = "Invalid argument count";
        ret =  -EINVAL;
        goto bad;
    }

    sworndisk = kzalloc(sizeof(struct dm_sworndisk), GFP_KERNEL);
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

    bio_prefetcher_init(&sworndisk->prefetcher);
    sema_init(&sworndisk->max_reader, MAX_READER);
    sworndisk->io_client = dm_io_client_create();
    if (!sworndisk->io_client) {
        target->error = "could not create dm-io client for sworndisk";
        ret = -EAGAIN;
		goto bad;
    }

    NR_SEGMENT = div_u64(dm_devsize(sworndisk->data_dev), SECTOES_PER_SEGMENT);
    sworndisk->meta = metadata_create(sworndisk->metadata_dev->bdev);
    if (!sworndisk->meta) {
        target->error = "could not create sworndisk metadata";
        ret = -EAGAIN;
		goto bad;
    }

    sworndisk->cipher = aes_gcm_cipher_create();
    if (!sworndisk->cipher) {
        target->error = "could not create sworndisk cipher";
        ret = -EAGAIN;
		goto bad;
    }

    sworndisk->lsm_tree = lsm_tree_create(argv[1], &sworndisk->meta->bit_catalogue->lsm_catalogue, sworndisk->cipher);
    if (!sworndisk->lsm_tree) {
        target->error = "could not create sworndisk lsm tree";
        ret = -EAGAIN;
		goto bad;
    }

    sworndisk->seg_allocator = sa_create();
    if (!sworndisk->seg_allocator) {
        target->error = "could not create sworndisk segment allocator";
        ret = -EAGAIN;
		goto bad;
    }

    init_rwsem(&sworndisk->rw_lock);
    spin_lock_init(&sworndisk->req_lock);
	bio_list_init(&sworndisk->deferred_bios);
    sworndisk->seg_buffer = segbuf_create();
    if (!sworndisk->seg_buffer) {
        target->error = "could not create sworndisk segment buffer";
        ret = -EAGAIN;
        goto bad;
    } 

    INIT_WORK(&sworndisk->deferred_bio_worker, process_deferred_bios);
    target->private = sworndisk;
    return 0;

bad:
    __bio_prefetcher_destroy(&sworndisk->prefetcher);
    if (sworndisk->seg_buffer)
        sworndisk->seg_buffer->destroy(sworndisk->seg_buffer);
    if (sworndisk->seg_allocator)
        sworndisk->seg_allocator->destroy(sworndisk->seg_allocator);
    if (sworndisk->lsm_tree) 
        sworndisk->lsm_tree->destroy(sworndisk->lsm_tree);
    if (sworndisk->meta)
        metadata_destroy(sworndisk->meta);
    if (sworndisk->cipher)
        sworndisk->cipher->destroy(sworndisk->cipher);
    if (sworndisk->io_client)
        dm_io_client_destroy(sworndisk->io_client);

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
    struct dm_sworndisk *sworndisk = (struct dm_sworndisk *) ti->private;
    __bio_prefetcher_destroy(&sworndisk->prefetcher);
    if (sworndisk->seg_buffer)
        sworndisk->seg_buffer->destroy(sworndisk->seg_buffer);
    if (sworndisk->seg_allocator)
        sworndisk->seg_allocator->destroy(sworndisk->seg_allocator);
    if (sworndisk->lsm_tree) 
        sworndisk->lsm_tree->destroy(sworndisk->lsm_tree);
    if (sworndisk->meta)
        metadata_destroy(sworndisk->meta);
    if (sworndisk->cipher)
        sworndisk->cipher->destroy(sworndisk->cipher);
    if (sworndisk->io_client)
        dm_io_client_destroy(sworndisk->io_client);

    dm_put_device(ti, sworndisk->data_dev);
    dm_put_device(ti, sworndisk->metadata_dev);
    if (sworndisk)
        kfree(sworndisk);
}
/*  This structure is fops for dm_sworndisk target */
static struct target_type dm_sworndisk = {

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
    result = dm_register_target(&dm_sworndisk);
    if (result < 0) {
        DMERR("Error in registering target");
    } else {
        DMINFO("Target registered");
    }
    return 0;
}


static void cleanup_dm_sworndisk_target(void)
{
    dm_unregister_target(&dm_sworndisk);
}

module_init(init_dm_sworndisk_target);
module_exit(cleanup_dm_sworndisk_target);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("lnhoo");
