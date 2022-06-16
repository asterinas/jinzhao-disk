#ifndef DM_SWORNDISK_H 
#define DM_SWORNDISK_H

#include <linux/dm-io.h>
#include <linux/semaphore.h>

#include "../../dm.h"
#include "lsm_tree.h"

#define DM_MSG_PREFIX "sworndisk"

extern struct dm_sworndisk* sworndisk;
extern struct bio_prefetcher prefetcher;
int bio_prefetcher_get(struct bio_prefetcher* this, dm_block_t blkaddr, void* buffer, enum dm_io_mem_type mem_type);
void sworndisk_read_blocks(dm_block_t blkaddr, size_t count, void* buffer, enum dm_io_mem_type mem_type);
bool bio_prefetcher_incache(struct bio_prefetcher* this, dm_block_t blkaddr);
void bio_prefetcher_clear(struct bio_prefetcher* this);
void sworndisk_write_blocks(dm_block_t blkaddr, size_t count, void* buffer, enum dm_io_mem_type mem_type);
bool sworndisk_should_threaded_logging(void);

#define MAX_READER 4

/* For underlying device */
struct dm_sworndisk {
    sector_t start;
    spinlock_t req_lock;
    struct dm_dev* data_dev;
    struct dm_dev* metadata_dev;
    struct workqueue_struct* wq;
    // workers
    struct work_struct deferred_bio_worker;
    // bio lists
    struct bio_list deferred_bios;
    // sworndisk components
	struct metadata* meta;
    struct segment_buffer* seg_buffer;
    struct segment_allocator* seg_allocator;
    struct lsm_tree* lsm_tree;
    // aead cipher
    struct aead_cipher *cipher;
    // io client
    struct dm_io_client* io_client;
    // read/write lock
    struct rw_semaphore rw_lock;
    // max reader limit
    struct semaphore max_reader;
};

#endif