#ifndef DM_SWORNDISK_H 
#define DM_SWORNDISK_H

#include <linux/dm-io.h>
#include <linux/semaphore.h>

#include "../../dm.h"
#include "lsm_tree.h"

#define DM_MSG_PREFIX "sworndisk"

extern struct dm_sworndisk* sworndisk;

#define MAX_READER 4
#define MIN_NR_FETCH (size_t)1
#define MAX_NR_FETCH (size_t)64

struct bio_prefetcher {
    void* _buffer;
    dm_block_t begin, end, last_blkaddr;
    struct mutex lock;
    size_t nr_fetch;
};

/* For underlying device */
struct dm_sworndisk {
    sector_t start;
    spinlock_t req_lock;
    struct dm_dev* data_dev;
    struct dm_dev* metadata_dev;
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
    // block io prefetcher
    struct bio_prefetcher prefetcher;
};

void sworndisk_read_blocks(dm_block_t blkaddr, size_t count, void* buffer, enum dm_io_mem_type mem_type);
void sworndisk_write_blocks(dm_block_t blkaddr, size_t count, void* buffer, enum dm_io_mem_type mem_type);
bool sworndisk_should_threaded_logging(void);

#endif