#ifndef DM_SWORNDISK_H 
#define DM_SWORNDISK_H

#include "../../dm.h"
#include "lsm_tree.h"

#define DM_MSG_PREFIX "sworndisk"

/* For underlying device */
struct dm_sworndisk_target {
    sector_t start;
    spinlock_t lock;
    struct dm_dev* data_dev;
    struct dm_dev* metadata_dev;
    struct workqueue_struct* wq;
    struct work_struct deferred_bio_worker;
    struct bio_list deferred_bios;
	struct metadata* metadata;
    struct segment_buffer* seg_buffer;
    struct segment_allocator* seg_allocator;
    struct memtable* memtable;
    struct aead_cipher *cipher;
};

#endif