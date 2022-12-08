/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef DM_JINDISK_H
#define DM_JINDISK_H

#include <linux/bio.h>
#include <linux/bitmap.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "lsm_tree.h"

extern struct dm_jindisk *jindisk;
extern struct disk_statistics disk_counter;
extern size_t NR_SEGMENT;

#define DM_MSG_PREFIX "jindisk"

#define INF_ADDR (~0ULL)
#define MAX_READER 4
#define MIN_NR_FETCH (size_t)1
#define MAX_NR_FETCH (size_t)64

#define SECTORS_PER_BLOCK 8
#define BLOCKS_PER_SEGMENT 1024
#define SECTORS_PER_SEGMENT (SECTORS_PER_BLOCK * BLOCKS_PER_SEGMENT)
#define DATA_BLOCK_SIZE (SECTORS_PER_BLOCK * SECTOR_SIZE)

#define bio_to_lba(bio) (bio->bi_iter.bi_sector / SECTORS_PER_BLOCK)

struct blk_info {
	dm_block_t lba;
	struct record *record;
	void *page_addr;
};

struct diskio_ctx {
	int bi_op;
	dm_block_t blk_start;
	int blk_count;
	void *io_buffer;
	enum dm_io_mem_type mem_type;
	struct completion *wait;
	atomic_t *cnt;
	struct blk_info **infos;
	struct work_struct work;
};

struct disk_statistics {
	uint64_t read_req_blocks;
	uint64_t read_io_blocks;
	uint64_t read_io_count;

	uint64_t write_req_blocks;
	uint64_t write_io_blocks;
	uint64_t write_io_count;

	uint64_t minor_compaction;
	uint64_t major_compaction;
	uint64_t bit_created;
	uint64_t bit_removed;
	uint64_t bit_node_cache_hit;
	uint64_t bit_node_cache_miss;
};

/* For underlying device */
struct dm_jindisk {
	sector_t start;
	spinlock_t req_lock;
	struct dm_dev *raw_dev;
	// workers
	struct work_struct deferred_bio_worker;
	// bio lists
	struct bio_list deferred_bios;
	// jindisk components
	struct metadata *meta;
	struct segment_buffer *seg_buffer;
	struct segment_allocator *seg_allocator;
	struct lsm_tree *lsm_tree;
	// aead cipher
	struct aead_cipher *cipher;
	// io client
	struct dm_io_client *io_client;
	// max reader limit
	struct semaphore max_reader;
};

void jindisk_read_blocks(dm_block_t pba, size_t count, void *buffer,
			 enum dm_io_mem_type mem_type, void *ctx);
void jindisk_write_blocks(dm_block_t pba, size_t count, void *buffer,
			  enum dm_io_mem_type mem_type);

#endif
