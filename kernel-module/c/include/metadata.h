/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef DM_JINDISK_METADATA_H
#define DM_JINDISK_METADATA_H

#include <linux/min_heap.h>
#include <linux/dm-bufio.h>

#include "disk_structs.h"
#include "dm_jindisk.h"
#include "journal.h"
#include "lsm_tree.h"
#include "segment_allocator.h"

struct meta_aux_data {
	struct disk_array *disk_array;
};
#define MAX_CONCURRENT_LOCKS 6
#define META_AUX_SIZE sizeof(struct meta_aux_data)
#define METADATA_BLOCK_SIZE 4096

#define STRUCTURE_BLOCKS(x)                                                    \
	(sizeof(x) ? (sizeof(x) - 1) / METADATA_BLOCK_SIZE + 1 : 0)

size_t __bytes_to_block(size_t bytes, size_t block_size);
size_t __disk_array_blocks(size_t nr_elem, size_t elem_size, size_t block_size);

// superblock definition
#define NR_SUPERBLOCK_METHOD 4
#define SUPERBLOCK_ENCRYPTED_SIZE                                              \
	(sizeof(struct superblock) - NR_SUPERBLOCK_METHOD * sizeof(void *) -   \
	 sizeof(void *) - AES_GCM_AUTH_SIZE - AES_GCM_KEY_SIZE -               \
	 AES_GCM_IV_SIZE)

struct superblock {
	// validation
	uint32_t csum;
	uint64_t magic;

	// data region
	uint32_t blocks_per_seg; // sector count within a segment
	uint64_t nr_segment; // segment count
	uint64_t data_start;

	// index region
	uint32_t common_ratio; // common ratio of adjacent disk levels
	uint32_t nr_disk_level; // lsm tree disk level count
	uint64_t max_disk_level_capacity; // sector unit
	uint64_t index_region_start;

	// journal region
	uint32_t journal_size; // sector aligned
	uint64_t nr_journal;
	uint64_t record_start;
	uint64_t record_end;
	uint64_t last_checkpoint_pack;
	uint64_t journal_region_start;

	// checkpoint region
	uint64_t seg_validity_table_start;
	uint64_t data_seg_table_start;
	uint64_t reverse_index_table_start;
	uint64_t block_index_table_catalogue_start;

	// root_mac to decrypt superblock
	char root_mac[AES_GCM_AUTH_SIZE];

	// following fields don't write to disk
	char root_key[AES_GCM_KEY_SIZE];
	char root_iv[AES_GCM_IV_SIZE];

	struct dm_bufio_client *bc;

	void (*print)(struct superblock *this);
	int (*read)(struct superblock *this);
	int (*write)(struct superblock *this);
	bool (*validate)(struct superblock *this);
} __packed;

struct superblock *superblock_create(struct dm_bufio_client *bc, char *key,
				     char *iv, bool format);
void superblock_destroy(struct superblock *this);

// segment validator definition
struct seg_validator {
	size_t nr_segment;
	size_t blk_count;
	size_t cur_segment;
	struct disk_bitset *seg_validity_table;
	struct rw_semaphore svt_lock;

	int (*format)(struct seg_validator *this);
	int (*take)(struct seg_validator *this, size_t seg);
	int (*next)(struct seg_validator *this, size_t *next_seg);
	int (*test_and_return)(struct seg_validator *this, size_t seg,
			       bool *old);
	int (*valid_segment_count)(struct seg_validator *this, size_t *count);
};

struct seg_validator *seg_validator_create(struct dm_bufio_client *bc,
					   char *key, dm_block_t start,
					   size_t nr_segment, int valid_field);
void seg_validator_destroy(struct seg_validator *this);

// reverse index table definition
struct reverse_index_entry {
	dm_block_t lba;
} __packed;

struct reverse_index_table {
	size_t nr_block;
	size_t blk_count;
	struct disk_array *array;
	struct rw_semaphore rit_lock;

	int (*format)(struct reverse_index_table *this);
	int (*set)(struct reverse_index_table *this, dm_block_t pba,
		   dm_block_t lba);
	int (*get)(struct reverse_index_table *this, dm_block_t pba,
		   dm_block_t *lba);
	int (*reset)(struct reverse_index_table *this, dm_block_t pba,
		     dm_block_t old_lba, dm_block_t *new_lba);
};

// data segment table definition
struct victim {
	size_t segno;
	size_t nr_valid_block;
	DECLARE_BITMAP(block_validity_table, BLOCKS_PER_SEGMENT);
	struct rb_node node;
} __packed;

struct victim *victim_create(size_t segno, size_t nr_valid_block,
			     unsigned long *block_validity_table);
void victim_destroy(struct victim *victim);

struct dst_entry {
	size_t nr_valid_block;
	DECLARE_BITMAP(block_validity_table, BLOCKS_PER_SEGMENT);
} __packed;

struct dst {
	dm_block_t start;
	size_t nr_segment;
	size_t logging_segno;
	size_t blk_count;
	int valid_field;
	struct disk_array *array;
	struct rb_node **node_list;
	struct rb_root victims;
	struct dm_bufio_client *bc;
	struct rw_semaphore dst_lock;

	int (*format)(struct dst *this);
	int (*load)(struct dst *this);
	int (*take_segment)(struct dst *this, size_t segno);
	int (*return_segment)(struct dst *this, size_t segno);
	int (*take_block)(struct dst *this, dm_block_t blkaddr);
	int (*return_block)(struct dst *this, dm_block_t block_id);
	int (*find_logging_block)(struct dst *this, dm_block_t *pba);
	bool (*victim_empty)(struct dst *this);
	struct victim *(*peek_victim)(struct dst *this);
	struct victim *(*pop_victim)(struct dst *this);
	struct victim *(*remove_victim)(struct dst *this, size_t segno);
	struct dst_entry *(*get)(struct dst *this, size_t segno);
};

struct dst *dst_create(struct dm_bufio_client *bc, char *key, dm_block_t start,
		       size_t nr_segment, int valid_field);
void dst_destroy(struct dst *this);

struct file_stat {
	loff_t root;
	char root_key[AES_GCM_KEY_SIZE];
	char root_iv[AES_GCM_IV_SIZE];
	size_t id, level, version;
	uint32_t first_key, last_key, nr_record;
	struct list_head node;
} __packed;

void file_stat_print(struct file_stat stat);

struct bit_catalogue {
	struct lsm_catalogue lsm_catalogue;

	size_t nr_bit, max_version;
	size_t blk_count;
	struct seg_validator *bit_validity_table;
	struct disk_array *file_stats;
	dm_block_t start, index_region_start;
	struct dm_bufio_client *bc;

	int (*format)(struct bit_catalogue *this);
};

// metadata definition
struct metadata {
	struct block_device *bdev;
	// dm_bufio client
	struct dm_bufio_client *bc;
	// superblock
	struct superblock *superblock;
	// journal region
	struct journal_region *journal;
	// checkpoint region
	struct seg_validator *seg_validator;
	struct reverse_index_table *rit;
	struct dst *dst;
	struct bit_catalogue *bit_catalogue;

	int (*format)(struct metadata *this);
	void (*destroy)(struct metadata *this);
};

uint64_t calc_avail_sectors(uint64_t real_sectors);
uint64_t calc_metadata_blocks(uint64_t nr_segment);
struct metadata *metadata_create(char *key, char *iv, unsigned long action_flag,
				 struct block_device *bdev);

struct journal_region *journal_region_create(struct superblock *superblock);
void journal_region_destroy(struct journal_region *this);

#endif
