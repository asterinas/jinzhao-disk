#ifndef DM_SWORNDISK_METADATA_H
#define DM_SWORNDISK_METADATA_H

#include <linux/min_heap.h>

#include "dm_sworndisk.h"
#include "disk_structs.h"
#include "segment_allocator.h"
#include "../../persistent-data/dm-block-manager.h"

#define SWORNDISK_MAX_CONCURRENT_LOCKS 6
#define SWORNDISK_METADATA_BLOCK_SIZE 4096

#define STRUCTURE_BLOCKS(x) (sizeof(x) ? (sizeof(x) - 1) / SWORNDISK_METADATA_BLOCK_SIZE + 1: 0) 

// superblock definition
#define SUPERBLOCK_ON_DISK_SIZE (sizeof(struct superblock) - 5 * sizeof(void*) - sizeof(uint32_t))
struct superblock {
	// validation 
	uint32_t csum;
	uint64_t magic;
	
	// data region
	uint32_t blocks_per_seg; // sector count within a segment
	uint64_t nr_segment; // segment count

	// index region
	uint32_t common_ratio; // common ratio of adjacent disk levels
	uint32_t nr_disk_level; // lsm tree disk level count
	uint64_t max_disk_level_size; // sector unit
	uint64_t index_region_start;

	// journal region
	uint32_t journal_size; // sector aligned
	uint64_t nr_journal;
	uint64_t cur_journal;
	uint64_t journal_region_start;

	// checkpoint region
	uint64_t seg_validity_table_start;
	uint64_t data_seg_table_start;
	uint64_t reverse_index_table_start;

	// persistent client
	struct dm_block_manager* bm;

	void (*print)(struct superblock* this);
	int (*read)(struct superblock* this);
	int (*write)(struct superblock* this);
	bool (*validate)(struct superblock* this);
} __packed;

struct superblock* superblock_create(struct dm_block_manager* bm);
void superblock_destroy(struct superblock* this);

// segment validator definition
struct seg_validator {
	size_t nr_segment;
	size_t cur_segment;
	struct disk_bitset* seg_validity_table;

	int (*take)(struct seg_validator* this, size_t seg);
	int (*next)(struct seg_validator* this, size_t* next_seg);
};

struct seg_validator* seg_validator_create(struct dm_block_manager* bm, dm_block_t start, size_t nr_segment);
void seg_validator_destroy(struct seg_validator* this);

// reverse index table definition
struct reverse_index_entry {
	bool valid: 1;
	dm_block_t lba;
} __packed;

struct reverse_index_table {
	size_t nr_block;
	struct disk_array* array;

	int (*format)(struct reverse_index_table* this);
	int (*set)(struct reverse_index_table* this, dm_block_t pba, dm_block_t lba);
	int (*get)(struct reverse_index_table* this, dm_block_t pba, dm_block_t *lba);
};

// data segment table definition
struct victim {
	size_t segment_id;
	size_t nr_valid_block;
	struct rb_node node;
} __packed;

struct victim* victim_create(size_t segment_id, size_t nr_valid_block);
void victim_destroy(struct victim* victim);


struct data_segment_entry {
	size_t nr_valid_block;
	DECLARE_BITMAP(block_validity_table, BLOCKS_PER_SEGMENT);
} __packed;

struct data_segment_table {
	dm_block_t start;
	size_t nr_segment;
	struct disk_array* array;
	struct rb_node** node_list;
	struct rb_root victims;

	int (*load)(struct data_segment_table* this);
	int (*take_segment)(struct data_segment_table* this, size_t segment_id);
	int (*return_block)(struct data_segment_table* this, dm_block_t block_id);
	bool (*victim_empty)(struct data_segment_table* this);
	struct victim* (*peek_victim)(struct data_segment_table* this);
	struct victim* (*pop_victim)(struct data_segment_table* this);
	struct victim* (*remove_victim)(struct data_segment_table* this, size_t segment_id);
};

struct data_segment_table* data_segment_table_create(struct dm_block_manager* bm, dm_block_t start, size_t nr_segment);
void data_segment_table_destroy(struct data_segment_table* this);

// metadata definition
struct metadata {
	// persistent client
	struct block_device* bdev;
	struct dm_block_manager* bm;
	// superblock
	struct superblock* superblock;
	// checkpoint region
	struct seg_validator* seg_validator;
	struct reverse_index_table* reverse_index_table;
};

struct metadata* metadata_create(struct block_device* bdev);
void metadata_destroy(struct metadata* this);

#endif