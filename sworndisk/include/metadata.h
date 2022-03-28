#ifndef DM_SWORNDISK_METADATA_H
#define DM_SWORNDISK_METADATA_H

#include "../include/dm_sworndisk.h"
#include "../../persistent-data/dm-block-manager.h"

#define SWORNDISK_MAX_CONCURRENT_LOCKS 3

// disk array definition
#define DISK_ARRAY_BLOCK_SIZE (16 * SECTOR_SIZE)

struct disk_array {
	sector_t start;
	size_t nr_entry;
	size_t entry_size;
	size_t entries_per_block;
	struct block_device* bdev;
	struct dm_block_manager* bm;

	int (*format)(struct disk_array* this, bool value);
	int (*set)(struct disk_array* this, size_t index, void* entry);
	void* (*get)(struct disk_array* this, size_t index);
};

struct disk_array* disk_array_create(struct block_device* bdev, sector_t start, size_t nr_entry, size_t entry_size);
void disk_array_destroy(struct disk_array* this);

// disk bitset definition
struct disk_bitset {
	size_t nr_bit;
	struct disk_array* array;

	int (*format)(struct disk_bitset* this, bool value);
	int (*set)(struct disk_bitset* this, size_t index);
	int (*clear)(struct disk_bitset* this, size_t index);
	int (*get)(struct disk_bitset* this, size_t index, bool* result);
};

struct disk_bitset* disk_bitset_create(struct block_device* bdev, sector_t start, size_t nr_bit);
void disk_bitset_destroy(struct disk_bitset* this);

// superblock definition
#define SUPERBLOCK_ON_DISK_SIZE (sizeof(struct superblock) - 5 * sizeof(void*) - sizeof(uint32_t))
struct superblock {
	// validation 
	uint32_t csum;
	uint64_t magic;
	
	// data region
	uint32_t sectors_per_seg; // sector count within a segment
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

int superblock_init(struct superblock* this, struct block_device* bdev);
struct superblock* superblock_create(struct block_device* bdev);
void superblock_destroy(struct superblock* this);

// segment validator definition
struct seg_validator {
	size_t nr_segment;
	size_t cur_segment;
	struct disk_bitset* seg_validity_table;

	int (*take)(struct seg_validator* this, size_t seg);
	int (*next)(struct seg_validator* this, size_t* next_seg);
};

struct seg_validator* seg_validator_create(struct block_device* bdev, sector_t start, size_t nr_segment);
void seg_validator_destroy(struct seg_validator* this);

// reverse index table definition
struct reverse_index_entry {
	bool valid: 1;
	sector_t lba;
} __packed;

struct reverse_index_table {
	size_t nr_block;
	struct disk_array* array;

	int (*format)(struct reverse_index_table* this);
	int (*set)(struct reverse_index_table* this, sector_t pba, sector_t lba);
	int (*get)(struct reverse_index_table* this, sector_t pba, sector_t *lba);
};

// metadata definition
struct metadata {
	struct block_device* bdev;
	// superblock
	struct superblock* superblock;
	// checkpoint region
	struct seg_validator* seg_validator;
	struct reverse_index_table* reverse_index_table;
};

struct metadata* metadata_create(struct block_device* bdev);
void metadata_destroy(struct metadata* this);

#endif