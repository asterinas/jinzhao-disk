#ifndef SWORNDISK_DISK_STRUCTS_H
#define SWORNDISK_DISK_STRUCTS_H

#include "../include/dm_sworndisk.h"
#include "../../persistent-data/dm-block-manager.h"

// disk array definition
struct disk_array {
	dm_block_t start;
	size_t nr_entry;
	size_t entry_size;
	size_t entries_per_block;
	struct dm_block_manager* bm;

	int (*format)(struct disk_array* this, bool value);
	int (*set)(struct disk_array* this, size_t index, void* entry);
	void* (*get)(struct disk_array* this, size_t index);
};

struct disk_array* disk_array_create(struct dm_block_manager* bm, dm_block_t start, size_t nr_entry, size_t entry_size);
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

struct disk_bitset* disk_bitset_create(struct dm_block_manager* bm, dm_block_t start, size_t nr_bit);
void disk_bitset_destroy(struct disk_bitset* this);

// disk queue definition
struct disk_queue {
	size_t len, capacity, elem_size, in, out;
	struct disk_array* array;

	int (*push)(struct disk_queue* this, void* elem);
	void* (*pop)(struct disk_queue* this);
	bool (*full)(struct disk_queue* this);
	bool (*empty)(struct disk_queue* this);
};

#endif