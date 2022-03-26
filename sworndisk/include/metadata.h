#ifndef DM_SWORNDISK_METADATA_H
#define DM_SWORNDISK_METADATA_H

#include "../../persistent-data/dm-block-manager.h"

#define SWORNDISK_MAX_CONCURRENT_LOCKS 3

// disk array definition
struct disk_array {
	sector_t start;
	size_t nr_entry;
	size_t entry_size;
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

	int (*read)(struct superblock* this);
	int (*write)(struct superblock* this);
	int (*validate)(struct superblock* this);
} __packed;

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

// deprecated, will be removed soon
#include "../../persistent-data/dm-space-map-metadata.h"
#define DM_SWORNDISK_METADATA_BLOCK_SIZE DM_SM_METADATA_BLOCK_SIZE

/* FIXME: remove this restriction */
/*
 * The metadata device is currently limited in size.
 */
#define DM_SWORNDISK_METADATA_MAX_SECTORS DM_SM_METADATA_MAX_SECTORS

/*
 * A metadata device larger than 16GB triggers a warning.
 */
#define DM_SWORNDISK_METADATA_MAX_SECTORS_WARNING (16 * (1024 * 1024 * 1024 >> SECTOR_SHIFT))

/*----------------------------------------------------------------*/

/*
 * Ext[234]-style compat feature flags.
 *
 * A new feature which old metadata will still be compatible with should
 * define a DM_CACHE_FEATURE_COMPAT_* flag (rarely useful).
 *
 * A new feature that is not compatible with old code should define a
 * DM_CACHE_FEATURE_INCOMPAT_* flag and guard the relevant code with
 * that flag.
 *
 * A new feature that is not compatible with old code accessing the
 * metadata RDWR should define a DM_CACHE_FEATURE_RO_COMPAT_* flag and
 * guard the relevant code with that flag.
 *
 * As these various flags are defined they should be added to the
 * following masks.
 */

#define DM_SWORNDISK_FEATURE_COMPAT_SUPP	  0UL
#define DM_SWORNDISK_FEATURE_COMPAT_RO_SUPP	  0UL
#define DM_SWORNDISK_FEATURE_INCOMPAT_SUPP	  0UL

struct dm_sworndisk_metadata;

/*
 * Reopens or creates a new, empty metadata volume.  Returns an ERR_PTR on
 * failure.  If reopening then features must match.
 */
struct dm_sworndisk_metadata *dm_sworndisk_metadata_open(struct block_device *bdev,
						 sector_t data_block_size,
						 bool may_format_device,
						 unsigned metadata_version,
						 int nr_segment,
						 int blk_per_seg);

void dm_sworndisk_metadata_close(struct dm_sworndisk_metadata *cmd);

/*
 * The metadata needs to know how many cache blocks there are.  We don't
 * care about the origin, assuming the core target is giving us valid
 * origin blocks to map to.
 */

int dm_sworndisk_changed_this_transaction(struct dm_sworndisk_metadata *cmd);


/*
 * 'void' because it's no big deal if it fails.
 */

int dm_sworndisk_commit(struct dm_sworndisk_metadata *cmd, bool clean_shutdown);

int dm_sworndisk_get_free_metadata_block_count(struct dm_sworndisk_metadata *cmd,
					   dm_block_t *result);

int dm_sworndisk_get_metadata_dev_size(struct dm_sworndisk_metadata *cmd,
				   dm_block_t *result);

void dm_sworndisk_dump(struct dm_sworndisk_metadata *cmd);

/*
 * The policy is invited to save a 32bit hint value for every cblock (eg,
 * for a hit count).  These are stored against the policy name.  If
 * policies are changed, then hints will be lost.  If the machine crashes,
 * hints will be lost.
 *
 * The hints are indexed by the cblock, but many policies will not
 * neccessarily have a fast way of accessing efficiently via cblock.  So
 * rather than querying the policy for each cblock, we let it walk its data
 * structures and fill in the hints in whatever order it wishes.
 */

/*
 * Query method.  Are all the blocks in the cache clean?
 */
int dm_sworndisk_metadata_all_clean(struct dm_sworndisk_metadata *cmd, bool *result);

int dm_sworndisk_metadata_needs_check(struct dm_sworndisk_metadata *cmd, bool *result);
int dm_sworndisk_metadata_set_needs_check(struct dm_sworndisk_metadata *cmd);
void dm_sworndisk_metadata_set_read_only(struct dm_sworndisk_metadata *cmd);
void dm_sworndisk_metadata_set_read_write(struct dm_sworndisk_metadata *cmd);
int dm_sworndisk_metadata_abort(struct dm_sworndisk_metadata *cmd);

/*----------------------------------------------------------------*/

int dm_sworndisk_set_svt(struct dm_sworndisk_metadata *cmd, size_t seg, bool valid);
int dm_sworndisk_get_first_free_segment(struct dm_sworndisk_metadata *cmd, size_t *seg, size_t next_seg);
int dm_sworndisk_rit_insert(struct dm_sworndisk_metadata *cmd, sector_t pba, sector_t lba);
int dm_sworndisk_rit_get(struct dm_sworndisk_metadata *cmd, sector_t pba, sector_t *lba);
int dm_sworndisk_reset_svt(struct dm_sworndisk_metadata *cmd);

#endif






