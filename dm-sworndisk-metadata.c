/*
 * Copyright (C) 2012 Red Hat, Inc.
 *
 * This file is released under the GPL.
 */

#include "dm-sworndisk-metadata.h"

#include "persistent-data/dm-array.h"
#include "persistent-data/dm-bitset.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-space-map-disk.h"
#include "persistent-data/dm-transaction-manager.h"

#include <linux/device-mapper.h>
#include <linux/refcount.h>

/*----------------------------------------------------------------*/

#define DM_MSG_PREFIX   "sworndisk metadata"

#define SWORNDISK_SUPERBLOCK_MAGIC 06142003
#define SWORNDISK_SUPERBLOCK_LOCATION 0

/*
 * defines a range of metadata versions that this module can handle.
 */
#define MIN_SWORNDISK_VERSION 1
#define MAX_SWORNDISK_VERSION 2

/*
 *  3 for btree insert +
 *  2 for btree lookup used within space map
 */
#define SWORNDISK_MAX_CONCURRENT_LOCKS 5
#define SPACE_MAP_ROOT_SIZE 128

enum superblock_flag_bits {
	/* for spotting crashes that would invalidate the dirty bitset */
	CLEAN_SHUTDOWN,
	/* metadata must be checked using the tools */
	NEEDS_CHECK,
};


struct sworndisk_disk_superblock {
	__le32 csum;
	__le32 flags;
	__le64 blocknr;

	__u8 uuid[16];
	__le64 magic;
	__le32 version;

    __le64 nr_segment;
    __le64 blk_per_seg;

	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];
	__le64 svt_root; // segment validation table root
	__le64 rit_root; // reverse index table root

	__le32 data_block_size;
	__le32 metadata_block_size;
} __packed;

struct dm_sworndisk_metadata {
	refcount_t ref_count;
	struct list_head list;

	unsigned version;
	struct block_device *bdev;
	struct dm_block_manager *bm;
	struct dm_space_map *metadata_sm;
	struct dm_transaction_manager *tm;

	struct dm_array_info rit_info; // reverse index table info 
	struct dm_disk_bitset svt_info; // segment invalidation table info

    unsigned long nr_segment;
    dm_block_t blk_per_seg;

	struct rw_semaphore root_lock;
	unsigned long flags;
	dm_block_t rit_root;
	dm_block_t svt_root;

	sector_t data_block_size;
	bool changed:1;
	bool clean_when_opened:1;
	/*
	 * Reading the space map root can fail, so we read it into this
	 * buffer before the superblock is locked and updated.
	 */
	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];

	/*
	 * Set if a transaction has to be aborted but the attempt to roll
	 * back to the previous (good) transaction failed.  The only
	 * metadata operation permissible in this state is the closing of
	 * the device.
	 */
	bool fail_io:1;

	/*
	 * Metadata format 2 fields.
	 */

	/*
	 * These structures are used when loading metadata.  They're too
	 * big to put on the stack.
	 */
	struct dm_array_cursor svt_cursor;
	struct dm_array_cursor rit_cursor;
};

/*-------------------------------------------------------------------
 * superblock validator
 *-----------------------------------------------------------------*/

#define SUPERBLOCK_CSUM_XOR 9031977

static void sb_prepare_for_write(struct dm_block_validator *v,
				 struct dm_block *b,
				 size_t sb_block_size)
{
	struct sworndisk_disk_superblock *disk_super = dm_block_data(b);

	disk_super->blocknr = cpu_to_le64(dm_block_location(b));
	disk_super->csum = cpu_to_le32(dm_bm_checksum(&disk_super->flags,
						      sb_block_size - sizeof(__le32),
						      SUPERBLOCK_CSUM_XOR));
}

static int check_metadata_version(struct sworndisk_disk_superblock *disk_super)
{
	uint32_t metadata_version = le32_to_cpu(disk_super->version);

	if (metadata_version < MIN_SWORNDISK_VERSION || metadata_version > MAX_SWORNDISK_VERSION) {
		DMERR("SWORNDISK metadata version %u found, but only versions between %u and %u supported.",
		      metadata_version, MIN_SWORNDISK_VERSION, MAX_SWORNDISK_VERSION);
		return -EINVAL;
	}

	return 0;
}

// check super block
static int sb_check(struct dm_block_validator *v,
		    struct dm_block *b,
		    size_t sb_block_size)
{
	struct sworndisk_disk_superblock *disk_super = dm_block_data(b);
	__le32 csum_le;

    // check super block nr_block
	if (dm_block_location(b) != le64_to_cpu(disk_super->blocknr)) {
		DMERR("sb_check failed: blocknr %llu: wanted %llu",
		      le64_to_cpu(disk_super->blocknr),
		      (unsigned long long)dm_block_location(b));
		return -ENOTBLK;
	}

    // cehck super block magic number
	if (le64_to_cpu(disk_super->magic) != SWORNDISK_SUPERBLOCK_MAGIC) {
		DMERR("sb_check failed: magic %llu: wanted %llu",
		      le64_to_cpu(disk_super->magic),
		      (unsigned long long)SWORNDISK_SUPERBLOCK_MAGIC);
		return -EILSEQ;
	}

    // check super block checksum
	csum_le = cpu_to_le32(dm_bm_checksum(&disk_super->flags,
					     sb_block_size - sizeof(__le32),
					     SUPERBLOCK_CSUM_XOR));
	if (csum_le != disk_super->csum) {
		DMERR("sb_check failed: csum %u: wanted %u",
		      le32_to_cpu(csum_le), le32_to_cpu(disk_super->csum));
		return -EILSEQ;
	}

    // check super block metadata version
	return check_metadata_version(disk_super);
}

static struct dm_block_validator sb_validator = {
	.name = "superblock",
	.prepare_for_write = sb_prepare_for_write,
	.check = sb_check
};

/*----------------------------------------------------------------*/

static int superblock_read_lock(struct dm_sworndisk_metadata *cmd,
				struct dm_block **sblock)
{
	return dm_bm_read_lock(cmd->bm, SWORNDISK_SUPERBLOCK_LOCATION,
			       &sb_validator, sblock);
}

static int superblock_lock_zero(struct dm_sworndisk_metadata *cmd,
				struct dm_block **sblock)
{
	return dm_bm_write_lock_zero(cmd->bm, SWORNDISK_SUPERBLOCK_LOCATION,
				     &sb_validator, sblock);
}

static int superblock_lock(struct dm_sworndisk_metadata *cmd,
			   struct dm_block **sblock)
{
	return dm_bm_write_lock(cmd->bm, SWORNDISK_SUPERBLOCK_LOCATION,
				&sb_validator, sblock);
}

/*----------------------------------------------------------------*/

static int __superblock_all_zeroes(struct dm_block_manager *bm, bool *result)
{
	int r;
	unsigned i;
	struct dm_block *b;
	__le64 *data_le, zero = cpu_to_le64(0);
	unsigned sb_block_size = dm_bm_block_size(bm) / sizeof(__le64);

	/*
	 * We can't use a validator here - it may be all zeroes.
	 */
	r = dm_bm_read_lock(bm, SWORNDISK_SUPERBLOCK_LOCATION, NULL, &b);
	if (r)
		return r;

	data_le = dm_block_data(b);
	*result = true;
	for (i = 0; i < sb_block_size; i++) {
		if (data_le[i] != zero) {
			*result = false;
			break;
		}
	}

	dm_bm_unlock(b);

	return 0;
}

static void __setup_mapping_info(struct dm_sworndisk_metadata *cmd)
{
	struct dm_btree_value_type vt;

	vt.context = NULL;
	vt.size = sizeof(__le64);
	vt.inc = NULL;
	vt.dec = NULL;
	vt.equal = NULL;
	dm_array_info_init(&cmd->rit_info, cmd->tm, &vt);
}

static int __save_sm_root(struct dm_sworndisk_metadata *cmd)
{
	int r;
	size_t metadata_len;

	r = dm_sm_root_size(cmd->metadata_sm, &metadata_len);
	if (r < 0)
		return r;

	return dm_sm_copy_root(cmd->metadata_sm, &cmd->metadata_space_map_root,
			       metadata_len);
}

static void __copy_sm_root(struct dm_sworndisk_metadata *cmd,
			   struct sworndisk_disk_superblock *disk_super)
{
	memcpy(&disk_super->metadata_space_map_root,
	       &cmd->metadata_space_map_root,
	       sizeof(cmd->metadata_space_map_root));
}

static int __write_initial_superblock(struct dm_sworndisk_metadata *cmd)
{
	int r;
	struct dm_block *sblock;
	struct sworndisk_disk_superblock *disk_super;
	sector_t bdev_size = i_size_read(cmd->bdev->bd_inode) >> SECTOR_SHIFT;

	/* FIXME: see if we can lose the max sectors limit */
	if (bdev_size > DM_SWORNDISK_METADATA_MAX_SECTORS)
		bdev_size = DM_SWORNDISK_METADATA_MAX_SECTORS;

	r = dm_tm_pre_commit(cmd->tm);
	if (r < 0)
		return r;

	/*
	 * dm_sm_copy_root() can fail.  So we need to do it before we start
	 * updating the superblock.
	 */
	r = __save_sm_root(cmd);
	if (r)
		return r;

	r = superblock_lock_zero(cmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	disk_super->flags = 0;
	memset(disk_super->uuid, 0, sizeof(disk_super->uuid));
	disk_super->magic = cpu_to_le64(SWORNDISK_SUPERBLOCK_MAGIC);
	disk_super->version = cpu_to_le32(cmd->version);

	__copy_sm_root(cmd, disk_super);

	disk_super->rit_root = cpu_to_le64(cmd->rit_root);
	disk_super->svt_root = cpu_to_le64(cmd->svt_root);
    disk_super->nr_segment = cpu_to_le64(cmd->nr_segment);
    disk_super->blk_per_seg = cpu_to_le64(cmd->blk_per_seg);
	disk_super->metadata_block_size = cpu_to_le32(DM_SWORNDISK_METADATA_BLOCK_SIZE);
	disk_super->data_block_size = cpu_to_le32(cmd->data_block_size);

	return dm_tm_commit(cmd->tm, sblock);
}

static int __format_metadata(struct dm_sworndisk_metadata *cmd)
{
	int r;

	r = dm_tm_create_with_sm(cmd->bm, SWORNDISK_SUPERBLOCK_LOCATION,
				 &cmd->tm, &cmd->metadata_sm);
	if (r < 0) {
		DMERR("tm_create_with_sm failed");
		return r;
	}

	__setup_mapping_info(cmd);

	r = dm_array_empty(&cmd->rit_info, &cmd->rit_root);
	if (r < 0)
		goto bad;

	dm_disk_bitset_init(cmd->tm, &cmd->svt_info);
	r = dm_bitset_empty(&cmd->svt_info, &cmd->svt_root);
	if (r < 0)
		goto bad;

	r = __write_initial_superblock(cmd);
	if (r)
		goto bad;

	cmd->clean_when_opened = true;
	return 0;

bad:
	dm_tm_destroy(cmd->tm);
	dm_sm_destroy(cmd->metadata_sm);

	return r;
}

static int __open_metadata(struct dm_sworndisk_metadata *cmd)
{
	int r;
	struct dm_block *sblock;
	struct sworndisk_disk_superblock *disk_super;
	unsigned long sb_flags;

	r = superblock_read_lock(cmd, &sblock);
	if (r < 0) {
		DMERR("couldn't read lock superblock");
		return r;
	}

	disk_super = dm_block_data(sblock);

	/* Verify the data block size hasn't changed */
	if (le32_to_cpu(disk_super->data_block_size) != cmd->data_block_size) {
		DMERR("changing the data block size (from %u to %llu) is not supported",
		      le32_to_cpu(disk_super->data_block_size),
		      (unsigned long long)cmd->data_block_size);
		r = -EINVAL;
		goto bad;
	}

	r = dm_tm_open_with_sm(cmd->bm, SWORNDISK_SUPERBLOCK_LOCATION,
			       disk_super->metadata_space_map_root,
			       sizeof(disk_super->metadata_space_map_root),
			       &cmd->tm, &cmd->metadata_sm);
	if (r < 0) {
		DMERR("tm_open_with_sm failed");
		goto bad;
	}

	__setup_mapping_info(cmd);
	dm_disk_bitset_init(cmd->tm, &cmd->svt_info);
	sb_flags = le32_to_cpu(disk_super->flags);
	cmd->clean_when_opened = test_bit(CLEAN_SHUTDOWN, &sb_flags);
	dm_bm_unlock(sblock);

	return 0;

bad:
	dm_bm_unlock(sblock);
	return r;
}

static int __open_or_format_metadata(struct dm_sworndisk_metadata *cmd,
				     bool format_device)
{
	int r;
	bool unformatted = false;

	r = __superblock_all_zeroes(cmd->bm, &unformatted);
	if (r)
		return r;

	if (unformatted)
		return format_device ? __format_metadata(cmd) : -EPERM;

	return __open_metadata(cmd);
}

static int __create_persistent_data_objects(struct dm_sworndisk_metadata *cmd,
					    bool may_format_device)
{
	int r;
	cmd->bm = dm_block_manager_create(cmd->bdev, DM_SWORNDISK_METADATA_BLOCK_SIZE << SECTOR_SHIFT,
					  SWORNDISK_MAX_CONCURRENT_LOCKS);
	if (IS_ERR(cmd->bm)) {
		DMERR("could not create block manager");
		r = PTR_ERR(cmd->bm);
		cmd->bm = NULL;
		return r;
	}

	r = __open_or_format_metadata(cmd, may_format_device);
	if (r) {
		dm_block_manager_destroy(cmd->bm);
		cmd->bm = NULL;
	}

	return r;
}

static void __destroy_persistent_data_objects(struct dm_sworndisk_metadata *cmd)
{
	dm_sm_destroy(cmd->metadata_sm);
	dm_tm_destroy(cmd->tm);
	dm_block_manager_destroy(cmd->bm);
}

typedef unsigned long (*flags_mutator)(unsigned long);

static void update_flags(struct sworndisk_disk_superblock *disk_super,
			 flags_mutator mutator)
{
	uint32_t sb_flags = mutator(le32_to_cpu(disk_super->flags));
	disk_super->flags = cpu_to_le32(sb_flags);
}

static unsigned long set_clean_shutdown(unsigned long flags)
{
	set_bit(CLEAN_SHUTDOWN, &flags);
	return flags;
}

static unsigned long clear_clean_shutdown(unsigned long flags)
{
	clear_bit(CLEAN_SHUTDOWN, &flags);
	return flags;
}

static void read_superblock_fields(struct dm_sworndisk_metadata *cmd,
				   struct sworndisk_disk_superblock *disk_super)
{
	cmd->version = le32_to_cpu(disk_super->version);
	cmd->flags = le32_to_cpu(disk_super->flags);
	cmd->rit_root = le64_to_cpu(disk_super->rit_root);
	cmd->svt_root = le64_to_cpu(disk_super->svt_root);
    cmd->nr_segment = le64_to_cpu(disk_super->nr_segment);
    cmd->blk_per_seg = le64_to_cpu(disk_super->blk_per_seg);
	cmd->data_block_size = le32_to_cpu(disk_super->data_block_size);

	cmd->changed = false;
}

/*
 * The mutator updates the superblock flags.
 */
static int __begin_transaction_flags(struct dm_sworndisk_metadata *cmd,
				     flags_mutator mutator)
{
	int r;
	struct sworndisk_disk_superblock *disk_super;
	struct dm_block *sblock;

	r = superblock_lock(cmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	update_flags(disk_super, mutator);
	read_superblock_fields(cmd, disk_super);
	dm_bm_unlock(sblock);

	return dm_bm_flush(cmd->bm);
}

static int __begin_transaction(struct dm_sworndisk_metadata *cmd)
{
	int r;
	struct sworndisk_disk_superblock *disk_super;
	struct dm_block *sblock;

	/*
	 * We re-read the superblock every time.  Shouldn't need to do this
	 * really.
	 */
	r = superblock_read_lock(cmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);
	read_superblock_fields(cmd, disk_super);
	dm_bm_unlock(sblock);

	return 0;
}

static int __commit_transaction(struct dm_sworndisk_metadata *cmd,
				flags_mutator mutator)
{
	int r;
	struct sworndisk_disk_superblock *disk_super;
	struct dm_block *sblock;

	/*
	 * We need to know if the sworndisk_disk_superblock exceeds a 512-byte sector.
	 */
	BUILD_BUG_ON(sizeof(struct sworndisk_disk_superblock) > 512);

	r = dm_bitset_flush(&cmd->svt_info, cmd->svt_root,
			    &cmd->svt_root);
	if (r)
		return r;

	r = dm_tm_pre_commit(cmd->tm);
	if (r < 0)
		return r;

	r = __save_sm_root(cmd);
	if (r)
		return r;

	r = superblock_lock(cmd, &sblock);
	if (r)
		return r;

	disk_super = dm_block_data(sblock);

	disk_super->flags = cpu_to_le32(cmd->flags);
	if (mutator)
		update_flags(disk_super, mutator);

	disk_super->rit_root = cpu_to_le64(cmd->rit_root);
	disk_super->svt_root = cpu_to_le64(cmd->svt_root);
    disk_super->nr_segment = cpu_to_le64(cmd->nr_segment);
    disk_super->blk_per_seg = cpu_to_le64(cmd->blk_per_seg);
	__copy_sm_root(cmd, disk_super);

	return dm_tm_commit(cmd->tm, sblock); 
}


static struct dm_sworndisk_metadata *metadata_open(struct block_device *bdev,
					       sector_t data_block_size,
					       bool may_format_device,
					       unsigned metadata_version)
{
	int r;
	struct dm_sworndisk_metadata *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		DMERR("could not allocate metadata struct");
		return ERR_PTR(-ENOMEM);
	}

	cmd->version = metadata_version;
	refcount_set(&cmd->ref_count, 1);
	init_rwsem(&cmd->root_lock);
	cmd->bdev = bdev;
	cmd->data_block_size = data_block_size;
	cmd->changed = true;
	cmd->fail_io = false;

	r = __create_persistent_data_objects(cmd, may_format_device);
	if (r) {
		kfree(cmd);
		return ERR_PTR(r);
	}

	r = __begin_transaction_flags(cmd, clear_clean_shutdown);
	if (r < 0) {
		dm_sworndisk_metadata_close(cmd);
		return ERR_PTR(r);
	}

	return cmd;
}

/*
 * We keep a little list of ref counted metadata objects to prevent two
 * different target instances creating separate bufio instances.  This is
 * an issue if a table is reloaded before the suspend.
 */
static DEFINE_MUTEX(table_lock);
static LIST_HEAD(table);

static struct dm_sworndisk_metadata *lookup(struct block_device *bdev)
{
	struct dm_sworndisk_metadata *cmd;

	list_for_each_entry(cmd, &table, list)
		if (cmd->bdev == bdev) {
			refcount_inc(&cmd->ref_count);
			return cmd;
		}

	return NULL;
}

static struct dm_sworndisk_metadata *lookup_or_open(struct block_device *bdev,
						sector_t data_block_size,
						bool may_format_device,
						unsigned metadata_version)
{
	struct dm_sworndisk_metadata *cmd, *cmd2;

	mutex_lock(&table_lock);
	cmd = lookup(bdev);
	mutex_unlock(&table_lock);

	if (cmd)
		return cmd;

	cmd = metadata_open(bdev, data_block_size, may_format_device, metadata_version);
	if (!IS_ERR(cmd)) {
		mutex_lock(&table_lock);
		cmd2 = lookup(bdev);
		if (cmd2) {
			mutex_unlock(&table_lock);
			__destroy_persistent_data_objects(cmd);
			kfree(cmd);
			return cmd2;
		}
		list_add(&cmd->list, &table);
		mutex_unlock(&table_lock);
	}

	return cmd;
}

static bool same_params(struct dm_sworndisk_metadata *cmd, sector_t data_block_size)
{
	if (cmd->data_block_size != data_block_size) {
		DMERR("data_block_size (%llu) different from that in metadata (%llu)",
		      (unsigned long long) data_block_size,
		      (unsigned long long) cmd->data_block_size);
		return false;
	}

	return true;
}

struct dm_sworndisk_metadata *dm_sworndisk_metadata_open(struct block_device *bdev,
						 sector_t data_block_size,
						 bool may_format_device,
						 unsigned metadata_version)
{
	struct dm_sworndisk_metadata *cmd = lookup_or_open(bdev, data_block_size, may_format_device, metadata_version);

	if (!IS_ERR(cmd) && !same_params(cmd, data_block_size)) {
		dm_sworndisk_metadata_close(cmd);
		return ERR_PTR(-EINVAL);
	}

	return cmd;
}

void dm_sworndisk_metadata_close(struct dm_sworndisk_metadata *cmd)
{
	if (refcount_dec_and_test(&cmd->ref_count)) {
		mutex_lock(&table_lock);
		list_del(&cmd->list);
		mutex_unlock(&table_lock);

		if (!cmd->fail_io)
			__destroy_persistent_data_objects(cmd);
		kfree(cmd);
	}
}


static bool cmd_write_lock(struct dm_sworndisk_metadata *cmd)
{
	down_write(&cmd->root_lock);
	if (cmd->fail_io || dm_bm_is_read_only(cmd->bm)) {
		up_write(&cmd->root_lock);
		return false;
	}
	return true;
}

#define WRITE_LOCK(cmd)				\
	do {					\
		if (!cmd_write_lock((cmd)))	\
			return -EINVAL;		\
	} while(0)

#define WRITE_LOCK_VOID(cmd)			\
	do {					\
		if (!cmd_write_lock((cmd)))	\
			return;			\
	} while(0)

#define WRITE_UNLOCK(cmd) \
	up_write(&(cmd)->root_lock)

static bool cmd_read_lock(struct dm_sworndisk_metadata *cmd)
{
	down_read(&cmd->root_lock);
	if (cmd->fail_io) {
		up_read(&cmd->root_lock);
		return false;
	}
	return true;
}

#define READ_LOCK(cmd)				\
	do {					\
		if (!cmd_read_lock((cmd)))	\
			return -EINVAL;		\
	} while(0)

#define READ_LOCK_VOID(cmd)			\
	do {					\
		if (!cmd_read_lock((cmd)))	\
			return;			\
	} while(0)

#define READ_UNLOCK(cmd) \
	up_read(&(cmd)->root_lock)


int dm_sworndisk_commit(struct dm_sworndisk_metadata *cmd, bool clean_shutdown)
{
	int r = -EINVAL;
	flags_mutator mutator = (clean_shutdown ? set_clean_shutdown :
				 clear_clean_shutdown);

	WRITE_LOCK(cmd);
	if (cmd->fail_io)
		goto out;

	r = __commit_transaction(cmd, mutator);
	if (r)
		goto out;

	r = __begin_transaction(cmd);
out:
	WRITE_UNLOCK(cmd);
	return r;
}

int dm_sworndisk_get_free_metadata_block_count(struct dm_sworndisk_metadata *cmd,
					   dm_block_t *result)
{
	int r = -EINVAL;

	READ_LOCK(cmd);
	if (!cmd->fail_io)
		r = dm_sm_get_nr_free(cmd->metadata_sm, result);
	READ_UNLOCK(cmd);

	return r;
}

int dm_sworndisk_get_metadata_dev_size(struct dm_sworndisk_metadata *cmd,
				   dm_block_t *result)
{
	int r = -EINVAL;

	READ_LOCK(cmd);
	if (!cmd->fail_io)
		r = dm_sm_get_nr_blocks(cmd->metadata_sm, result);
	READ_UNLOCK(cmd);

	return r;
}

/*----------------------------------------------------------------*/



void dm_sworndisk_metadata_set_read_only(struct dm_sworndisk_metadata *cmd)
{
	WRITE_LOCK_VOID(cmd);
	dm_bm_set_read_only(cmd->bm);
	WRITE_UNLOCK(cmd);
}

void dm_sworndisk_metadata_set_read_write(struct dm_sworndisk_metadata *cmd)
{
	WRITE_LOCK_VOID(cmd);
	dm_bm_set_read_write(cmd->bm);
	WRITE_UNLOCK(cmd);
}

int dm_sworndisk_metadata_set_needs_check(struct dm_sworndisk_metadata *cmd)
{
	int r;
	struct dm_block *sblock;
	struct sworndisk_disk_superblock *disk_super;

	WRITE_LOCK(cmd);
	set_bit(NEEDS_CHECK, &cmd->flags);

	r = superblock_lock(cmd, &sblock);
	if (r) {
		DMERR("couldn't read superblock");
		goto out;
	}

	disk_super = dm_block_data(sblock);
	disk_super->flags = cpu_to_le32(cmd->flags);

	dm_bm_unlock(sblock);

out:
	WRITE_UNLOCK(cmd);
	return r;
}

int dm_sworndisk_metadata_needs_check(struct dm_sworndisk_metadata *cmd, bool *result)
{
	READ_LOCK(cmd);
	*result = !!test_bit(NEEDS_CHECK, &cmd->flags);
	READ_UNLOCK(cmd);

	return 0;
}

int dm_sworndisk_metadata_abort(struct dm_sworndisk_metadata *cmd)
{
	int r;

	WRITE_LOCK(cmd);
	__destroy_persistent_data_objects(cmd);
	r = __create_persistent_data_objects(cmd, false);
	if (r)
		cmd->fail_io = true;
	WRITE_UNLOCK(cmd);

	return r;
}

static int __set_svt(struct dm_sworndisk_metadata *cmd, dm_dblock_t b)
{
	return dm_bitset_set_bit(&cmd->svt_info, cmd->svt_root,
				 from_dblock(b), &cmd->svt_root);
}

static int __clear_svt(struct dm_sworndisk_metadata *cmd, dm_dblock_t b)
{
	return dm_bitset_clear_bit(&cmd->svt_info, cmd->svt_root,
				   from_dblock(b), &cmd->svt_root);
}

static int __svt(struct dm_sworndisk_metadata *cmd,
		     dm_dblock_t dblock, bool valid)
{
	int r;

	r = (valid ? __set_svt : __clear_svt)(cmd, dblock);
	if (r)
		return r;

	cmd->changed = true;
	return 0;
}

int dm_sworndisk_set_svt(struct dm_sworndisk_metadata *cmd,
			 dm_dblock_t dblock, bool valid)
{
	int r;

	WRITE_LOCK(cmd);
	r = __svt(cmd, dblock, valid);
	WRITE_UNLOCK(cmd);

	return r;
}

int dm_sworndisk_get_first_free_segment(struct dm_sworndisk_metadata *cmd, int *seg) {
    int i, err;
    bool result;
    
    for (i=0; i<cmd->nr_segment; ++i) {
        err = dm_bitset_test_bit(&cmd->svt_info, cmd->svt_root, i, &cmd->svt_root, &result);
        if (err)
            return err;
        if (result == false) {
            *seg = i;
            return 0;
        }
    }
    return 0;
}