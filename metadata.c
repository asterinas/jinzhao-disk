#include "metadata.h"
#include "persistent-data/dm-array.h"
#include "persistent-data/dm-bitset.h"
#include "persistent-data/dm-space-map.h"
#include "persistent-data/dm-space-map-disk.h"
#include "persistent-data/dm-transaction-manager.h"

#include <linux/device-mapper.h>
#include <linux/refcount.h>

/*----------------------------------------------------------------*/

#define DM_MSG_PREFIX   "cache metadata"

#define CACHE_SUPERBLOCK_MAGIC 06142003
#define CACHE_SUPERBLOCK_LOCATION 0

#define CACHE_MAX_CONCURRENT_LOCKS 5
#define SPACE_MAP_ROOT_SIZE 128

enum superblock_flag_bits {
	/* for spotting crashes that would invalidate the dirty bitset */
	CLEAN_SHUTDOWN,
	/* metadata must be checked using the tools */
	NEEDS_CHECK,
};

struct cache_disk_superblock {
	__le32 csum;
	__le32 flags;
	__le64 blocknr;

	__u8 uuid[16];
	__le64 magic;
	__le32 version;

	__u8 metadata_space_map_root[SPACE_MAP_ROOT_SIZE];
	__le64 mapping_root;

	__le32 data_block_size;
	__le32 metadata_block_size;

	__le32 compat_flags;
	__le32 compat_ro_flags;
	__le32 incompat_flags;

} __packed;

struct dm_cache_metadata {
	refcount_t ref_count;
	struct list_head list;

	unsigned version;
	struct block_device *bdev;
	struct dm_block_manager *bm;
	struct dm_space_map *metadata_sm;
	struct dm_transaction_manager *tm;

	struct dm_array_info info;


	struct rw_semaphore root_lock;
	unsigned long flags;
	dm_block_t root;

	sector_t data_block_size;
	bool changed:1;
	bool clean_when_opened:1;
	uint32_t sst_len;

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
	 * These structures are used when loading metadata.  They're too
	 * big to put on the stack.
	 */
	struct dm_array_cursor mapping_cursor;
	struct dm_array_cursor hint_cursor;
	struct dm_bitset_cursor dirty_cursor;
};

#define SUPERBLOCK_CSUM_XOR 9031977

static void sb_prepare_for_write(struct dm_block_validator *v,
				 struct dm_block *b,
				 size_t sb_block_size)
{
	struct cache_disk_superblock *disk_super = dm_block_data(b);

	disk_super->blocknr = cpu_to_le64(dm_block_location(b));
	disk_super->csum = cpu_to_le32(dm_bm_checksum(&disk_super->flags,
						      sb_block_size - sizeof(__le32),
						      SUPERBLOCK_CSUM_XOR));
}

static int sb_check(struct dm_block_validator *v,
		    struct dm_block *b,
		    size_t sb_block_size)
{
	struct cache_disk_superblock *disk_super = dm_block_data(b);
	__le32 csum_le;

	if (dm_block_location(b) != le64_to_cpu(disk_super->blocknr)) {
		DMERR("sb_check failed: blocknr %llu: wanted %llu",
		      le64_to_cpu(disk_super->blocknr),
		      (unsigned long long)dm_block_location(b));
		return -ENOTBLK;
	}

	if (le64_to_cpu(disk_super->magic) != CACHE_SUPERBLOCK_MAGIC) {
		DMERR("sb_check failed: magic %llu: wanted %llu",
		      le64_to_cpu(disk_super->magic),
		      (unsigned long long)CACHE_SUPERBLOCK_MAGIC);
		return -EILSEQ;
	}

	csum_le = cpu_to_le32(dm_bm_checksum(&disk_super->flags,
					     sb_block_size - sizeof(__le32),
					     SUPERBLOCK_CSUM_XOR));
	if (csum_le != disk_super->csum) {
		DMERR("sb_check failed: csum %u: wanted %u",
		      le32_to_cpu(csum_le), le32_to_cpu(disk_super->csum));
		return -EILSEQ;
	}

	return 0;
}

static struct dm_block_validator sb_validator = {
	.name = "superblock",
	.prepare_for_write = sb_prepare_for_write,
	.check = sb_check
};

/*----------------------------------------------------------------*/

static int superblock_read_lock(struct dm_cache_metadata *cmd,
				struct dm_block **sblock)
{
	return dm_bm_read_lock(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
			       &sb_validator, sblock);
}

static int superblock_lock_zero(struct dm_cache_metadata *cmd,
				struct dm_block **sblock)
{
	return dm_bm_write_lock_zero(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
				     &sb_validator, sblock);
}

static int superblock_lock(struct dm_cache_metadata *cmd,
			   struct dm_block **sblock)
{
	return dm_bm_write_lock(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
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
	r = dm_bm_read_lock(bm, CACHE_SUPERBLOCK_LOCATION, NULL, &b);
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

static void __setup_mapping_info(struct dm_cache_metadata *cmd)
{
	struct dm_btree_value_type vt;

	vt.context = NULL;
	vt.size = sizeof(__le64);
	vt.inc = NULL;
	vt.dec = NULL;
	vt.equal = NULL;
	dm_array_info_init(&cmd->info, cmd->tm, &vt);
}

static int __save_sm_root(struct dm_cache_metadata *cmd)
{
	int r;
	size_t metadata_len;

	r = dm_sm_root_size(cmd->metadata_sm, &metadata_len);
	if (r < 0)
		return r;

	return dm_sm_copy_root(cmd->metadata_sm, &cmd->metadata_space_map_root,
			       metadata_len);
}

static void __copy_sm_root(struct dm_cache_metadata *cmd,
			   struct cache_disk_superblock *disk_super)
{
	memcpy(&disk_super->metadata_space_map_root,
	       &cmd->metadata_space_map_root,
	       sizeof(cmd->metadata_space_map_root));
}


static int __write_initial_superblock(struct dm_cache_metadata *cmd)
{
	int r;
	struct dm_block *sblock;
	struct cache_disk_superblock *disk_super;
	sector_t bdev_size = i_size_read(cmd->bdev->bd_inode) >> SECTOR_SHIFT;

	/* FIXME: see if we can lose the max sectors limit */
	if (bdev_size > DM_CACHE_METADATA_MAX_SECTORS)
		bdev_size = DM_CACHE_METADATA_MAX_SECTORS;

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
	disk_super->magic = cpu_to_le64(CACHE_SUPERBLOCK_MAGIC);

	__copy_sm_root(cmd, disk_super);

	disk_super->mapping_root = cpu_to_le64(cmd->root);
	disk_super->metadata_block_size = cpu_to_le32(DM_CACHE_METADATA_BLOCK_SIZE);
	disk_super->data_block_size = cpu_to_le32(cmd->data_block_size);
	
	return dm_tm_commit(cmd->tm, sblock);
}

static int __format_metadata(struct dm_cache_metadata *cmd)
{
	int r;

	r = dm_tm_create_with_sm(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
				 &cmd->tm, &cmd->metadata_sm);
	if (r < 0) {
		DMERR("tm_create_with_sm failed");
		return r;
	}

	__setup_mapping_info(cmd);

	r = dm_array_empty(&cmd->info, &cmd->root);
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


static int __open_metadata(struct dm_cache_metadata *cmd)
{
	int r;
	struct dm_block *sblock;
	struct cache_disk_superblock *disk_super;
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

	r = dm_tm_open_with_sm(cmd->bm, CACHE_SUPERBLOCK_LOCATION,
			       disk_super->metadata_space_map_root,
			       sizeof(disk_super->metadata_space_map_root),
			       &cmd->tm, &cmd->metadata_sm);
	if (r < 0) {
		DMERR("tm_open_with_sm failed");
		goto bad;
	}

	__setup_mapping_info(cmd);
	sb_flags = le32_to_cpu(disk_super->flags);
	cmd->clean_when_opened = test_bit(CLEAN_SHUTDOWN, &sb_flags);
	dm_bm_unlock(sblock);

	return 0;

bad:
	dm_bm_unlock(sblock);
	return r;
}


static int __open_or_format_metadata(struct dm_cache_metadata *cmd,
				     bool format_device)
{
	int r;
	bool unformatted = false;

	r = __superblock_all_zeroes(cmd->bm, &unformatted);
	if (r)
		return r;

	return __format_metadata(cmd);
	//if (unformatted)
	//	return format_device ? __format_metadata(cmd) : -EPERM;

	//return __open_metadata(cmd);
}


static int __create_persistent_data_objects(struct dm_cache_metadata *cmd,
					    bool may_format_device)
{
	int r;
	cmd->bm = dm_block_manager_create(cmd->bdev, DM_CACHE_METADATA_BLOCK_SIZE << SECTOR_SHIFT,
					  CACHE_MAX_CONCURRENT_LOCKS);
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

static void __destroy_persistent_data_objects(struct dm_cache_metadata *cmd)
{
	dm_sm_destroy(cmd->metadata_sm);
	dm_tm_destroy(cmd->tm);
	dm_block_manager_destroy(cmd->bm);
}

typedef unsigned long (*flags_mutator)(unsigned long);

static void update_flags(struct cache_disk_superblock *disk_super,
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


static void read_superblock_fields(struct dm_cache_metadata *cmd,
				   struct cache_disk_superblock *disk_super)
{
	cmd->version = le32_to_cpu(disk_super->version);
	cmd->flags = le32_to_cpu(disk_super->flags);
	cmd->root = le64_to_cpu(disk_super->mapping_root);
	cmd->data_block_size = le32_to_cpu(disk_super->data_block_size);

	cmd->changed = false;
}


/*
 * The mutator updates the superblock flags.
 */
static int __begin_transaction_flags(struct dm_cache_metadata *cmd,
				     flags_mutator mutator)
{
	int r;
	struct cache_disk_superblock *disk_super;
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

static int __begin_transaction(struct dm_cache_metadata *cmd)
{
	int r;
	struct cache_disk_superblock *disk_super;
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


static int __commit_transaction(struct dm_cache_metadata *cmd,
				flags_mutator mutator)
{
	int r;
	struct cache_disk_superblock *disk_super;
	struct dm_block *sblock;

	/*
	 * We need to know if the cache_disk_superblock exceeds a 512-byte sector.
	 */
	BUILD_BUG_ON(sizeof(struct cache_disk_superblock) > 512);

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

	disk_super->mapping_root = cpu_to_le64(cmd->root);
	__copy_sm_root(cmd, disk_super);

	return dm_tm_commit(cmd->tm, sblock);
}


/*
 * The mappings are held in a dm-array that has 64-bit values stored in
 * little-endian format.  The index is the cblock, the high 48bits of the
 * value are the oblock and the low 16 bit the flags.
 */
#define FLAGS_MASK ((1 << 16) - 1)

static __le64 pack_value(dm_oblock_t lba, dm_oblock_t pba)
{
	uint64_t value = from_oblock(lba);
	value <<= 32;
	value = value | pba;
	return cpu_to_le64(value);
}

static void unpack_value(__le64 value_le, dm_oblock_t *lba, dm_oblock_t *pba)
{
	uint64_t value = le64_to_cpu(value_le);
	uint64_t b = value >> 32;
	uint64_t c = value << 32 >> 32;
	*lba = to_oblock(b);
	*pba = to_oblock(c);
}


/*----------------------------------------------------------------*/

static struct dm_cache_metadata *metadata_open(struct block_device *bdev,
					       sector_t data_block_size,
						   bool may_format_device)
{
	int r;
	struct dm_cache_metadata *cmd;

	cmd = kzalloc(sizeof(*cmd), GFP_KERNEL);
	if (!cmd) {
		DMERR("could not allocate metadata struct");
		return ERR_PTR(-ENOMEM);
	}

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
		dm_cache_metadata_close(cmd);
		return ERR_PTR(r);
	}

	return cmd;
}


static DEFINE_MUTEX(table_lock);
static LIST_HEAD(table);

static struct dm_cache_metadata *lookup(struct block_device *bdev)
{
	struct dm_cache_metadata *cmd;

	list_for_each_entry(cmd, &table, list)
		if (cmd->bdev == bdev) {
			refcount_inc(&cmd->ref_count);
			return cmd;
		}

	return NULL;
}

static struct dm_cache_metadata *lookup_or_open(struct block_device *bdev,
						sector_t data_block_size,
						bool may_format_device)
{
	struct dm_cache_metadata *cmd, *cmd2;

	mutex_lock(&table_lock);
	cmd = lookup(bdev);
	mutex_unlock(&table_lock);

	if (cmd)
		return cmd;

	cmd = metadata_open(bdev, data_block_size, may_format_device);
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

static bool same_params(struct dm_cache_metadata *cmd, sector_t data_block_size)
{
	if (cmd->data_block_size != data_block_size) {
		DMERR("data_block_size (%llu) different from that in metadata (%llu)",
		      (unsigned long long) data_block_size,
		      (unsigned long long) cmd->data_block_size);
		return false;
	}

	return true;
}

void dm_cache_metadata_close(struct dm_cache_metadata *cmd)
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

static bool cmd_write_lock(struct dm_cache_metadata *cmd)
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

static bool cmd_read_lock(struct dm_cache_metadata *cmd)
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


static int __get_value(struct dm_cache_metadata *cmd, dm_oblock_t lba, dm_oblock_t *pba)
{
	int r;
	unsigned flags;
	dm_oblock_t oblock;
	__le64 value;

	r = dm_array_get_value(&cmd->info, cmd->root, from_cblock(lba), &value);
	if (r)
		return r;

	unpack_value(value, &lba, pba);
	return 0;

}

static int __set_value(struct dm_cache_metadata *cmd, dm_oblock_t lba, dm_oblock_t pba)
{
	int r;
	unsigned flags;

	__le64 value = pack_value(lba, pba);

	__dm_bless_for_disk(&value);
	r = dm_array_set_value(&cmd->info, cmd->root, from_cblock(lba), &value, &cmd->root);
	if (r)
		return r;

	return 0;

}

int dm_cache_read(struct dm_cache_metadata *cmd, dm_oblock_t lba, __le64 *pba)
{
	int r;
	__le64 value;

	READ_LOCK(cmd);
    dm_array_get_value(&cmd->info, cmd->root, lba, pba);
	READ_UNLOCK(cmd);

	return r;
}

int dm_cache_write(struct dm_cache_metadata *cmd, dm_oblock_t lba, dm_oblock_t pba)
{
	int r;

	WRITE_LOCK(cmd);
	r = __get_value(cmd, lba, pba);
	WRITE_UNLOCK(cmd);

	return r;

}

static int get_lbapba(uint32_t index, void *value_le, void *context)
{
	uint64_t value;
	uint64_t *lba_pba = context;

	value = lba_pba[index];
	*((__le64 *) value_le) = cpu_to_le64(value);
	//DMINFO("123  %d  %d", (int)index, (int)value);

	return 0;
}

struct dm_cache_metadata *dm_cache_metadata_open(struct block_device *bdev,
						 sector_t data_block_size,
						 bool may_format_device, sector_t len)
{
	int i;
	struct dm_cache_metadata *cmd = lookup_or_open(bdev, data_block_size, may_format_device);

	if (!IS_ERR(cmd) && !same_params(cmd, data_block_size)) {
		dm_cache_metadata_close(cmd);
		return ERR_PTR(-EINVAL);
	}

	DMINFO("!root %d", (int)cmd->root);
	cmd->sst_len = len / 8;
	
    uint64_t *x = kmalloc(sizeof(uint64_t) * cmd->sst_len, GFP_KERNEL);
	for (i = 0; i < len / 8; i++)
		x[i] = (i * 8LL << 32) + i * 8;
	int r = dm_array_del(&cmd->info, cmd->root);
	r = dm_array_new(&cmd->info, &cmd->root, cmd->sst_len, get_lbapba, x);
	return cmd;
}

int dm_cache_create_info(struct dm_cache_metadata *cmd, void *context)
{
	int r;
	WRITE_LOCK(cmd);
	if (cmd->root) {
		r = dm_array_del(&cmd->info, cmd->root);
		if (r)
			return r;
	}
	r = dm_array_new(&cmd->info, &cmd->root, cmd->sst_len, get_lbapba, context);
	WRITE_UNLOCK(cmd);
	return r;
}

