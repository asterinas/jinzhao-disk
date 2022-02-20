#include "persistent-data/dm-space-map-metadata.h"
#include "persistent-data/dm-block-manager.h"

/*----------------------------------------------------------------*/

#define DM_CACHE_METADATA_BLOCK_SIZE DM_SM_METADATA_BLOCK_SIZE

/* FIXME: remove this restriction */
/*
 * The metadata device is currently limited in size.
 */
#define DM_CACHE_METADATA_MAX_SECTORS DM_SM_METADATA_MAX_SECTORS

/*
 * A metadata device larger than 16GB triggers a warning.
 */
#define DM_CACHE_METADATA_MAX_SECTORS_WARNING (16 * (1024 * 1024 * 1024 >> SECTOR_SHIFT))

typedef dm_block_t __bitwise dm_oblock_t;
typedef uint32_t __bitwise dm_cblock_t;
typedef dm_block_t __bitwise dm_dblock_t;

static inline dm_oblock_t to_oblock(dm_block_t b)
{
	return (__force dm_oblock_t) b;
}

static inline dm_block_t from_oblock(dm_oblock_t b)
{
	return (__force dm_block_t) b;
}

static inline dm_cblock_t to_cblock(uint32_t b)
{
	return (__force dm_cblock_t) b;
}

static inline uint32_t from_cblock(dm_cblock_t b)
{
	return (__force uint32_t) b;
}

static inline dm_dblock_t to_dblock(dm_block_t b)
{
	return (__force dm_dblock_t) b;
}

static inline dm_block_t from_dblock(dm_dblock_t b)
{
	return (__force dm_block_t) b;
}

struct dm_cache_metadata;

/*
 * Reopens or creates a new, empty metadata volume.  Returns an ERR_PTR on
 * failure.  If reopening then features must match.
 */
struct dm_cache_metadata *dm_cache_metadata_open(struct block_device *bdev,
						 sector_t data_block_size,
						 bool may_format_device, sector_t len);

void dm_cache_metadata_close(struct dm_cache_metadata *cmd);

int dm_cache_read(struct dm_cache_metadata *cmd, dm_oblock_t lba, __le64 *pba);
int dm_cache_write(struct dm_cache_metadata *cmd, dm_oblock_t lba, dm_oblock_t pba);
int dm_cache_create_info(struct dm_cache_metadata *cmd, void *context);