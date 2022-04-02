#include "../include/metadata.h"

#define SUPERBLOCK_LOCATION 0
#define SUPERBLOCK_MAGIC 0x22946
#define SUPERBLOCK_CSUM_XOR 0x3828

// superblock implementation
int superblock_read(struct superblock* this) {
	int r;
	struct superblock* disk_super;
	struct dm_block* block;

	r = dm_bm_read_lock(this->bm, SUPERBLOCK_LOCATION, NULL, &block);
	if (r) 
		return -ENODATA;
	
	disk_super = dm_block_data(block);
	
	this->csum = le32_to_cpu(disk_super->csum);
	this->magic = le64_to_cpu(disk_super->magic);
	this->blocks_per_seg = le32_to_cpu(disk_super->blocks_per_seg);
	this->nr_segment = le64_to_cpu(disk_super->nr_segment);
	this->common_ratio = le32_to_cpu(disk_super->common_ratio);
	this->nr_disk_level = le32_to_cpu(disk_super->nr_disk_level);
	this->max_disk_level_size = le64_to_cpu(disk_super->max_disk_level_size);
	this->index_region_start = le64_to_cpu(disk_super->index_region_start);
	this->journal_size = le32_to_cpu(disk_super->journal_size);
	this->nr_journal = le64_to_cpu(disk_super->nr_journal);
	this->cur_journal = le64_to_cpu(disk_super->cur_journal);
	this->journal_region_start = le64_to_cpu(disk_super->journal_region_start);
	this->seg_validity_table_start = le64_to_cpu(disk_super->seg_validity_table_start);
	this->data_seg_table_start = le64_to_cpu(disk_super->data_seg_table_start);
	this->reverse_index_table_start = le64_to_cpu(disk_super->reverse_index_table_start);

	dm_bm_unlock(block);
	return 0;
}

int superblock_write(struct superblock* this) {
	int r;
	struct superblock* disk_super;
	struct dm_block* block;

	r = dm_bm_write_lock(this->bm, SUPERBLOCK_LOCATION, NULL, &block);
	if (r) {
		DMERR("dm bm write lock error\n");
		return -EAGAIN;
	}
		

	disk_super = dm_block_data(block);

	disk_super->csum = cpu_to_le32(dm_bm_checksum(&this->magic, SUPERBLOCK_ON_DISK_SIZE, SUPERBLOCK_CSUM_XOR));
	disk_super->magic = cpu_to_le64(this->magic);
	disk_super->blocks_per_seg = cpu_to_le32(this->blocks_per_seg);
	disk_super->nr_segment = cpu_to_le64(this->nr_segment);
	disk_super->common_ratio = cpu_to_le32(this->common_ratio);
	disk_super->nr_disk_level = cpu_to_le32(this->nr_disk_level);
	disk_super->max_disk_level_size = cpu_to_le64(this->max_disk_level_size);
	disk_super->index_region_start = cpu_to_le64(this->index_region_start);
	disk_super->journal_size = cpu_to_le32(this->journal_size);
	disk_super->nr_journal = cpu_to_le64(this->nr_journal);
	disk_super->cur_journal = cpu_to_le64(this->cur_journal);
	disk_super->journal_region_start = cpu_to_le64(this->journal_region_start);
	disk_super->seg_validity_table_start = cpu_to_le64(this->seg_validity_table_start);
	disk_super->data_seg_table_start = cpu_to_le64(this->data_seg_table_start);
	disk_super->reverse_index_table_start = cpu_to_le64(this->reverse_index_table_start);
	
	dm_bm_unlock(block);
	return dm_bm_flush(this->bm);
}

bool superblock_validate(struct superblock* this) {
	uint32_t csum;

	if (this->magic != SUPERBLOCK_MAGIC)
		return false;

	csum = dm_bm_checksum(&this->magic, SUPERBLOCK_ON_DISK_SIZE, SUPERBLOCK_CSUM_XOR);
	if (csum != this->csum)
		return false;

	return true;
}

void superblock_print(struct superblock* this) {
	DMINFO("superblock: ");
	DMINFO("\tmagic: %lld", this->magic);
	DMINFO("\tblocks_per_seg: %d", this->blocks_per_seg);
	DMINFO("\tnr_segment: %lld", this->nr_segment);
	DMINFO("\tcommon ratio: %d", this->common_ratio);
	DMINFO("\tnr_disk_level: %d", this->nr_disk_level);
	DMINFO("\tmax_disk_level_size: %lld", this->max_disk_level_size);
	DMINFO("\tindex_region_start: %lld", this->index_region_start);
	DMINFO("\tjournal_size: %d", this->journal_size);
	DMINFO("\tnr_journal: %lld", this->nr_journal);
	DMINFO("\tcur_journal: %lld", this->cur_journal);
	DMINFO("\tjournal_region_start: %lld", this->journal_region_start);
	DMINFO("\tseg_validity_table_start: %lld", this->seg_validity_table_start);
	DMINFO("\tdata_seg_table_start: %lld", this->data_seg_table_start);
	DMINFO("\treverse_index_table_start: %lld", this->reverse_index_table_start);
}

#include "../include/segment_allocator.h"
#define LSM_TREE_DISK_LEVEL_COMMON_RATIO 8

size_t __index_region_blocks(size_t nr_disk_level, size_t common_ratio, size_t max_disk_level_size) {
	size_t i, blocks, cur_size;

	blocks = 0;
	cur_size = max_disk_level_size;
	for (i = 0; i < nr_disk_level; ++i) {
		blocks += cur_size;
		cur_size /= common_ratio;
	}

	return blocks;
}

size_t __journal_region_blocks(size_t nr_journal, size_t journal_size) {
	size_t bytes;

	bytes = nr_journal * journal_size;
	if (!bytes)
		return 0;
	
	return (bytes - 1) / SWORNDISK_METADATA_BLOCK_SIZE + 1;
}

size_t __seg_validity_table_blocks(size_t nr_segment) {
	if (!nr_segment)
		return 0;
	return (((nr_segment - 1) / BITS_PER_LONG + 1) * sizeof(unsigned long) - 1) / SWORNDISK_METADATA_BLOCK_SIZE + 1;
}

size_t __data_seg_table_blocks(size_t nr_segment, size_t blocks_per_seg) {
	return 0;
}

int superblock_init(struct superblock* this, struct dm_block_manager* bm) {
	int r;

	this->bm = bm;

	this->read = superblock_read;
	this->write = superblock_write;
	this->validate = superblock_validate;
	this->print = superblock_print;

	r = this->read(this);
	if (r)
		return r;
	
	if (this->validate(this))
		return 0;

	this->magic = SUPERBLOCK_MAGIC;
	this->blocks_per_seg = BLOCKS_PER_SEGMENT;
	this->nr_segment = NR_SEGMENT;
	this->common_ratio = LSM_TREE_DISK_LEVEL_COMMON_RATIO;
	this->nr_disk_level = 0;
	this->max_disk_level_size = 0;
	this->index_region_start = SUPERBLOCK_LOCATION +  STRUCTURE_BLOCKS(struct superblock);
	this->journal_size = 0;
	this->nr_journal = 0;
	this->cur_journal = 0;
	this->journal_region_start = this->index_region_start + __index_region_blocks(
	  this->nr_disk_level, this->common_ratio, this->max_disk_level_size);
	this->seg_validity_table_start = this->journal_region_start + __journal_region_blocks(this->nr_journal, this->journal_size);
	this->data_seg_table_start = this->seg_validity_table_start + __seg_validity_table_blocks(this->nr_segment);
	this->reverse_index_table_start = this->data_seg_table_start + __data_seg_table_blocks(this->nr_segment, this->blocks_per_seg);

	this->write(this);
	return 0;
}

struct superblock* superblock_create(struct dm_block_manager* bm) {
	int r;
	struct superblock* this;

	this = kmalloc(sizeof(struct superblock), GFP_KERNEL);
	if (!this)
		return NULL;
	
	r = superblock_init(this, bm);
	if (r)
		return NULL;
	
	return this;
}

void superblock_destroy(struct superblock* this) {
	if (!IS_ERR_OR_NULL(this)) {
		kfree(this);
	}
}

int seg_validator_take(struct seg_validator* this, size_t seg) {
	int r;

	r = this->seg_validity_table->set(this->seg_validity_table, seg);
	if (r)
		return r;
	
	this->cur_segment += 1;
	return 0;
}

int seg_validator_next(struct seg_validator* this, size_t* next_seg) {
	int r;
	bool valid;

next:
	while(this->cur_segment < this->nr_segment) {
		r = this->seg_validity_table->get(this->seg_validity_table, this->cur_segment, &valid);
		if (!r && !valid) {
			*next_seg = this->cur_segment;
			return 0;
		}
		this->cur_segment += 1;
	}

	// since there is no segment cleaning method, a trick to provide sufficient space
	this->cur_segment = 0;
	this->seg_validity_table->format(this->seg_validity_table, false);
	goto next;

	return -ENODATA;
}

int seg_validator_init(struct seg_validator* this, struct dm_block_manager* bm, dm_block_t start, size_t nr_segment) {
	int r;

	this->nr_segment = nr_segment;
	this->cur_segment = 0;
	this->seg_validity_table = disk_bitset_create(bm, start, nr_segment);
	if (IS_ERR_OR_NULL(this->seg_validity_table))
		return -ENOMEM;

	r = this->seg_validity_table->format(this->seg_validity_table, false);
	if (r)
		return r;

	this->take = seg_validator_take;
	this->next = seg_validator_next;

	return 0;
} 

struct seg_validator* seg_validator_create(struct dm_block_manager* bm, dm_block_t start, size_t nr_segment) {
	int r;
	struct seg_validator* this;

	this = kmalloc(sizeof(struct seg_validator), GFP_KERNEL);
	if (!this)
		return NULL;
	
	r = seg_validator_init(this, bm, start, nr_segment);
	if (r)
		return NULL;

	return this;
}

// reverse index table implementation
int reverse_index_table_format(struct reverse_index_table* this) {
	return this->array->format(this->array, false);
}

int __reverse_index_table_set_entry(struct reverse_index_table* this, dm_block_t pba, struct reverse_index_entry* entry) {
	return this->array->set(this->array, pba, entry);
}

int reverse_index_table_set(struct reverse_index_table* this, dm_block_t pba, dm_block_t lba) {
	int r;
	struct reverse_index_entry entry = {
		.valid = true,
		.lba = lba
	};

	r = __reverse_index_table_set_entry(this, pba, &entry);
	if (r)
		return r;
	
	return 0;
}

struct reverse_index_entry* __reverse_index_table_get_entry(struct reverse_index_table* this, dm_block_t pba) {
	return this->array->get(this->array, pba);
}

int reverse_index_table_get(struct reverse_index_table* this, dm_block_t pba, dm_block_t* lba) {
	struct reverse_index_entry* entry;

	entry = __reverse_index_table_get_entry(this, pba);
	if (IS_ERR_OR_NULL(entry))
		return -ENODATA;
	
	if (!entry->valid)
		return -ENODATA;
	
	*lba = entry->lba;
	return 0;
}

int reverse_index_table_init(struct reverse_index_table* this, struct dm_block_manager* bm, dm_block_t start, size_t nr_block) {
	this->nr_block = nr_block;
	this->array = disk_array_create(bm, start, this->nr_block, sizeof(struct reverse_index_entry));
	if (IS_ERR_OR_NULL(this->array))
		return -ENOMEM;

	this->format = reverse_index_table_format;
	this->set = reverse_index_table_set;
	this->get = reverse_index_table_get;

	return 0;
}

struct reverse_index_table* reverse_index_table_create(struct dm_block_manager* bm, dm_block_t start, size_t nr_block) {
	int r;
	struct reverse_index_table* this;

	this = kmalloc(sizeof(struct reverse_index_table), GFP_KERNEL);
	if (!this)
		return NULL;
	
	r = reverse_index_table_init(this, bm, start, nr_block);
	if (r)
		return NULL;
	
	return this;
}

void reverse_index_table_destroy(struct reverse_index_table* this) {
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->array))
			disk_array_destroy(this->array);
		kfree(this);
	}
}

void seg_validator_destroy(struct seg_validator* this) {
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->seg_validity_table)) 
			disk_bitset_destroy(this->seg_validity_table);
		kfree(this);
	}
}

// metadata implementation
int metadata_init(struct metadata* this, struct block_device* bdev) {
	this->bdev = bdev;
	this->bm = dm_block_manager_create(this->bdev, SWORNDISK_METADATA_BLOCK_SIZE, SWORNDISK_MAX_CONCURRENT_LOCKS);
	if (IS_ERR_OR_NULL(this->bm))
		goto bad;

	this->superblock = superblock_create(this->bm);
	if (IS_ERR_OR_NULL(this->superblock))
		goto bad;
	
	this->seg_validator = seg_validator_create(this->bm, this->superblock->seg_validity_table_start, this->superblock->nr_segment);
	if (IS_ERR_OR_NULL(this->seg_validator))
		goto bad;

	this->reverse_index_table = reverse_index_table_create(this->bm, 
	  this->superblock->reverse_index_table_start, this->superblock->nr_segment * this->superblock->blocks_per_seg);
	if (IS_ERR_OR_NULL(this->reverse_index_table))
		goto bad;
	
	return 0;
bad:
	if (!IS_ERR_OR_NULL(this->bm))
		dm_block_manager_destroy(this->bm);
	superblock_destroy(this->superblock);
	seg_validator_destroy(this->seg_validator);
	reverse_index_table_destroy(this->reverse_index_table);
	return -EAGAIN;
}

struct metadata* metadata_create(struct block_device* bdev) {
	int r;
	struct metadata* this;

	this = kmalloc(sizeof(struct metadata), GFP_KERNEL);
	if (!this)
		return NULL;
	
	r = metadata_init(this, bdev);
	if (r)
		return NULL;
	
	return this;
}

void metadata_destroy(struct metadata* this) {
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->bm)) {
			dm_bm_flush(this->bm);
			dm_block_manager_destroy(this->bm);
		}
		if (!IS_ERR_OR_NULL(this->superblock))
			superblock_destroy(this->superblock);
		if (!IS_ERR_OR_NULL(this->seg_validator))
			seg_validator_destroy(this->seg_validator);
		if (!IS_ERR_OR_NULL(this->reverse_index_table))
			reverse_index_table_destroy(this->reverse_index_table);
		kfree(this);
	}
}
