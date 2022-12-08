/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include "../include/metadata.h"
#include "../include/lsm_tree.h"
#include "../include/segment_allocator.h"

#define LSM_TREE_DISK_LEVEL_COMMON_RATIO 10
#define SUPERBLOCK_LOCATION 0
#define SUPERBLOCK_MAGIC 0x22946
#define SUPERBLOCK_CSUM_XOR 0x3828

static uint32_t crc32_checksum(void *data, size_t len, uint32_t init_xor)
{
	return crc32_be(~(uint32_t)0, data, len) ^ init_xor;
}

// superblock implementation
int superblock_read(struct superblock *this)
{
	int r;
	struct superblock *disk_super;
	struct aead_cipher *cipher = jindisk->cipher;
	struct dm_buffer *b = NULL;
	void *data = NULL;

	data = dm_bufio_read(this->bc, SUPERBLOCK_LOCATION, &b);
	if (IS_ERR_OR_NULL(data)) {
		DMERR("superblock dm_bufio_read failed");
		return data ? PTR_ERR(data) : -EBUSY;
	}
	disk_super = (struct superblock *)data;

	r = cipher->decrypt(cipher, data, SUPERBLOCK_ENCRYPTED_SIZE,
			    this->root_key, this->root_iv, disk_super->root_mac,
			    0, data);
	if (r) {
		DMERR("decrypt superblock failed");
		goto out;
	}

	this->csum = le32_to_cpu(disk_super->csum);
	this->magic = le64_to_cpu(disk_super->magic);
	this->blocks_per_seg = le32_to_cpu(disk_super->blocks_per_seg);
	this->nr_segment = le64_to_cpu(disk_super->nr_segment);
	this->common_ratio = le32_to_cpu(disk_super->common_ratio);
	this->nr_disk_level = le32_to_cpu(disk_super->nr_disk_level);
	this->max_disk_level_capacity =
		le64_to_cpu(disk_super->max_disk_level_capacity);
	this->index_region_start = le64_to_cpu(disk_super->index_region_start);
	this->journal_size = le32_to_cpu(disk_super->journal_size);
	this->nr_journal = le64_to_cpu(disk_super->nr_journal);
	this->record_start = le64_to_cpu(disk_super->record_start);
	this->record_end = le64_to_cpu(disk_super->record_end);
	this->journal_region_start =
		le64_to_cpu(disk_super->journal_region_start);
	this->seg_validity_table_start =
		le64_to_cpu(disk_super->seg_validity_table_start);
	this->data_seg_table_start =
		le64_to_cpu(disk_super->data_seg_table_start);
	this->reverse_index_table_start =
		le64_to_cpu(disk_super->reverse_index_table_start);
	this->block_index_table_catalogue_start =
		le64_to_cpu(disk_super->block_index_table_catalogue_start);
	this->data_start = le64_to_cpu(disk_super->data_start);
out:
	dm_bufio_release(b);
	return r;
}

int superblock_write(struct superblock *this)
{
	int r;
	struct superblock *disk_super;
	struct aead_cipher *cipher = jindisk->cipher;
	struct dm_buffer *b = NULL;
	void *data = NULL;

	data = dm_bufio_read(this->bc, SUPERBLOCK_LOCATION, &b);
	if (IS_ERR_OR_NULL(data)) {
		DMERR("superblock dm_bufio_read failed");
		return data ? PTR_ERR(data) : -EBUSY;
	}
	disk_super = (struct superblock *)data;

	this->csum = cpu_to_le32(crc32_checksum(
		&this->magic, SUPERBLOCK_ENCRYPTED_SIZE - sizeof(uint32_t),
		SUPERBLOCK_CSUM_XOR));
	r = cipher->encrypt(cipher, (void *)this, SUPERBLOCK_ENCRYPTED_SIZE,
			    this->root_key, this->root_iv, disk_super->root_mac,
			    0, data);
	if (r) {
		DMERR("encrypt superblock failed");
		return r;
	}

	dm_bufio_mark_buffer_dirty(b);
	dm_bufio_release(b);
	return 0;
}

bool superblock_validate(struct superblock *this)
{
	uint32_t csum;

	if (this->magic != SUPERBLOCK_MAGIC)
		return false;

	csum = crc32_checksum(&this->magic,
			      SUPERBLOCK_ENCRYPTED_SIZE - sizeof(uint32_t),
			      SUPERBLOCK_CSUM_XOR);
	if (csum != this->csum)
		return false;

	return true;
}

void superblock_print(struct superblock *this)
{
	DMINFO("superblock: ");
	DMINFO("\t\tmagic: %lld", this->magic);
	DMINFO("\t\tblocks_per_seg: %d", this->blocks_per_seg);
	DMINFO("\t\tnr_segment: %lld", this->nr_segment);
	DMINFO("\t\tcommon ratio: %d", this->common_ratio);
	DMINFO("\t\tnr_disk_level: %d", this->nr_disk_level);
	DMINFO("\t\tmax_disk_level_capacity: %lld",
	       this->max_disk_level_capacity);
	DMINFO("\t\tindex_region_start: %lld", this->index_region_start);
	DMINFO("\t\tjournal_size: %d", this->journal_size);
	DMINFO("\t\tnr_journal: %lld", this->nr_journal);
	DMINFO("\t\trecord_start: %lld", this->record_start);
	DMINFO("\t\trecord_end: %lld", this->record_end);
	DMINFO("\t\tjournal_region_start: %lld", this->journal_region_start);
	DMINFO("\t\tseg_validity_table_start: %lld",
	       this->seg_validity_table_start);
	DMINFO("\t\tdata_seg_table_start: %lld", this->data_seg_table_start);
	DMINFO("\t\treverse_index_table_start: %lld",
	       this->reverse_index_table_start);
	DMINFO("\t\tblock_index_table_catalogue_start: %lld",
	       this->block_index_table_catalogue_start);
	DMINFO("\t\tdata_start: %lld", this->data_start);
}

size_t __bytes_to_block(size_t bytes, size_t block_size)
{
	if (bytes == 0)
		return 0;

	return (bytes - 1) / block_size + 1;
}

size_t __disk_array_blocks(size_t nr_elem, size_t elem_size, size_t block_size)
{
	size_t elems_per_block;

	if (elem_size == 0)
		return 0;

	elems_per_block = block_size / elem_size;
	return nr_elem / elems_per_block + 1;
}

size_t __total_bit(size_t nr_disk_level, size_t common_ratio,
		   size_t max_disk_level_capacity)
{
	size_t total = 0, capacity, i;

	capacity = max_disk_level_capacity;
	for (i = 1; i < nr_disk_level; ++i) {
		total +=
			(capacity ? (capacity - 1) / DEFAULT_LSM_FILE_CAPACITY +
					    1 :
				    0);
		capacity /= common_ratio;
	}
	return total + DEFAULT_LSM_LEVEL0_NR_FILE;
}

size_t __extra_bit(size_t max_disk_level_capacity)
{
	return __total_bit(2, LSM_TREE_DISK_LEVEL_COMMON_RATIO,
			   max_disk_level_capacity);
}

size_t __index_region_blocks(size_t nr_disk_level, size_t common_ratio,
			     size_t max_disk_level_capacity)
{
	size_t total_bit = __total_bit(nr_disk_level, common_ratio,
				       max_disk_level_capacity);
	size_t extra_bit = __extra_bit(max_disk_level_capacity);

	return __bytes_to_block(
		(total_bit + extra_bit) *
			calculate_bit_size(DEFAULT_LSM_FILE_CAPACITY,
					   DEFAULT_BIT_DEGREE),
		METADATA_BLOCK_SIZE);
}

size_t __journal_region_blocks(size_t nr_journal, size_t journal_size)
{
	return __disk_array_blocks(nr_journal, journal_size,
				   METADATA_BLOCK_SIZE);
}

size_t __seg_validity_table_blocks(size_t nr_segment)
{
	if (!nr_segment)
		return 0;
	return (((nr_segment - 1) / BITS_PER_LONG + 1) * sizeof(unsigned long) -
		1) / METADATA_BLOCK_SIZE +
	       1;
}

size_t __data_seg_table_blocks(size_t nr_segment)
{
	return __disk_array_blocks(nr_segment, sizeof(struct dst_entry),
				   METADATA_BLOCK_SIZE);
}

size_t __reverse_index_table_blocks(size_t nr_block)
{
	return __disk_array_blocks(nr_block, sizeof(struct reverse_index_entry),
				   METADATA_BLOCK_SIZE);
}

size_t __bit_catalogue_blocks(size_t nr_fd)
{
	return __disk_array_blocks(nr_fd, sizeof(struct file_stat),
				   METADATA_BLOCK_SIZE);
}

int superblock_init(struct superblock *this, struct dm_bufio_client *bc,
		    char *key, char *iv, bool format)
{
	int r;
	size_t nr_bits;

	// init root key, iv
	memcpy(this->root_key, key, AES_GCM_KEY_SIZE);
	memcpy(this->root_iv, iv, AES_GCM_IV_SIZE);

	this->bc = bc;
	this->read = superblock_read;
	this->write = superblock_write;
	this->validate = superblock_validate;
	this->print = superblock_print;

	if (format) {
		DMINFO("formatting jindisk superblock...");
		this->magic = SUPERBLOCK_MAGIC;
		this->blocks_per_seg = BLOCKS_PER_SEGMENT;
		this->nr_segment = NR_SEGMENT + NR_GC_PRESERVED;
		this->common_ratio = LSM_TREE_DISK_LEVEL_COMMON_RATIO;
		this->nr_disk_level = DEFAULT_LSM_TREE_NR_DISK_LEVEL;
		this->max_disk_level_capacity =
			(this->nr_segment) * BLOCKS_PER_SEGMENT;
		this->index_region_start = SUPERBLOCK_LOCATION +
					   STRUCTURE_BLOCKS(struct superblock);
		this->journal_size = sizeof(struct journal_record);
		this->nr_journal = MAX_RECORDS;
		this->record_start = 0;
		this->record_end = 0;
		this->journal_region_start =
			this->index_region_start +
			__index_region_blocks(this->nr_disk_level,
					      this->common_ratio,
					      this->max_disk_level_capacity);
		this->seg_validity_table_start =
			this->journal_region_start +
			NR_JOURNAL_SEGMENT * BLOCKS_PER_SEGMENT;
		this->data_seg_table_start =
			this->seg_validity_table_start +
			__seg_validity_table_blocks(this->nr_segment) *
				NR_CHECKPOINT_PACKS;
		this->reverse_index_table_start =
			this->data_seg_table_start +
			__data_seg_table_blocks(this->nr_segment) *
				NR_CHECKPOINT_PACKS;
		this->block_index_table_catalogue_start =
			this->reverse_index_table_start +
			__reverse_index_table_blocks(this->nr_segment *
						     this->blocks_per_seg) *
				NR_CHECKPOINT_PACKS;

		nr_bits = __total_bit(this->nr_disk_level, this->common_ratio,
				      this->max_disk_level_capacity) +
			  __extra_bit(this->max_disk_level_capacity);
		this->data_start = this->block_index_table_catalogue_start +
				   (__seg_validity_table_blocks(nr_bits) +
				    __bit_catalogue_blocks(nr_bits)) *
					   NR_CHECKPOINT_PACKS;
		return this->write(this);
	}
	DMINFO("reloading jindisk superblock...");
	r = this->read(this);
	if (r)
		return r;

	if (this->validate(this))
		return 0;

	return -EACCES;
}

struct superblock *superblock_create(struct dm_bufio_client *bc, char *key,
				     char *iv, bool format)
{
	int r;
	struct superblock *this;

	this = kmalloc(sizeof(struct superblock), GFP_KERNEL);
	if (!this)
		return NULL;

	r = superblock_init(this, bc, key, iv, format);
	if (r)
		return NULL;

	this->print(this);
	return this;
}

void superblock_destroy(struct superblock *this)
{
	if (!IS_ERR_OR_NULL(this))
		kfree(this);
}

int seg_validator_take(struct seg_validator *this, size_t seg)
{
	int r = 0;

	down_write(&this->svt_lock);
	r = this->seg_validity_table->set(this->seg_validity_table, seg);
	if (r)
		goto out;

	this->cur_segment += 1;
out:
	up_write(&this->svt_lock);
	return r;
}

int seg_validator_next(struct seg_validator *this, size_t *next_seg)
{
	int r;
	bool valid;
	size_t try_times = 0;

	down_read(&this->svt_lock);
next_try:
	while (this->cur_segment < this->nr_segment) {
		r = this->seg_validity_table->get(this->seg_validity_table,
						  this->cur_segment, &valid);
		if (!r && !valid) {
			*next_seg = this->cur_segment;
			goto out;
		}
		this->cur_segment += 1;
	}

	if (try_times < 1) {
		try_times += 1;
		this->cur_segment = 0;
		goto next_try;
	}
	r = -ENODATA;
out:
	up_read(&this->svt_lock);
	return r;
}

int seg_validator_test_and_return(struct seg_validator *this, size_t seg,
				  bool *old)
{
	int r;
	bool valid;

	down_write(&this->svt_lock);
	r = this->seg_validity_table->get(this->seg_validity_table, seg,
					  &valid);
	if (r)
		goto out;

	r = this->seg_validity_table->clear(this->seg_validity_table, seg);
	if (r)
		goto out;

	*old = valid;
out:
	up_write(&this->svt_lock);
	return r;
}

int seg_validator_format(struct seg_validator *this)
{
	int r;

	r = this->seg_validity_table->format(this->seg_validity_table, false);
	if (r)
		return r;

	this->cur_segment = 0;
	return 0;
}

int seg_validator_valid_segment_count(struct seg_validator *this, size_t *count)
{
	int r;
	bool valid;
	size_t segno;

	*count = 0;
	for (segno = 0; segno < this->nr_segment; ++segno) {
		r = this->seg_validity_table->get(this->seg_validity_table,
						  segno, &valid);
		if (r)
			return r;
		*count += valid;
	}
	return 0;
}

int seg_validator_init(struct seg_validator *this, struct dm_bufio_client *bc,
		       dm_block_t start, size_t nr_segment, int valid_field)
{
	this->nr_segment = nr_segment;
	this->blk_count = __seg_validity_table_blocks(nr_segment);
	this->cur_segment = 0;
	init_rwsem(&this->svt_lock);
	this->seg_validity_table = disk_bitset_create(
		bc, start + valid_field * this->blk_count, nr_segment);
	if (IS_ERR_OR_NULL(this->seg_validity_table))
		return -ENOMEM;

	this->take = seg_validator_take;
	this->next = seg_validator_next;
	this->format = seg_validator_format;
	this->valid_segment_count = seg_validator_valid_segment_count;
	this->test_and_return = seg_validator_test_and_return;
	return 0;
}

struct seg_validator *seg_validator_create(struct dm_bufio_client *bc,
					   dm_block_t start, size_t nr_segment,
					   int valid_field)
{
	int r;
	struct seg_validator *this;

	this = kmalloc(sizeof(struct seg_validator), GFP_KERNEL);
	if (!this)
		return NULL;

	r = seg_validator_init(this, bc, start, nr_segment, valid_field);
	if (r)
		return NULL;

	return this;
}

// reverse index table implementation
int reverse_index_table_format(struct reverse_index_table *this)
{
	return this->array->format(this->array, false);
}

int reverse_index_table_reset(struct reverse_index_table *this, dm_block_t pba,
			      dm_block_t old_lba, dm_block_t *new_lba)
{
	int r = 0;
	struct reverse_index_entry entry;

	down_write(&this->rit_lock);
	r = this->array->get(this->array, pba, &entry);
	if (r) {
		DMERR("reverse_index_table_reset get pba:%llu failed", pba);
		goto out;
	}
	*new_lba = entry.lba;

	DMDEBUG("reverse_index_table_reset pba:%llu lba:%llu", pba, entry.lba);
	if (old_lba != INF_ADDR && old_lba != entry.lba)
		goto out;

	entry.lba = INF_ADDR;
	r = this->array->set(this->array, pba, &entry);
	if (r)
		DMERR("reverse_index_table_reset set pba:%llu failed", pba);
out:
	up_write(&this->rit_lock);
	return r;
}

int reverse_index_table_set(struct reverse_index_table *this, dm_block_t pba,
			    dm_block_t lba)
{
	int r = 0;
	struct reverse_index_entry entry = {
		.lba = lba,
	};

	DMDEBUG("reverse_index_table_set pba:%llu lba:%llu", pba, lba);
	down_write(&this->rit_lock);
	r = this->array->set(this->array, pba, &entry);
	up_write(&this->rit_lock);
	return r;
}

int reverse_index_table_get(struct reverse_index_table *this, dm_block_t pba,
			    dm_block_t *lba)
{
	int r = 0;
	struct reverse_index_entry entry;

	down_read(&this->rit_lock);
	r = this->array->get(this->array, pba, &entry);
	if (r)
		goto out;

	DMDEBUG("reverse_index_table_get pba:%llu lba:%llu", pba, entry.lba);
	*lba = entry.lba;
out:
	up_read(&this->rit_lock);
	return r;
}

int reverse_index_table_init(struct reverse_index_table *this,
			     struct dm_bufio_client *bc, dm_block_t start,
			     size_t nr_block, int valid_field)
{
	init_rwsem(&this->rit_lock);
	this->nr_block = nr_block;
	this->blk_count = __reverse_index_table_blocks(nr_block);
	this->array =
		disk_array_create(bc, start + valid_field * this->blk_count,
				  nr_block, sizeof(struct reverse_index_entry));
	if (!this->array)
		return -ENOMEM;

	this->format = reverse_index_table_format;
	this->set = reverse_index_table_set;
	this->get = reverse_index_table_get;
	this->reset = reverse_index_table_reset;
	return 0;
}

struct reverse_index_table *
reverse_index_table_create(struct dm_bufio_client *bc, dm_block_t start,
			   size_t nr_block, int valid_field)
{
	int r;
	struct reverse_index_table *this;

	this = kmalloc(sizeof(struct reverse_index_table), GFP_KERNEL);
	if (!this)
		return NULL;

	r = reverse_index_table_init(this, bc, start, nr_block, valid_field);
	if (r)
		return NULL;

	return this;
}

void reverse_index_table_destroy(struct reverse_index_table *this)
{
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->array))
			disk_array_destroy(this->array);
		kfree(this);
	}
}

void seg_validator_destroy(struct seg_validator *this)
{
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->seg_validity_table))
			disk_bitset_destroy(this->seg_validity_table);
		kfree(this);
	}
}

// data segment table implementaion
struct victim *victim_create(size_t segno, size_t nr_valid_block,
			     unsigned long *block_validity_table)
{
	struct victim *victim;

	victim = kmalloc(sizeof(struct victim), GFP_KERNEL);
	if (!victim)
		return NULL;

	victim->segno = segno;
	victim->nr_valid_block = nr_valid_block;
	bitmap_copy(victim->block_validity_table, block_validity_table,
		    BLOCKS_PER_SEGMENT);
	return victim;
}

void victim_destroy(struct victim *victim)
{
	if (!IS_ERR_OR_NULL(victim))
		kfree(victim);
}

bool victim_less(struct rb_node *node1, const struct rb_node *node2)
{
	struct victim *victim1, *victim2;

	victim1 = container_of(node1, struct victim, node);
	victim2 = container_of(node2, struct victim, node);
	return victim1->nr_valid_block < victim2->nr_valid_block;
}

void dst_destroy_victim(struct dst *this, size_t segno)
{
	victim_destroy(this->remove_victim(this, segno));
}

int dst_add_victim(struct dst *this, size_t segno, size_t nr_valid,
		   unsigned long *block_validity_table)
{
	struct victim *victim = NULL;

	if (nr_valid >= BLOCKS_PER_SEGMENT) {
		DMDEBUG("dst_add_victim invalid value nr_valid: %lu", nr_valid);
		return -EINVAL;
	}

	victim = victim_create(segno, nr_valid, block_validity_table);
	if (!victim) {
		DMERR("dst_add_victim victim_create failed segno:%lu", segno);
		return -ENOMEM;
	}
	DMDEBUG("dst_add_victim segno:%lu nu_valid:%lu", segno, nr_valid);
	rb_add(&victim->node, &this->victims, victim_less);
	this->node_list[segno] = &victim->node;
	return 0;
}

int dst_load(struct dst *this)
{
	int err = 0;
	size_t segno;
	struct dst_entry entry;

	for (segno = 0; segno < this->nr_segment; ++segno) {
		err = this->array->get(this->array, segno, &entry);
		if (err)
			return -ENODATA;
		if (entry.nr_valid_block) {
			dst_add_victim(this, segno, entry.nr_valid_block,
				       entry.block_validity_table);
		}
	}
	return 0;
}

inline size_t __block_to_segment(dm_block_t pba)
{
	return pba / BLOCKS_PER_SEGMENT;
}

inline size_t __block_offset_whthin_segment(dm_block_t pba)
{
	return pba % BLOCKS_PER_SEGMENT;
}

int dst_update_victim(struct dst *this, size_t segno, size_t nr_valid,
		      unsigned long *block_validity_table)
{
	dst_destroy_victim(this, segno);
	if (nr_valid >= BLOCKS_PER_SEGMENT)
		return 0;
	return dst_add_victim(this, segno, nr_valid, block_validity_table);
}

int dst_take_segment(struct dst *this, size_t segno)
{
	int err = 0;
	struct dst_entry entry;

	down_write(&this->dst_lock);
	err = this->array->get(this->array, segno, &entry);
	if (err) {
		DMERR("dst_take_segment get segno:%lu err:%d", segno, err);
		goto out;
	}
	if (entry.nr_valid_block) {
		DMERR("dst_take_segment failed segno:%lu nr_valid_block:%lu",
		      segno, entry.nr_valid_block);
		err = -EINVAL;
		goto out;
	}
	entry.nr_valid_block = BLOCKS_PER_SEGMENT;
	bitmap_fill(entry.block_validity_table, BLOCKS_PER_SEGMENT);

	err = this->array->set(this->array, segno, &entry);
	if (err) {
		DMERR("dst_take_segment set segno:%lu err:%d", segno, err);
		goto out;
	}
	dst_destroy_victim(this, segno);
	DMDEBUG("dst_take_segment segno:%lu", segno);
out:
	up_write(&this->dst_lock);
	return err;
}

int dst_return_segment(struct dst *this, size_t segno)
{
	int err = 0;
	struct dst_entry entry = { 0 };

	down_write(&this->dst_lock);
	err = this->array->set(this->array, segno, &entry);
	if (err)
		DMERR("dst_return_segment set segno:%lu err:%d", segno, err);
	dst_destroy_victim(this, segno);
	up_write(&this->dst_lock);
	DMDEBUG("dst_return_segment segno:%lu", segno);
	return err;
}

int dst_take_block(struct dst *this, dm_block_t pba)
{
	int err = 0;
	struct dst_entry entry;
	size_t segno, offset;

	segno = __block_to_segment(pba);
	offset = __block_offset_whthin_segment(pba);

	down_write(&this->dst_lock);
	err = this->array->get(this->array, segno, &entry);
	if (err)
		goto out;

	if (entry.nr_valid_block >= BLOCKS_PER_SEGMENT) {
		err = -EINVAL;
		goto out;
	}

	entry.nr_valid_block += 1;
	bitmap_set(entry.block_validity_table, offset, 1);

	err = this->array->set(this->array, segno, &entry);
	if (err)
		goto out;

	err = dst_update_victim(this, segno, entry.nr_valid_block,
				entry.block_validity_table);
out:
	up_write(&this->dst_lock);
	return err;
}

int dst_return_block(struct dst *this, dm_block_t pba)
{
	int err = 0;
	struct dst_entry entry;
	size_t segno, offset;

	segno = __block_to_segment(pba);
	offset = __block_offset_whthin_segment(pba);

	down_write(&this->dst_lock);
	err = this->array->get(this->array, segno, &entry);
	if (err || !entry.nr_valid_block) {
		DMERR("dst_return_block failed pba:%llu nr_valid:%lu err:%d",
		      pba, entry.nr_valid_block, err);
		goto out;
	}

	if (test_and_clear_bit(offset, entry.block_validity_table)) {
		entry.nr_valid_block -= 1;
	} else {
		DMERR("dst_return_block has been cleared pba:%llu", pba);
	}

	err = this->array->set(this->array, segno, &entry);
	if (err) {
		DMERR("dst_return_block set failed pba:%llu err:%d", pba, err);
		goto out;
	}
	err = dst_update_victim(this, segno, entry.nr_valid_block,
				entry.block_validity_table);
out:
	up_write(&this->dst_lock);
	DMDEBUG("dst_return_block pba:%llu err:%d", pba, err);
	return err;
}

int dst_find_logging_block(struct dst *this, dm_block_t *pba)
{
	int err = 0, offset;
	size_t nr_valid_segment;
	struct victim *victim;
	struct dst_entry entry;
	struct segment_allocator *sa = jindisk->seg_allocator;
	struct seg_validator *svt = jindisk->meta->seg_validator;

	down_write(&this->dst_lock);
retry:
	if (this->logging_segno == INF_ADDR) {
		if (RB_EMPTY_ROOT(&this->victims)) {
			DMDEBUG("no logging block, try to alloc a full segment");
			err = svt->next(svt, &this->logging_segno);
			if (err) {
				DMERR("find_logging_block svt->next failed");
				goto out;
			}
			err = svt->take(svt, this->logging_segno);
			if (err) {
				DMERR("find_logging_block svt->take failed");
				goto out;
			}
			nr_valid_segment = sa->nr_valid_segment_get(sa);
			nr_valid_segment += 1;
			sa->nr_valid_segment_set(sa, nr_valid_segment);
			goto retry;
		}
		victim = rb_entry(rb_last(&this->victims), struct victim, node);
		this->logging_segno = victim->segno;
		dst_destroy_victim(this, this->logging_segno);
		DMDEBUG("logging segment:%lu", this->logging_segno);
	}

	err = this->array->get(this->array, this->logging_segno, &entry);
	if (err) {
		DMERR("logging_segment:%lu get dst_entry failed",
		      this->logging_segno);
		goto out;
	}
	if (entry.nr_valid_block >= BLOCKS_PER_SEGMENT) {
		DMDEBUG("logging_segment:%lu is full, try another",
			this->logging_segno);
		dst_destroy_victim(this, this->logging_segno);
		this->logging_segno = INF_ADDR;
		goto retry;
	}

	offset = find_first_zero_bit(entry.block_validity_table,
				     BLOCKS_PER_SEGMENT);
	if (offset == BLOCKS_PER_SEGMENT) {
		DMERR("logging_segment:%lu find zero_bit failed",
		      this->logging_segno);
		dst_destroy_victim(this, this->logging_segno);
		this->logging_segno = INF_ADDR;
		goto retry;
	}
	entry.nr_valid_block += 1;
	bitmap_set(entry.block_validity_table, offset, 1);

	err = this->array->set(this->array, this->logging_segno, &entry);
	if (err) {
		DMERR("logging_segment:%lu set dst_entry failed",
		      this->logging_segno);
		goto out;
	}
	*pba = this->logging_segno * BLOCKS_PER_SEGMENT + offset;
out:
	up_write(&this->dst_lock);
	return err;
}

bool dst_victim_empty(struct dst *this)
{
	return RB_EMPTY_ROOT(&this->victims);
}

struct victim *dst_peek_victim(struct dst *this)
{
	struct rb_node *node;

	down_read(&this->dst_lock);
	node = rb_first(&this->victims);
	up_read(&this->dst_lock);
	if (!node)
		return NULL;

	return rb_entry(node, struct victim, node);
}

struct victim *dst_remove_victim(struct dst *this, size_t segno)
{
	if (this->node_list[segno]) {
		struct victim *victim =
			rb_entry(this->node_list[segno], struct victim, node);
		if (!victim)
			return NULL;
		rb_erase(&victim->node, &this->victims);
		this->node_list[segno] = NULL;
		return victim;
	}
	return NULL;
}

struct victim *dst_pop_victim(struct dst *this)
{
	struct rb_node *node = NULL;
	struct victim *victim = NULL;

	down_write(&this->dst_lock);
	node = rb_first(&this->victims);
	if (!node)
		goto out;
	victim = rb_entry(node, struct victim, node);
	dst_remove_victim(this, victim->segno);
out:
	up_write(&this->dst_lock);
	return victim;
}

int dst_init(struct dst *this, struct dm_bufio_client *bc, dm_block_t start,
	     size_t nr_segment, int valid_field);

int dst_format(struct dst *this)
{
	int r;

	r = this->array->format(this->array, false);
	if (r)
		return r;

	while (!RB_EMPTY_ROOT(&this->victims)) {
		victim_destroy(this->pop_victim(this));
	}

	kfree(this->node_list);

	r = dst_init(this, this->bc, this->start, this->nr_segment,
		     this->valid_field);
	return r;
}

int dst_init(struct dst *this, struct dm_bufio_client *bc, dm_block_t start,
	     size_t nr_segment, int valid_field)
{
	int r;

	this->load = dst_load;
	this->take_segment = dst_take_segment;
	this->return_segment = dst_return_segment;
	this->take_block = dst_take_block;
	this->return_block = dst_return_block;
	this->find_logging_block = dst_find_logging_block;
	this->victim_empty = dst_victim_empty;
	this->peek_victim = dst_peek_victim;
	this->pop_victim = dst_pop_victim;
	this->remove_victim = dst_remove_victim;
	this->format = dst_format;

	init_rwsem(&this->dst_lock);
	this->bc = bc;
	this->start = start;
	this->nr_segment = nr_segment;
	this->logging_segno = INF_ADDR;
	this->blk_count = __data_seg_table_blocks(nr_segment);
	this->valid_field = valid_field;
	this->array =
		disk_array_create(bc, start + valid_field * this->blk_count,
				  nr_segment, sizeof(struct dst_entry));
	if (!this->array)
		return -ENOMEM;

	this->node_list = kzalloc(this->nr_segment * sizeof(struct rb_node *),
				  GFP_KERNEL);
	if (!this->node_list)
		return -ENOMEM;

	this->victims = RB_ROOT;
	r = this->load(this);
	return r;
}

struct dst *dst_create(struct dm_bufio_client *bc, dm_block_t start,
		       size_t nr_segment, int valid_field)
{
	int r;
	struct dst *this;

	this = kmalloc(sizeof(struct dst), GFP_KERNEL);
	if (!this)
		return NULL;

	r = dst_init(this, bc, start, nr_segment, valid_field);
	if (r)
		return NULL;

	return this;
}

void dst_destroy(struct dst *this)
{
	if (!IS_ERR_OR_NULL(this)) {
		while (!RB_EMPTY_ROOT(&this->victims))
			victim_destroy(this->pop_victim(this));
		if (!IS_ERR_OR_NULL(this->node_list))
			kfree(this->node_list);
		kfree(this);
	}
}

// block index table catalogue implementation
int bitc_alloc_file(struct lsm_catalogue *lsm_catalogue, size_t *fd)
{
	int err = 0;
	struct bit_catalogue *this = container_of(
		lsm_catalogue, struct bit_catalogue, lsm_catalogue);
	err = this->bit_validity_table->next(this->bit_validity_table, fd);
	if (err) {
		DMERR("bitc_alloc_file next failed err:%d", err);
		return err;
	}

	err = this->bit_validity_table->take(this->bit_validity_table, *fd);
	if (err) {
		DMERR("bitc_alloc_file take failed err:%d", err);
		return err;
	}
	return 0;
}

int bitc_release_file(struct lsm_catalogue *lsm_catalogue, size_t fd)
{
	int err;
	bool old;
	struct bit_catalogue *this = container_of(
		lsm_catalogue, struct bit_catalogue, lsm_catalogue);
	err = this->bit_validity_table->test_and_return(
		this->bit_validity_table, fd, &old);
	if (err) {
		DMERR("bitc_release_file test_and_return failed err:%d", err);
		return err;
	}
	return 0;
}

void file_stat_print(struct file_stat stat)
{
	DMINFO("file_stat id:%lu level:%lu version:%lu root:%llu "
	       "first_key:%u last_key:%u nr_record:%u",
	       stat.id, stat.level, stat.version, stat.root, stat.first_key,
	       stat.last_key, stat.nr_record);
}

int bitc_set_file_stats(struct lsm_catalogue *lsm_catalogue, size_t fd,
			struct file_stat stats)
{
	struct bit_catalogue *this = container_of(
		lsm_catalogue, struct bit_catalogue, lsm_catalogue);
	return this->file_stats->set(this->file_stats, fd, &stats);
}

int bitc_get_file_stats(struct lsm_catalogue *lsm_catalogue, size_t fd,
			void *stats)
{
	int err = 0;
	struct file_stat info;
	struct bit_catalogue *this = container_of(
		lsm_catalogue, struct bit_catalogue, lsm_catalogue);
	err = this->file_stats->get(this->file_stats, fd, &info);
	if (!err) {
		*(struct file_stat *)stats = info;
		return 0;
	}
	return -ENODATA;
}

int bitc_get_all_file_stats(struct lsm_catalogue *lsm_catalogue,
			    struct list_head *stats)
{
	int err = 0;
	bool valid;
	size_t i;
	struct file_stat *stat;
	struct bit_catalogue *this = container_of(
		lsm_catalogue, struct bit_catalogue, lsm_catalogue);
	INIT_LIST_HEAD(stats);
	for (i = 0; i < this->bit_validity_table->nr_segment; ++i) {
		err = this->bit_validity_table->seg_validity_table->get(
			this->bit_validity_table->seg_validity_table, i,
			&valid);
		if (err)
			return err;

		if (valid) {
			stat = kzalloc(sizeof(struct file_stat), GFP_KERNEL);
			if (!stat)
				return -ENOMEM;
			err = this->file_stats->get(this->file_stats, i, stat);
			if (!err) {
				list_add_tail(&stat->node, stats);
			}
		}
	}
	return 0;
}

size_t bitc_get_next_version(struct lsm_catalogue *lsm_catalogue)
{
	struct bit_catalogue *this = container_of(
		lsm_catalogue, struct bit_catalogue, lsm_catalogue);
	return this->max_version++;
}

int bit_catalogue_format(struct bit_catalogue *this)
{
	int err = 0;

	err = this->bit_validity_table->format(this->bit_validity_table);
	if (err) {
		DMERR("bit_catalogue_format bvt failed err:%d", err);
		return err;
	}

	err = this->file_stats->format(this->file_stats, false);
	if (err) {
		DMERR("bit_catalogue_format stat failed err:%d", err);
		return err;
	}
	return 0;
}

size_t bitc_get_current_version(struct bit_catalogue *this)
{
	size_t max_version = 0;
	struct file_stat *info;
	struct list_head file_stats;

	bitc_get_all_file_stats(&this->lsm_catalogue, &file_stats);
	list_for_each_entry (info, &file_stats, node) {
		if (max_version < info->version)
			max_version = info->version + 1;
	}
	return max_version;
}

int bit_catalogue_init(struct bit_catalogue *this, struct dm_bufio_client *bc,
		       struct superblock *superblock, int valid_svt,
		       int valid_bitc)
{
	int err = 0;
	size_t max_fd;
	dm_block_t file_stats_start;

	this->bc = bc;
	this->start = superblock->block_index_table_catalogue_start;
	this->index_region_start = superblock->index_region_start;
	this->nr_bit =
		__total_bit(superblock->nr_disk_level, superblock->common_ratio,
			    superblock->max_disk_level_capacity);

	max_fd =
		this->nr_bit + __extra_bit(superblock->max_disk_level_capacity);
	this->bit_validity_table =
		seg_validator_create(bc, this->start, max_fd, valid_svt);
	if (!this->bit_validity_table) {
		err = -ENOMEM;
		goto bad;
	}

	file_stats_start = this->start + this->bit_validity_table->blk_count *
						 NR_CHECKPOINT_PACKS;
	this->blk_count = __bit_catalogue_blocks(max_fd);
	this->file_stats = disk_array_create(
		bc, file_stats_start + valid_bitc * this->blk_count, max_fd,
		sizeof(struct file_stat));
	if (!this->file_stats) {
		err = -ENOMEM;
		goto bad;
	}

	this->max_version = bitc_get_current_version(this);
	this->lsm_catalogue.get_next_version = bitc_get_next_version;
	this->format = bit_catalogue_format;
	this->lsm_catalogue.file_size = calculate_bit_size(
		DEFAULT_LSM_FILE_CAPACITY, DEFAULT_BIT_DEGREE);
	this->lsm_catalogue.total_file = this->nr_bit;
	this->lsm_catalogue.start =
		this->index_region_start * METADATA_BLOCK_SIZE;
	this->lsm_catalogue.nr_disk_level = superblock->nr_disk_level;
	this->lsm_catalogue.common_ratio = superblock->common_ratio;
	this->lsm_catalogue.max_level_nr_file =
		__total_bit(2, superblock->common_ratio,
			    superblock->max_disk_level_capacity);
	this->lsm_catalogue.alloc_file = bitc_alloc_file;
	this->lsm_catalogue.release_file = bitc_release_file;
	this->lsm_catalogue.set_file_stats = bitc_set_file_stats;
	this->lsm_catalogue.get_file_stats = bitc_get_file_stats;
	this->lsm_catalogue.get_all_file_stats = bitc_get_all_file_stats;
	return 0;
bad:
	if (this->bit_validity_table)
		seg_validator_destroy(this->bit_validity_table);
	if (this->file_stats)
		disk_array_destroy(this->file_stats);
	return err;
}

struct bit_catalogue *bit_catalogue_create(struct dm_bufio_client *bc,
					   struct superblock *superblock,
					   int valid_svt, int valid_bitc)
{
	int err = 0;
	struct bit_catalogue *this;

	this = kzalloc(sizeof(struct bit_catalogue), GFP_KERNEL);
	if (!this)
		goto bad;

	err = bit_catalogue_init(this, bc, superblock, valid_svt, valid_bitc);
	if (err)
		goto bad;

	return this;
bad:
	if (this)
		kfree(this);
	return NULL;
}

void bit_catalogue_destroy(struct bit_catalogue *this)
{
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->bit_validity_table))
			seg_validator_destroy(this->bit_validity_table);
		if (!IS_ERR_OR_NULL(this->file_stats))
			disk_array_destroy(this->file_stats);
		kfree(this);
	}
}

// metadata implementation
int metadata_format(struct metadata *this)
{
	int r;

	r = this->seg_validator->format(this->seg_validator);
	if (r)
		return r;

	r = this->rit->format(this->rit);
	if (r)
		return r;

	r = this->dst->format(this->dst);
	if (r)
		return r;

	r = this->bit_catalogue->format(this->bit_catalogue);
	if (r)
		return r;

	return 0;
}

uint64_t calc_metadata_blocks(uint64_t nr_segment)
{
	size_t nr_bits;

	nr_bits = __total_bit(DEFAULT_LSM_TREE_NR_DISK_LEVEL,
			      LSM_TREE_DISK_LEVEL_COMMON_RATIO,
			      nr_segment * BLOCKS_PER_SEGMENT) +
		  __extra_bit(nr_segment * BLOCKS_PER_SEGMENT);

	return STRUCTURE_BLOCKS(struct superblock) +
	       __index_region_blocks(DEFAULT_LSM_TREE_NR_DISK_LEVEL,
				     LSM_TREE_DISK_LEVEL_COMMON_RATIO,
				     nr_segment * BLOCKS_PER_SEGMENT) +
	       NR_JOURNAL_SEGMENT * BLOCKS_PER_SEGMENT +
	       __seg_validity_table_blocks(nr_segment) * NR_CHECKPOINT_PACKS +
	       __data_seg_table_blocks(nr_segment) * NR_CHECKPOINT_PACKS +
	       __reverse_index_table_blocks(nr_segment * BLOCKS_PER_SEGMENT) *
		       NR_CHECKPOINT_PACKS +
	       __seg_validity_table_blocks(nr_bits) * NR_CHECKPOINT_PACKS +
	       __bit_catalogue_blocks(nr_bits) * NR_CHECKPOINT_PACKS;
}

void metadata_destroy(struct metadata *this)
{
	if (!IS_ERR_OR_NULL(this)) {
		journal_region_destroy(this->journal);
		if (!IS_ERR_OR_NULL(this->bc)) {
			dm_bufio_client_destroy(this->bc);
		}
		superblock_destroy(this->superblock);
		seg_validator_destroy(this->seg_validator);
		reverse_index_table_destroy(this->rit);
		dst_destroy(this->dst);
		bit_catalogue_destroy(this->bit_catalogue);
		kfree(this);
	}
}

void meta_alloc_cb(struct dm_buffer *db)
{
}

void meta_write_cb(struct dm_buffer *db)
{
}

int metadata_init(struct metadata *this, char *key, char *iv,
		  unsigned long action_flag, struct block_device *bdev)
{
	int r, valid_field0, valid_field1;
	bool should_format = false;

	if (action_flag == 1)
		should_format = true;

	this->bdev = bdev;
	this->bc = dm_bufio_client_create(this->bdev, METADATA_BLOCK_SIZE,
					  MAX_CONCURRENT_LOCKS, META_AUX_SIZE,
					  meta_alloc_cb, meta_write_cb);
	if (IS_ERR_OR_NULL(this->bc))
		goto bad;

	this->superblock = superblock_create(this->bc, key, iv, should_format);
	if (IS_ERR_OR_NULL(this->superblock))
		goto bad;

	this->journal = journal_region_create(this->superblock);
	if (IS_ERR_OR_NULL(this->journal))
		goto bad;

	valid_field0 = test_bit(DATA_SVT, this->journal->valid_fields) ? 1 : 0;
	this->seg_validator = seg_validator_create(
		this->bc, this->superblock->seg_validity_table_start,
		this->superblock->nr_segment, valid_field0);
	if (IS_ERR_OR_NULL(this->seg_validator))
		goto bad;

	valid_field0 = test_bit(DATA_RIT, this->journal->valid_fields) ? 1 : 0;
	this->rit = reverse_index_table_create(
		this->bc, this->superblock->reverse_index_table_start,
		this->superblock->nr_segment * this->superblock->blocks_per_seg,
		valid_field0);
	if (IS_ERR_OR_NULL(this->rit))
		goto bad;

	valid_field0 = test_bit(DATA_DST, this->journal->valid_fields) ? 1 : 0;
	this->dst = dst_create(this->bc, this->superblock->data_seg_table_start,
			       this->superblock->nr_segment, valid_field0);
	if (IS_ERR_OR_NULL(this->dst))
		goto bad;

	valid_field0 = test_bit(INDEX_SVT, this->journal->valid_fields) ? 1 : 0;
	valid_field1 =
		test_bit(INDEX_BITC, this->journal->valid_fields) ? 1 : 0;
	this->bit_catalogue = bit_catalogue_create(this->bc, this->superblock,
						   valid_field0, valid_field1);
	if (IS_ERR_OR_NULL(this->bit_catalogue))
		goto bad;

	this->format = metadata_format;
	this->destroy = metadata_destroy;
	if (should_format) {
		r = this->format(this);
		if (r)
			goto bad;
	}
	return 0;
bad:
	metadata_destroy(this);
	return -EAGAIN;
}

struct metadata *metadata_create(char *key, char *iv, unsigned long action_flag,
				 struct block_device *bdev)
{
	int r;
	struct metadata *this;

	this = kzalloc(sizeof(struct metadata), GFP_KERNEL);
	if (!this)
		return NULL;

	r = metadata_init(this, key, iv, action_flag, bdev);
	if (r)
		return NULL;

	return this;
}
