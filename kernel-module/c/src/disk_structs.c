/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include "../include/disk_structs.h"
#include "../include/dm_jindisk.h"
#include "../include/metadata.h"

// disk array implememtation
dm_block_t disk_array_entry_block(struct disk_array *this, size_t index)
{
	return this->start + index / this->entries_per_block;
}

size_t disk_array_entry_offset(struct disk_array *this, size_t index)
{
	return (index % this->entries_per_block) * this->entry_size;
}

int disk_array_set(struct disk_array *this, size_t index, void *entry)
{
	struct dm_buffer *b = NULL;
	void *data = NULL;
	struct meta_aux_data *aux = NULL;
	struct skcipher *sc = this->skcipher;
	uint64_t seq;

	if (index < 0 || index >= this->nr_entry)
		return -EINVAL;

	data = dm_bufio_get(this->bc, disk_array_entry_block(this, index), &b);
	if (!IS_ERR_OR_NULL(data))
		goto copy_data;

	data = dm_bufio_read(this->bc, disk_array_entry_block(this, index), &b);
	if (IS_ERR_OR_NULL(data)) {
		DMERR("disk_array_set dm_bufio_read failed");
		return data ? PTR_ERR(data) : -EBUSY;
	}
	aux = dm_bufio_get_aux_data(b);
	aux->disk_array = this;
	seq = dm_bufio_get_block_number(b);
	sc->decrypt(sc, data, METADATA_BLOCK_SIZE, this->key, NULL, seq, data);
copy_data:
	data += disk_array_entry_offset(this, index);
	memcpy(data, entry, this->entry_size);

	dm_bufio_mark_buffer_dirty(b);

	dm_bufio_release(b);
	return 0;
}

int disk_array_get(struct disk_array *this, size_t index, void *entry)
{
	struct dm_buffer *b = NULL;
	struct meta_aux_data *aux = NULL;
	void *data = NULL;
	struct skcipher *sc = this->skcipher;
	uint64_t seq;

	if (index < 0 || index >= this->nr_entry)
		return -EINVAL;

	data = dm_bufio_get(this->bc, disk_array_entry_block(this, index), &b);
	if (!IS_ERR_OR_NULL(data))
		goto copy_data;

	data = dm_bufio_read(this->bc, disk_array_entry_block(this, index), &b);
	if (IS_ERR_OR_NULL(data)) {
		DMERR("disk_array_get dm_bufio_read failed");
		return data ? PTR_ERR(data) : -EBUSY;
	}
	aux = dm_bufio_get_aux_data(b);
	aux->disk_array = this;
	seq = dm_bufio_get_block_number(b);
	sc->decrypt(sc, data, METADATA_BLOCK_SIZE, this->key, NULL, seq, data);
copy_data:
	data += disk_array_entry_offset(this, index);
	memcpy(entry, data, this->entry_size);

	dm_bufio_release(b);
	return 0;
}

int disk_array_format(struct disk_array *this, bool value)
{
	struct dm_buffer *b = NULL;
	struct meta_aux_data *aux = NULL;
	void *data = NULL;
	size_t shift, total, cycle;

	shift = 0;
	total = __disk_array_blocks(this->nr_entry, this->entry_size,
				    METADATA_BLOCK_SIZE) *
		METADATA_BLOCK_SIZE;
	while (total > 0) {
		data = dm_bufio_new(this->bc, this->start + shift, &b);
		if (IS_ERR_OR_NULL(data)) {
			DMERR("disk_array_format dm_bufio_new pba:%llu failed",
			      this->start + shift);
			return data ? PTR_ERR(data) : -EBUSY;
		}
		aux = dm_bufio_get_aux_data(b);
		aux->disk_array = this;

		cycle = METADATA_BLOCK_SIZE;
		if (total < cycle)
			cycle = total;

		memset(data, value ? 0xff : 0, cycle);

		dm_bufio_mark_buffer_dirty(b);
		dm_bufio_release(b);

		total -= cycle;
		shift += 1;
	}
	return 0;
}

int disk_array_init(struct disk_array *this, struct dm_bufio_client *bc,
		    char *key, dm_block_t start, size_t nr_entry,
		    size_t entry_size)
{
	this->skcipher = aes_cbc_cipher_create();
	if (!this->skcipher)
		return -EAGAIN;

	this->start = start;
	this->nr_entry = nr_entry;
	this->entry_size = entry_size;
	this->entries_per_block = METADATA_BLOCK_SIZE / this->entry_size;
	this->bc = bc;
	memcpy(this->key, key, AES_CBC_KEY_SIZE);

	this->set = disk_array_set;
	this->get = disk_array_get;
	this->format = disk_array_format;
	return 0;
}

struct disk_array *disk_array_create(struct dm_bufio_client *bc, char *key,
				     dm_block_t start, size_t nr_entry,
				     size_t entry_size)
{
	int r;
	struct disk_array *this;

	this = kmalloc(sizeof(struct disk_array), GFP_KERNEL);
	if (!this)
		return NULL;

	r = disk_array_init(this, bc, key, start, nr_entry, entry_size);
	if (r)
		return NULL;

	return this;
}

void disk_array_destroy(struct disk_array *this)
{
	if (!IS_ERR_OR_NULL(this)) {
		this->skcipher->destroy(this->skcipher);
		kfree(this);
	}
}

// disk bitset implementation
size_t __disk_bitset_group(size_t index)
{
	return index / BITS_PER_LONG;
}

size_t __disk_bitset_offset(size_t index)
{
	return index % BITS_PER_LONG;
}

size_t __disk_bitset_nr_group(size_t nr_bit)
{
	return nr_bit ? (nr_bit - 1) / BITS_PER_LONG + 1 : 0;
}

int __disk_bitset_operate(struct disk_bitset *this, size_t index, bool set)
{
	int r;
	unsigned long group;

	if (index < 0 || index >= this->nr_bit)
		return -EINVAL;

	r = this->array->get(this->array, __disk_bitset_group(index), &group);
	if (r)
		return r;

	(set ? set_bit : clear_bit)(__disk_bitset_offset(index), &group);
	return this->array->set(this->array, __disk_bitset_group(index),
				&group);
}

int disk_bitset_set(struct disk_bitset *this, size_t index)
{
	return __disk_bitset_operate(this, index, true);
}

int disk_bitset_clear(struct disk_bitset *this, size_t index)
{
	return __disk_bitset_operate(this, index, false);
}

int disk_bitset_get(struct disk_bitset *this, size_t index, bool *result)
{
	int r;
	unsigned long group;

	r = this->array->get(this->array, __disk_bitset_group(index), &group);
	if (r)
		return r;

	*result = test_bit(__disk_bitset_offset(index), &group);
	return 0;
}

int disk_bitset_format(struct disk_bitset *this, bool value)
{
	return this->array->format(this->array, value);
}

int disk_bitset_init(struct disk_bitset *this, struct dm_bufio_client *bc,
		     char *key, dm_block_t start, size_t nr_bit)
{
	this->nr_bit = nr_bit;
	this->array = disk_array_create(bc, key, start,
					__disk_bitset_nr_group(nr_bit),
					sizeof(unsigned long));
	if (IS_ERR_OR_NULL(this->array))
		return -ENOMEM;

	this->set = disk_bitset_set;
	this->clear = disk_bitset_clear;
	this->get = disk_bitset_get;
	this->format = disk_bitset_format;
	return 0;
}

struct disk_bitset *disk_bitset_create(struct dm_bufio_client *bc, char *key,
				       dm_block_t start, size_t nr_bit)
{
	int r;
	struct disk_bitset *this;

	this = kmalloc(sizeof(struct disk_bitset), GFP_KERNEL);
	if (!this)
		return NULL;

	r = disk_bitset_init(this, bc, key, start, nr_bit);
	if (r)
		return NULL;

	return this;
}

void disk_bitset_destroy(struct disk_bitset *this)
{
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->array))
			disk_array_destroy(this->array);
		kfree(this);
	}
}
