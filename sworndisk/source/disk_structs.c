#include "../include/dm_sworndisk.h"
#include "../include/disk_structs.h"
#include "../include/metadata.h"

// disk array implememtation
dm_block_t disk_array_entry_block(struct disk_array* this, size_t index) {
	return this->start + index / this->entries_per_block;
}

size_t disk_array_entry_offset(struct disk_array* this, size_t index) {
	return (index % this->entries_per_block) * this->entry_size;
}

int disk_array_set(struct disk_array* this, size_t index, void* entry) {
	int r;
	struct dm_block* block;
	if (index < 0 || index >= this->nr_entry)
		return -EINVAL;

	r = dm_bm_write_lock(this->bm, disk_array_entry_block(this, index), NULL, &block);
	if (r)
		return r;
		
	memcpy(dm_block_data(block) + disk_array_entry_offset(this, index), entry, this->entry_size);
	
	dm_bm_unlock(block);
	return 0;
}

void* disk_array_get(struct disk_array* this, size_t index) {
	int r;
	void* entry;
	struct dm_block* block;

	entry = kmalloc(this->entry_size, GFP_KERNEL);
	if (!entry) 
		return NULL;
	
	r = dm_bm_read_lock(this->bm, disk_array_entry_block(this, index), NULL, &block);
	if (r)
		return NULL;

	memcpy(entry, dm_block_data(block) + disk_array_entry_offset(this, index), this->entry_size);
	dm_bm_unlock(block);

	return entry;
}

int disk_array_format(struct disk_array* this, bool value) {
	int r;
	size_t shift, total, cycle;
	struct dm_block* block;

	shift = 0;
	total = __disk_array_blocks(this->nr_entry, this->entry_size, SWORNDISK_METADATA_BLOCK_SIZE) * SWORNDISK_METADATA_BLOCK_SIZE;
	while (total > 0) {
		r = dm_bm_write_lock(this->bm, this->start + shift, NULL, &block);
		if (r)
			return r;
		cycle = SWORNDISK_METADATA_BLOCK_SIZE;
		if (total < cycle)
			cycle = total;
		memset(dm_block_data(block), value ? 0xff : 0, cycle);
		dm_bm_unlock(block);

		total -= cycle;
		shift += 1;
	}

	return 0;
}


int disk_array_init(struct disk_array* this, struct dm_block_manager* bm, dm_block_t start, size_t nr_entry, size_t entry_size) {
	this->start = start;
	this->nr_entry = nr_entry;
	this->entry_size = entry_size;
	this->entries_per_block = SWORNDISK_METADATA_BLOCK_SIZE / this->entry_size;
	this->bm = bm;

	this->set = disk_array_set;
	this->get = disk_array_get;
	this->format = disk_array_format;
	
	return 0;
}

struct disk_array* disk_array_create(struct dm_block_manager* bm, dm_block_t start, size_t nr_entry, size_t entry_size) {
	int r;
	struct disk_array* this;

	this = kmalloc(sizeof(struct disk_array), GFP_KERNEL);
	if (!this)
		return NULL;
	
	r = disk_array_init(this, bm, start, nr_entry, entry_size);
	if (r)
		return NULL;
	
	return this;
}

void disk_array_destroy(struct disk_array* this) {
	if (!IS_ERR_OR_NULL(this)) {
		kfree(this);
	}
}

// disk bitset implementation
size_t __disk_bitset_group(size_t index) {
	return index / BITS_PER_LONG;
}

size_t __disk_bitset_offset(size_t index) {
	return index % BITS_PER_LONG;
}

size_t __disk_bitset_nr_group(size_t nr_bit) {
	return nr_bit ? (nr_bit - 1) / BITS_PER_LONG + 1 : 0;
}

int __disk_bitset_operate(struct disk_bitset* this, size_t index, bool set) {
	int r;
	unsigned long* group;

	if (index < 0 || index >= this->nr_bit)
		return -EINVAL;
	
	r = 0;
	group = this->array->get(this->array, __disk_bitset_group(index));
	if (IS_ERR_OR_NULL(group))
		return -ENODATA;
	
	(set ? set_bit : clear_bit)(__disk_bitset_offset(index), group);
	r = this->array->set(this->array, __disk_bitset_group(index), group);
	
	kfree(group);
	return r;
}

int disk_bitset_set(struct disk_bitset* this, size_t index) {
	return __disk_bitset_operate(this, index, true);
}

int disk_bitset_clear(struct disk_bitset* this, size_t index) {
	return __disk_bitset_operate(this, index, false);
}

int disk_bitset_get(struct disk_bitset* this, size_t index, bool* result) {
	unsigned long* group;

	group = this->array->get(this->array, __disk_bitset_group(index));
	if (IS_ERR_OR_NULL(group))
		return -EINVAL;
	
	*result = test_bit(__disk_bitset_offset(index), group);

	kfree(group);
	return 0;
}

int disk_bitset_format(struct disk_bitset* this, bool value) {
	return this->array->format(this->array, value);
}

int disk_bitset_init(struct disk_bitset* this, struct dm_block_manager* bm, dm_block_t start, size_t nr_bit) {
	this->nr_bit = nr_bit;
	this->array = disk_array_create(bm, start, __disk_bitset_nr_group(nr_bit), sizeof(unsigned long));
	if (IS_ERR_OR_NULL(this->array))
		return -ENOMEM;

	this->set = disk_bitset_set;
	this->clear = disk_bitset_clear;
	this->get = disk_bitset_get;
	this->format = disk_bitset_format;

	return 0;
}

struct disk_bitset* disk_bitset_create(struct dm_block_manager* bm, dm_block_t start, size_t nr_bit) {
	int r;
	struct disk_bitset* this;

	this = kmalloc(sizeof(struct disk_bitset), GFP_KERNEL);
	if (!this)
		return NULL;
	
	r = disk_bitset_init(this, bm, start, nr_bit);
	if (r)
		return NULL;

	return this;
}

void disk_bitset_destroy(struct disk_bitset* this) {
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->array))
			disk_array_destroy(this->array);
		kfree(this);
	}
}

// disk io implementation
int __disk_io(struct dm_block_manager* bm, struct dm_block_validator* validator, 
  dm_block_t block_id, size_t offset, size_t len, void* buffer, bool write) {
	int r;
	struct dm_block* block;
	
	if (offset + len > SWORNDISK_METADATA_BLOCK_SIZE)
		return -ENODATA;
	
	r = (write ? dm_bm_write_lock : dm_bm_read_lock)(bm, block_id, validator, &block);
	if (r)
		return r;

	if (write) 
		memcpy(dm_block_data(block) + offset, buffer, len);
	else 
		memcpy(buffer, dm_block_data(block) + offset, len);

	dm_bm_unlock(block);
	return 0;
}

int disk_read(struct dm_block_manager* bm, struct dm_block_validator* validator, 
  dm_block_t block_id, size_t offset, size_t len, void* buffer) {
	return __disk_io(bm, validator, block_id, offset, len, buffer, false);
}

int disk_write(struct dm_block_manager* bm, struct dm_block_validator* validator, 
  dm_block_t block_id, size_t offset, size_t len, void* buffer) {
	return __disk_io(bm, validator, block_id, offset, len, buffer, true);
}

// disk queue implementation
#define DISK_QUEUE_CSUM_XOR 0xde375872
bool disk_queue_validate(struct disk_queue* disk_queue) {
	uint32_t csum;

	csum = dm_bm_checksum(&disk_queue->start, sizeof(struct disk_queue) - sizeof(uint32_t), DISK_QUEUE_CSUM_XOR);
	if (csum != disk_queue->csum)
		return false;

	return true;
}

int disk_queue_load(struct disk_queue* this) {
	int r;
	struct disk_queue last;

	r = disk_read(this->bm, NULL, this->start, 0, sizeof(struct disk_queue), &last);
	if (r)
		return r;

	if (!disk_queue_validate(&last)) {
		DMINFO("disk queue invalid");
		return -EINVAL;
	}
	
	this->size = last.size;
	this->capacity = last.capacity;
	this->elem_size = last.elem_size;
	this->in = last.in;
	this->out = last.out;

	return 0;
}

int disk_queue_write(struct disk_queue* this) {
	this->csum = dm_bm_checksum(&this->start, sizeof(struct disk_queue) - sizeof(uint32_t), DISK_QUEUE_CSUM_XOR);
	return disk_write(this->bm, NULL, this->start, 0, sizeof(struct disk_queue), this);
}

void disk_queue_print(struct disk_queue* this) {
	DMINFO("disk queue: ");
	DMINFO("\tcsum: %x", this->csum);
	DMINFO("\tsize: %ld", this->size);
	DMINFO("\tcapacity: %ld", this->capacity);
	DMINFO("\telem_size: %ld", this->elem_size);
	DMINFO("\tin: %ld", this->in);
	DMINFO("\tout: %ld", this->out);
}

int disk_queue_flush(struct disk_queue* this) {
	return dm_bm_flush(this->bm);
}

int disk_queue_push(struct disk_queue* this, void* elem) {
	int r;

	if (this->full(this))
		return -ENOSPC; // no space

	r= this->array->set(this->array, this->in, elem);
	if (r)
		return r;
	
	this->in = (this->in + 1) % this->capacity;
	this->size += 1;

	return this->write(this);
}

void* disk_queue_pop(struct disk_queue* this) {
	void* elem;

	if (this->empty(this))
		return NULL;
	
	elem = this->array->get(this->array, this->out);
	if (IS_ERR_OR_NULL(elem))
		return NULL;
	
	this->out = (this->out + 1) % this->capacity;
	this->size -= 1;
	this->write(this);

	return elem;
}

void** disk_queue_peek(struct disk_queue* this, size_t count) {
	size_t cur, index;
	void* entry;
	void** entry_list;

	if (count < 0 || count > this->size)
		return NULL;
	
	entry_list = kmalloc(count * sizeof(void*), GFP_KERNEL);
	if (!entry_list)
		return NULL;

	cur = 0;
	index = this->out;
	while(cur != count) {
		entry = this->array->get(this->array, index);
		if (IS_ERR_OR_NULL(entry))
			goto bad;
		entry_list[cur] = entry;
		cur += 1;
		index = (index + 1) % this->capacity;
	}

	return entry_list;
bad:
	for (index = 0; index < cur; ++index)
		kfree(entry_list[cur]);
	kfree(entry_list);
	return NULL;
}

bool disk_queue_full(struct disk_queue* this) {
	return this->size == this->capacity;
}

bool disk_queue_empty(struct disk_queue* this) {
	return this->size == 0;
}

int disk_queue_clear(struct disk_queue* this) {
	this->size = 0;
	this->in = 0;
	this->out = 0;

	return this->write(this);
}

int disk_queue_init(struct disk_queue* this, struct dm_block_manager* bm, dm_block_t start, size_t capacity, size_t elem_size) {
	int r;
	
	this->bm = bm;
	this->start = start;
	this->array = disk_array_create(bm, this->start + STRUCTURE_BLOCKS(struct disk_queue), capacity, elem_size);
	if (IS_ERR_OR_NULL(this->array))
		return -ENOMEM;
	
	this->print = disk_queue_print;
	this->push = disk_queue_push;
	this->pop = disk_queue_pop;
	this->peek = disk_queue_peek;
	this->full = disk_queue_full;
	this->empty = disk_queue_empty;
	this->load = disk_queue_load;
	this->write = disk_queue_write;
	this->flush = disk_queue_flush;
	this->clear = disk_queue_clear;

	r = this->load(this);
	if (!r)
		return 0;

	this->capacity = capacity;
	this->elem_size = elem_size;
	this->size = 0;
	this->in = 0;
	this->out = 0;

	return 0;
}

struct disk_queue* disk_queue_create(struct dm_block_manager* bm, dm_block_t start, size_t capacity, size_t elem_size) {
	int r;
	struct disk_queue* this;

	this = kmalloc(sizeof(struct disk_queue), GFP_KERNEL);
	if (!this)
		return NULL;
	
	r = disk_queue_init(this, bm, start, capacity, elem_size);
	if (r)
		return NULL;
	
	return this;
}

void disk_queue_destroy(struct disk_queue* this) {
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->array))
			disk_array_destroy(this->array);
		kfree(this);
	}
}