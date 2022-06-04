#include "../include/metadata.h"
#include "../include/lsm_tree.h"

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
	this->max_disk_level_capacity = le64_to_cpu(disk_super->max_disk_level_capacity);
	this->index_region_start = le64_to_cpu(disk_super->index_region_start);
	this->journal_size = le32_to_cpu(disk_super->journal_size);
	this->nr_journal = le64_to_cpu(disk_super->nr_journal);
	this->journal_region_start = le64_to_cpu(disk_super->journal_region_start);
	this->seg_validity_table_start = le64_to_cpu(disk_super->seg_validity_table_start);
	this->data_seg_table_start = le64_to_cpu(disk_super->data_seg_table_start);
	this->reverse_index_table_start = le64_to_cpu(disk_super->reverse_index_table_start);
	this->block_index_table_catalogue_start = le64_to_cpu(disk_super->block_index_table_catalogue_start);

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
	disk_super->max_disk_level_capacity = cpu_to_le64(this->max_disk_level_capacity);
	disk_super->index_region_start = cpu_to_le64(this->index_region_start);
	disk_super->journal_size = cpu_to_le32(this->journal_size);
	disk_super->nr_journal = cpu_to_le64(this->nr_journal);
	disk_super->journal_region_start = cpu_to_le64(this->journal_region_start);
	disk_super->seg_validity_table_start = cpu_to_le64(this->seg_validity_table_start);
	disk_super->data_seg_table_start = cpu_to_le64(this->data_seg_table_start);
	disk_super->reverse_index_table_start = cpu_to_le64(this->reverse_index_table_start);
	disk_super->block_index_table_catalogue_start = cpu_to_le64(this->block_index_table_catalogue_start);	

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
	DMINFO("\tmax_disk_level_capacity: %lld", this->max_disk_level_capacity);
	DMINFO("\tindex_region_start: %lld", this->index_region_start);
	DMINFO("\tjournal_size: %d", this->journal_size);
	DMINFO("\tnr_journal: %lld", this->nr_journal);
	DMINFO("\tjournal_region_start: %lld", this->journal_region_start);
	DMINFO("\tseg_validity_table_start: %lld", this->seg_validity_table_start);
	DMINFO("\tdata_seg_table_start: %lld", this->data_seg_table_start);
	DMINFO("\treverse_index_table_start: %lld", this->reverse_index_table_start);
	DMINFO("\tblock_index_table_catalogue_start: %lld", this->block_index_table_catalogue_start);
}

#include "../include/segment_allocator.h"
#define LSM_TREE_DISK_LEVEL_COMMON_RATIO 10

size_t __bytes_to_block(size_t bytes, size_t block_size) {
	if (bytes == 0)
		return 0;
	
	return (bytes - 1) / block_size + 1;
}

size_t __disk_array_blocks(size_t nr_elem, size_t elem_size, size_t block_size) {
	size_t elems_per_block;

	if (elem_size == 0)
		return 0;
	
	elems_per_block = block_size / elem_size;
	return nr_elem / elems_per_block + 1;
}

size_t __total_bit(size_t nr_disk_level, size_t common_ratio, size_t max_disk_level_capacity) {
	size_t total = 0, capacity, i;

	capacity = max_disk_level_capacity;
	for (i = 1; i < nr_disk_level; ++i) {
		total += (capacity ? (capacity - 1) / DEFAULT_LSM_FILE_CAPACITY + 1 : 0);
		capacity /= common_ratio;
	}

	return total + DEFAULT_LSM_LEVEL0_NR_FILE;
}

size_t __extra_bit(size_t max_disk_level_capacity) {
	return __total_bit(2, LSM_TREE_DISK_LEVEL_COMMON_RATIO, max_disk_level_capacity);
}

size_t __index_region_blocks(size_t nr_disk_level, size_t common_ratio, size_t max_disk_level_capacity) {
	size_t total_bit = __total_bit(nr_disk_level, common_ratio, max_disk_level_capacity);
	size_t extra_bit = __extra_bit(max_disk_level_capacity);

	return __bytes_to_block((total_bit + extra_bit)* calculate_bit_size(DEFAULT_LSM_FILE_CAPACITY, DEFAULT_BIT_DEGREE), SWORNDISK_METADATA_BLOCK_SIZE);
}

size_t __journal_region_blocks(size_t nr_journal, size_t journal_size) {
	return __disk_array_blocks(nr_journal, journal_size, SWORNDISK_METADATA_BLOCK_SIZE);
}

size_t __seg_validity_table_blocks(size_t nr_segment) {
	if (!nr_segment)
		return 0;
	return (((nr_segment - 1) / BITS_PER_LONG + 1) * sizeof(unsigned long) - 1) / SWORNDISK_METADATA_BLOCK_SIZE + 1;
}

size_t __data_seg_table_blocks(size_t nr_segment) {
	return __disk_array_blocks(nr_segment, sizeof(struct dst_entry), SWORNDISK_METADATA_BLOCK_SIZE);
}

size_t __reverse_index_table_blocks(size_t nr_segment, size_t blocks_per_seg) {
	return __disk_array_blocks(nr_segment * blocks_per_seg, sizeof(struct reverse_index_entry), SWORNDISK_METADATA_BLOCK_SIZE);
}

int superblock_init(struct superblock* this, struct dm_block_manager* bm, bool* should_format) {
	int r;

	*should_format = false;
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

	*should_format = true;
	this->magic = SUPERBLOCK_MAGIC;
	this->blocks_per_seg = BLOCKS_PER_SEGMENT;
	this->nr_segment = NR_SEGMENT;
	this->common_ratio = LSM_TREE_DISK_LEVEL_COMMON_RATIO;
	this->nr_disk_level = DEFAULT_LSM_TREE_NR_DISK_LEVEL;
	this->max_disk_level_capacity = NR_SEGMENT * BLOCKS_PER_SEGMENT;
	this->index_region_start = SUPERBLOCK_LOCATION +  STRUCTURE_BLOCKS(struct superblock);
	this->journal_size = 0;
	this->nr_journal = 0;
	this->journal_region_start = this->index_region_start + __index_region_blocks(
	  this->nr_disk_level, this->common_ratio, this->max_disk_level_capacity);
	this->seg_validity_table_start = this->journal_region_start + __journal_region_blocks(this->nr_journal, this->journal_size);
	this->data_seg_table_start = this->seg_validity_table_start + __seg_validity_table_blocks(this->nr_segment);
	this->reverse_index_table_start = this->data_seg_table_start + __data_seg_table_blocks(this->nr_segment);
	this->block_index_table_catalogue_start = this->reverse_index_table_start + __reverse_index_table_blocks(this->nr_segment, this->blocks_per_seg);

	this->write(this);
	return 0;
}

struct superblock* superblock_create(struct dm_block_manager* bm, bool* should_format) {
	int r;
	struct superblock* this;

	this = kmalloc(sizeof(struct superblock), GFP_KERNEL);
	if (!this)
		return NULL;
	
	r = superblock_init(this, bm, should_format);
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
	size_t try_times = 0;

next_try:
	while(this->cur_segment < this->nr_segment) {
		r = this->seg_validity_table->get(this->seg_validity_table, this->cur_segment, &valid);
		if (!r && !valid) {
			*next_seg = this->cur_segment;
			return 0;
		}
		this->cur_segment += 1;
	}

	if (try_times < 1) {
		try_times += 1;
		this->cur_segment = 0;
		goto next_try;
	}

	return -ENODATA;
}

int seg_validator_test_and_return(struct seg_validator* this, size_t seg, bool* old) {
	int r;
	bool valid;

	r = this->seg_validity_table->get(this->seg_validity_table, seg, &valid);
	if (r)
		return r;

	r = this->seg_validity_table->clear(this->seg_validity_table, seg);
	if (r)
		return r;

	*old = valid;
	return 0;
}

int seg_validator_format(struct seg_validator* this) {
	int r;

	r = this->seg_validity_table->format(this->seg_validity_table, false);
	if (r)
		return r;

	this->cur_segment = 0;
	return 0;
}

int seg_validator_valid_segment_count(struct seg_validator* this, size_t* count) {
	int r;
	bool valid;
	size_t segno;

	*count = 0;
	for (segno = 0; segno < this->nr_segment; ++segno) {
		r = this->seg_validity_table->get(this->seg_validity_table, segno, &valid);
		if (r)
			return r;
		*count += valid;
	}

	return 0;
}

int seg_validator_init(struct seg_validator* this, struct dm_block_manager* bm, dm_block_t start, size_t nr_segment) {
	this->nr_segment = nr_segment;
	this->cur_segment = 0;
	this->seg_validity_table = disk_bitset_create(bm, start, nr_segment);
	if (IS_ERR_OR_NULL(this->seg_validity_table))
		return -ENOMEM;

	this->take = seg_validator_take;
	this->next = seg_validator_next;
	this->format = seg_validator_format;
	this->valid_segment_count = seg_validator_valid_segment_count;
	this->test_and_return = seg_validator_test_and_return;

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
		.lba = lba,
	};

	r = __reverse_index_table_set_entry(this, pba, &entry);
	if (r)
		return r;
	
	return 0;
}

int __reverse_index_table_get_entry(struct reverse_index_table* this, dm_block_t pba, void* entry) {
	return this->array->get(this->array, pba, entry);
}

int reverse_index_table_get(struct reverse_index_table* this, dm_block_t pba, dm_block_t* lba) {
	int err = 0;
	struct reverse_index_entry entry;

	err = __reverse_index_table_get_entry(this, pba, &entry);
	if (err)
		return err;

	*lba = entry.lba;
	return 0;
}

int reverse_index_table_init(struct reverse_index_table* this, struct dm_block_manager* bm, dm_block_t start, size_t nr_block) {
	this->nr_block = nr_block;
	this->array = disk_array_create(bm, start, this->nr_block, sizeof(struct reverse_index_entry));
	if (!this->array)
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

// data segment table implementaion
struct victim* victim_create(size_t segno, size_t nr_valid_block, unsigned long* block_validity_table) {
	struct victim* victim;

	victim = kmalloc(sizeof(struct victim), GFP_KERNEL);
	if (!victim)
		return NULL;
	
	victim->segno = segno;
	victim->nr_valid_block = nr_valid_block;
	bitmap_copy(victim->block_validity_table, block_validity_table, BLOCKS_PER_SEGMENT);
	return victim;
}

void victim_destroy(struct victim* victim) {
	if (!IS_ERR_OR_NULL(victim)) {
		kfree(victim);
	}
}

bool victim_less(struct rb_node* node1, const struct rb_node* node2) {
	struct victim *victim1, *victim2;

	victim1 = container_of(node1, struct victim, node);
	victim2 = container_of(node2, struct victim, node);
	return victim1->nr_valid_block < victim2->nr_valid_block;
} 

void dst_destroy_victim(struct dst* this, size_t segno) {
	victim_destroy(this->remove_victim(this, segno));
}

int dst_add_victim(struct dst* this, size_t segno, size_t nr_valid, unsigned long* block_validity_table) {
	struct victim* victim = victim_create(segno, nr_valid, block_validity_table);

	if (!victim) 	
		return -ENOMEM;
	rb_add(&victim->node, &this->victims, victim_less);
	this->node_list[segno] = &victim->node;
	return 0;
}

int dst_load(struct dst* this) {
	int err = 0;
	size_t segno;
	struct dst_entry entry;
	
	for (segno = 0; segno < this->nr_segment; ++segno) {
		err = this->array->get(this->array, segno, &entry);
		if (err)
			return -ENODATA;
		
		if (entry.nr_valid_block < BLOCKS_PER_SEGMENT) {
			dst_add_victim(this, segno, entry.nr_valid_block, entry.block_validity_table);
		}
	}

	return 0;
}

inline size_t __block_to_segment(dm_block_t block_id) {
	return block_id / BLOCKS_PER_SEGMENT;
}

inline size_t __block_offset_whthin_segment(dm_block_t block_id) {
	return block_id % BLOCKS_PER_SEGMENT;
}

int dst_update_victim(struct dst* this, size_t segno, size_t nr_valid, unsigned long* block_validity_table) {
	dst_destroy_victim(this, segno);
	if (nr_valid >= BLOCKS_PER_SEGMENT)
		return 0;
	return dst_add_victim(this, segno, nr_valid, block_validity_table);
}

int dst_take_segment(struct dst* this, size_t segno) {
	int err = 0;
	struct dst_entry entry;

	err = this->array->get(this->array, segno, &entry);
	if (err)
		return err;

	if (entry.nr_valid_block) 
		return -EINVAL;

	entry.nr_valid_block = BLOCKS_PER_SEGMENT;
	bitmap_fill(entry.block_validity_table, BLOCKS_PER_SEGMENT);

	err = this->array->set(this->array, segno, &entry);
	if (err) 
		return err;

	dst_destroy_victim(this, segno);
	return err;
}

int dst_take_block(struct dst* this, dm_block_t blkaddr) {
	int err = 0;
	struct dst_entry entry;
	size_t segno, offset;

	segno = __block_to_segment(blkaddr);
	offset = __block_offset_whthin_segment(blkaddr);

	err = this->array->get(this->array, segno, &entry);
	if (err)
		return err;

	if (entry.nr_valid_block >= BLOCKS_PER_SEGMENT)
		return -EINVAL;

	entry.nr_valid_block += 1;
	bitmap_set(entry.block_validity_table, offset, 1);

	err = this->array->set(this->array, segno, &entry);
	if (err) 
		return err;

	err = dst_update_victim(this, segno, entry.nr_valid_block, entry.block_validity_table);
	if (err)
		return err;

	return err;
}

int dst_return_block(struct dst* this, dm_block_t blkaddr) {
	int err = 0;
	struct dst_entry entry;
	size_t segno, offset;

	segno = __block_to_segment(blkaddr);
	offset = __block_offset_whthin_segment(blkaddr);

	err = this->array->get(this->array, segno, &entry);
	if (err)
		return err;

	if (!entry.nr_valid_block)
		return -EINVAL;

	entry.nr_valid_block -= 1;
	bitmap_clear(entry.block_validity_table, offset, 1);

	err = this->array->set(this->array, segno, &entry);
	if (err) 
		return err;

	err = dst_update_victim(this, segno, entry.nr_valid_block, entry.block_validity_table);
	if (err)
		return err;

	return err;
}

bool dst_victim_empty(struct dst* this) {
	return RB_EMPTY_ROOT(&this->victims);
}

struct victim* dst_peek_victim(struct dst* this) {
	struct rb_node* node;

	node = rb_first(&this->victims);
	if (!node)
		return NULL;
	
	return rb_entry(node, struct victim, node);
}

struct victim* dst_remove_victim(struct dst* this, size_t segno) {
	if (this->node_list[segno]) {
		struct victim* victim = rb_entry(this->node_list[segno], struct victim, node);

		if (!victim)
			return NULL;
		rb_erase(&victim->node, &this->victims);
		this->node_list[segno] = NULL;
		return victim;
	}
	
	return NULL;
}

bool should_threaded_logging(struct dst* dst) {
	struct victim* victim;

	if (dst_victim_empty(dst))
		return false;
	
	victim = rb_entry(rb_first(&dst->victims), struct victim, node);
	if (victim->nr_valid_block > (BLOCKS_PER_SEGMENT >> 1))
		return true;
	
	return false;
}

struct victim* dst_pop_victim(struct dst* this) {
	struct victim* victim = this->peek_victim(this);

	if (!victim)
		return NULL;
	return dst_remove_victim(this, victim->segno);
}


int dst_init(struct dst* this, struct dm_block_manager* bm, dm_block_t start, size_t nr_segment);
int dst_format(struct dst* this) {
	int r;

	r = this->array->format(this->array, false);
	if (r)
		return r;
	
	while(!RB_EMPTY_ROOT(&this->victims)) {
		victim_destroy(this->pop_victim(this));
	}

	kfree(this->node_list);
	r = dst_init(this, this->bm, this->start, this->nr_segment);
	if (r)
		return r;
	
	return 0;
}

int dst_init(struct dst* this, struct dm_block_manager* bm, dm_block_t start, size_t nr_segment) {
	int r;

	this->load = dst_load;
	this->take_segment = dst_take_segment;
	this->take_block = dst_take_block;
	this->return_block = dst_return_block;
	this->victim_empty = dst_victim_empty;
	this->peek_victim = dst_peek_victim;
	this->pop_victim = dst_pop_victim;
	this->remove_victim = dst_remove_victim;
	this->format = dst_format;

	this->bm = bm;
	this->start = start;
	this->nr_segment = nr_segment;
	this->array = disk_array_create(this->bm, this->start, this->nr_segment, sizeof(struct dst_entry));
	if (!this->array)
		return -ENOMEM;

	this->node_list = kzalloc(this->nr_segment * sizeof(struct rb_node*), GFP_KERNEL);
	if (!this->node_list)
		return -ENOMEM;

	this->victims = RB_ROOT;
	r = this->load(this);
	if (r)
		return r;
	
	return 0;
}

struct dst* dst_create(struct dm_block_manager* bm, dm_block_t start, size_t nr_segment) {
	int r;
	struct dst* this;

	this = kmalloc(sizeof(struct dst), GFP_KERNEL);
	if (!this)	
		return NULL;
	
	r = dst_init(this, bm, start, nr_segment);
	if (r)
		return NULL;

	return this;
}

void dst_destroy(struct dst* this) {	
	if (!IS_ERR_OR_NULL(this)) {
		while(!RB_EMPTY_ROOT(&this->victims)) 
			victim_destroy(this->pop_victim(this));
		if (!IS_ERR_OR_NULL(this->node_list)) 
			kfree(this->node_list);
		kfree(this);
	}
}

// block index table catalogue implementation
int bitc_alloc_file(struct lsm_catalogue* lsm_catalogue, size_t* fd) {
	int err = 0;
	struct bit_catalogue* this = container_of(lsm_catalogue, struct bit_catalogue, lsm_catalogue);

	err = this->bit_validity_table->next(this->bit_validity_table, fd);
	if (err)
		return err;
	
	err = this->bit_validity_table->take(this->bit_validity_table, *fd);
	if (err)
		return err;
	
	return 0;
}

int bitc_release_file(struct lsm_catalogue* lsm_catalogue, size_t fd) {
	int err;
	bool old;
	struct bit_catalogue* this = container_of(lsm_catalogue, struct bit_catalogue, lsm_catalogue);

	err = this->bit_validity_table->test_and_return(this->bit_validity_table, fd, &old);
	if (err)
		return err;
	
	return 0;
}

void file_stat_print(struct file_stat stat) {
	DMINFO("file stat, id: %ld, level: %ld, root: %lld, first key: %u, last key: %u",
	  stat.id, stat.level, stat.root, stat.first_key, stat.last_key);
}

int bitc_set_file_stats(struct lsm_catalogue* lsm_catalogue, size_t fd, struct file_stat stats) {
	struct bit_catalogue* this = container_of(lsm_catalogue, struct bit_catalogue, lsm_catalogue);

	return this->file_stats->set(this->file_stats, fd, &stats);
}

int bitc_get_file_stats(struct lsm_catalogue* lsm_catalogue, size_t fd, void* stats) {
	int err = 0;
	struct file_stat info;
	struct bit_catalogue* this = container_of(lsm_catalogue, struct bit_catalogue, lsm_catalogue);

	err = this->file_stats->get(this->file_stats, fd, &info);
	if (!err) {
		*(struct file_stat*)stats = info;
		return 0;
	}

	return -ENODATA;
}

int bitc_get_all_file_stats(struct lsm_catalogue* lsm_catalogue, struct list_head* stats) {
	int err = 0;
	bool valid;
	size_t i;
	struct file_stat* stat;
	struct bit_catalogue* this = container_of(lsm_catalogue, struct bit_catalogue, lsm_catalogue);

	INIT_LIST_HEAD(stats);
	for (i = 0; i < this->bit_validity_table->nr_segment; ++i) {
		err = this->bit_validity_table->seg_validity_table->get(this->bit_validity_table->seg_validity_table, i, &valid);
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

size_t bitc_get_next_version(struct lsm_catalogue* lsm_catalogue) {
	struct bit_catalogue* this = container_of(lsm_catalogue, struct bit_catalogue, lsm_catalogue);

	return this->max_version++;
}

int bit_catalogue_format(struct bit_catalogue* this) {
	int err = 0;

	err = this->bit_validity_table->format(this->bit_validity_table);
	if (err)
		return err;
	
	err = this->file_stats->format(this->file_stats, false);
	if (err)
		return err;
	
	return 0;
}

size_t bitc_get_current_version(struct bit_catalogue* this) {
	size_t max_version = 0;
	struct file_stat* info;
	struct list_head file_stats;

	bitc_get_all_file_stats(&this->lsm_catalogue, &file_stats);
	list_for_each_entry(info, &file_stats, node) {
		if (max_version < info->version)
			max_version = info->version + 1;
	}

	return max_version;
}

int bit_catalogue_init(struct bit_catalogue* this, struct dm_block_manager* bm, struct superblock* superblock) {
	int err = 0;
	size_t max_fd;
	
	this->bm = bm;
	this->start = superblock->block_index_table_catalogue_start;
	this->index_region_start = superblock->index_region_start;
	this->nr_bit = __total_bit(superblock->nr_disk_level, superblock->common_ratio, superblock->max_disk_level_capacity);

	max_fd = this->nr_bit + __extra_bit(superblock->max_disk_level_capacity);
	this->bit_validity_table = seg_validator_create(bm, this->start, max_fd);
	if (!this->bit_validity_table) {
		err = -ENOMEM;
		goto bad;
	}

	this->file_stats = disk_array_create(bm, this->start + __seg_validity_table_blocks(max_fd), max_fd, sizeof(struct file_stat));
	if (!this->file_stats) {
		err = -ENOMEM;
		goto bad;
	}

	this->max_version = bitc_get_current_version(this);
	this->lsm_catalogue.get_next_version = bitc_get_next_version;
	this->format = bit_catalogue_format;
	this->lsm_catalogue.file_size = calculate_bit_size(DEFAULT_LSM_FILE_CAPACITY, DEFAULT_BIT_DEGREE);
	this->lsm_catalogue.total_file = this->nr_bit;
	this->lsm_catalogue.start = this->index_region_start * SWORNDISK_METADATA_BLOCK_SIZE;
	this->lsm_catalogue.nr_disk_level = superblock->nr_disk_level;
	this->lsm_catalogue.common_ratio = superblock->common_ratio;
	this->lsm_catalogue.max_level_nr_file = __total_bit(2, superblock->common_ratio, superblock->max_disk_level_capacity);
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

struct bit_catalogue* bit_catalogue_create(struct dm_block_manager* bm, struct superblock* superblock) {
	int err = 0;
	struct bit_catalogue* this;

	this = kzalloc(sizeof(struct bit_catalogue), GFP_KERNEL);
	if (!this)
		goto bad;

	err = bit_catalogue_init(this, bm, superblock);
	if (err)
		goto bad;
	
	return this;
bad:
	if (this)
		kfree(this);
	return NULL;
}

void bit_catalogue_destroy(struct bit_catalogue* this) {
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->bit_validity_table))
			seg_validator_destroy(this->bit_validity_table);
		if (!IS_ERR_OR_NULL(this->file_stats))
			disk_array_destroy(this->file_stats);
		kfree(this);
	}
}

// metadata implementation
int metadata_format(struct metadata* this) {
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

int metadata_init(struct metadata* this, struct block_device* bdev) {
	int r;
	bool should_format;

	this->bdev = bdev;
	this->bm = dm_block_manager_create(this->bdev, SWORNDISK_METADATA_BLOCK_SIZE, SWORNDISK_MAX_CONCURRENT_LOCKS);
	if (IS_ERR_OR_NULL(this->bm))
		goto bad;

	this->superblock = superblock_create(this->bm, &should_format);
	if (IS_ERR_OR_NULL(this->superblock))
		goto bad;
	
	this->seg_validator = seg_validator_create(this->bm, this->superblock->seg_validity_table_start, this->superblock->nr_segment);
	if (IS_ERR_OR_NULL(this->seg_validator))
		goto bad;

	this->rit = reverse_index_table_create(this->bm, 
	  this->superblock->reverse_index_table_start, this->superblock->nr_segment * this->superblock->blocks_per_seg);
	if (IS_ERR_OR_NULL(this->rit))
		goto bad;

	this->dst = dst_create(this->bm, this->superblock->data_seg_table_start, this->superblock->nr_segment);
	if (IS_ERR_OR_NULL(this->dst))
		goto bad;

	this->bit_catalogue = bit_catalogue_create(this->bm, this->superblock);
	if (IS_ERR_OR_NULL(this->bit_catalogue))
		goto bad;

	this->format = metadata_format;
	if (should_format) {
		r = this->format(this);
		if (r)
			goto bad;
	}

	return 0;
bad:
	if (!IS_ERR_OR_NULL(this->bm))
		dm_block_manager_destroy(this->bm);
	superblock_destroy(this->superblock);
	seg_validator_destroy(this->seg_validator);
	reverse_index_table_destroy(this->rit);
	dst_destroy(this->dst);
	bit_catalogue_destroy(this->bit_catalogue);
	return -EAGAIN;
}

struct metadata* metadata_create(struct block_device* bdev) {
	int r;
	struct metadata* this;

	this = kzalloc(sizeof(struct metadata), GFP_KERNEL);
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
		superblock_destroy(this->superblock);
		seg_validator_destroy(this->seg_validator);
		reverse_index_table_destroy(this->rit);
		dst_destroy(this->dst);
		bit_catalogue_destroy(this->bit_catalogue);
		kfree(this);
	}
}
