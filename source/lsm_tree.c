#include <linux/bsearch.h>
#include <linux/slab.h>
#include <linux/mempool.h>
#include <linux/random.h>

#include "../include/dm_sworndisk.h"
#include "../include/lsm_tree.h"
#include "../include/segment_buffer.h"
#include "../include/memtable.h"
#include "../include/metadata.h"

struct compaction_work {
	struct work_struct work;
	void *data;
};
static struct workqueue_struct *compaction_wq;

static struct aead_cipher* global_cipher; // global cipher

// block index table node implementaion
void bit_node_print(struct bit_node* bit_node) {
    size_t i;

    DMINFO("is leaf: %d", bit_node->is_leaf);
    if (bit_node->is_leaf) {
        for (i = 0; i < BIT_LEAF_LEN; ++i) {
            DMINFO("\tkey: %d", bit_node->leaf.keys[i]);
            DMINFO("\tvalue: %lld", bit_node->leaf.records[i].pba);
        }
        DMINFO("next: %ld", bit_node->leaf.next_pos);
    } else {
        for (i = 0; i < bit_node->inner.nr_child; ++i) {
            DMINFO("child %ld", i);
            DMINFO("\tkey: %d", bit_node->inner.children[i].key);
            DMINFO("\tpos: %ld", bit_node->inner.children[i].pos);
        }
    }
}

int bit_node_encode(struct bit_node* node, char* key, char* iv) {
    char* mac = NULL;
    size_t data_len = BIT_INNER_NODE_SIZE - AES_GCM_AUTH_SIZE;

    if (node->is_leaf)
        data_len = BIT_LEAF_NODE_SIZE - AES_GCM_AUTH_SIZE;
    mac = ((char*)node) + data_len;
    return global_cipher->encrypt(global_cipher, (char*)node, data_len, key, iv, mac, 0, (char*)node);
}

// we don't know whether the node is leaf when decrypting
int bit_node_decode(char* data, bool is_leaf, char* key, char* iv) {
    int err = 0;
    char* mac = NULL;
    size_t len = BIT_INNER_NODE_SIZE - AES_GCM_AUTH_SIZE;

    if (is_leaf)
        len = BIT_LEAF_NODE_SIZE - AES_GCM_AUTH_SIZE;
    mac = data + len;
    err = global_cipher->decrypt(global_cipher, data, len, key, iv, mac, 0, data);
    if (err)
        return err;

    memcpy(((struct bit_node*)data)->mac, mac, AES_GCM_AUTH_SIZE);
    return 0;
}

// block index table builder implementaion
size_t __bit_height(size_t nr_record, size_t nr_degree) {
    uint32_t rem = 0;
    size_t height = 1, size = 1, nr_leaf;

    if (!nr_record)
        return 0;

    nr_leaf = div_u64_rem(nr_record, BIT_LEAF_LEN, &rem);
    if (rem)
        nr_leaf += 1;

    while(size < nr_leaf) {
        height += 1;
        size *= nr_degree;
    }

    return height;
}

size_t __bit_array_len(size_t nr_record, size_t nr_degree) {
    uint32_t rem = 0;
    size_t len = 0, size = 1, nr_leaf;

    if (!nr_record)
        return 0;
    
    nr_leaf = div_u64_rem(nr_record, BIT_LEAF_LEN, &rem);
    if (rem)
        nr_leaf += 1;

    while (size < nr_leaf) {
        len += size;
        size *= nr_degree;
    }

    return len + nr_leaf;
}

size_t calculate_bit_size(size_t nr_record, size_t nr_degree) {
    uint32_t rem = 0;
    size_t nr_leaf;

    if (!nr_record)
        return 0;
    
    nr_leaf = div_u64_rem(nr_record, BIT_LEAF_LEN, &rem);
    if (rem)
        nr_leaf += 1;
    
    return (__bit_array_len(nr_record, nr_degree) - nr_leaf) * BIT_INNER_NODE_SIZE + nr_leaf * BIT_LEAF_NODE_SIZE + BIT_BLOOM_FILTER_SIZE;
}

struct bit_node __bit_inner(struct bit_builder_context* ctx) {
    size_t i;
    struct bit_node node = {
        .is_leaf = false,
        .inner.nr_child = ctx->nr
    };

    for (i = 0; i < ctx->nr; ++i) {
        node.inner.children[i].is_leaf = ctx->nodes[i].is_leaf;
        node.inner.children[i].key = ctx->nodes[i].is_leaf ? ctx->nodes[i].leaf.keys[ctx->nodes[i].leaf.nr_record-1] : ctx->nodes[i].inner.children[ctx->nodes[i].inner.nr_child - 1].key;
        node.inner.children[i].pos = ctx->pos[i];
    }

    return node;
}

void bit_builder_buffer_flush_if_full(struct bit_builder* this) {
    loff_t pos = this->begin;

    if (this->cur + this->height * sizeof(struct bit_node) > DEFAULT_LSM_FILE_BUILDER_BUFFER_SIZE) {
        kernel_write(this->file, this->buffer, this->cur, &pos);
        this->begin += this->cur;
        this->cur = 0;
    }
}

int bit_builder_add_entry(struct lsm_file_builder* builder, struct entry* entry) {
    struct bit_builder* this = container_of(builder, struct bit_builder, lsm_file_builder);
    struct bit_node *inner_node = NULL, *leaf_node = NULL;
    size_t h = 0, cur, nr_record = this->cur_leaf.nr_record;
    struct journal_region *journal = sworndisk->meta->journal;
    struct journal_record j_record;
    size_t pos = this->begin + this->cur;

    if (!this->has_first_key) {
        this->first_key = entry->key;
        this->has_first_key = true;
    } 
    this->last_key = entry->key;
    this->lsm_file_builder.size += 1;
    bloom_filter_add(this->filter, &entry->key, sizeof(uint32_t));

    this->cur_leaf.keys[nr_record] = entry->key;
    this->cur_leaf.records[nr_record] = *(struct record*)entry->val;
    this->cur_leaf.nr_record += 1;
    if (this->cur_leaf.nr_record < BIT_LEAF_LEN)
        goto exit;

    inner_node = kmalloc(sizeof(struct bit_node), GFP_KERNEL);
    leaf_node = kmalloc(sizeof(struct bit_node), GFP_KERNEL);
    leaf_node->is_leaf = true;
    leaf_node->leaf = this->cur_leaf;

    this->ctx[h].nodes[this->ctx[h].nr] = *leaf_node;
    this->ctx[h].pos[this->ctx[h].nr] = pos;
    bit_builder_buffer_flush_if_full(this);
    cur = this->cur;
    this->cur += BIT_LEAF_NODE_SIZE;

    j_record.type = BIT_NODE;
    j_record.bit_node.bit_id = this->id;

    this->ctx[h].nr += 1;
    while (this->ctx[h].nr == DEFAULT_BIT_DEGREE) {
        size_t *node_pos = &(this->ctx[h+1].pos[this->ctx[h+1].nr]);

        *inner_node = __bit_inner(&this->ctx[h]);
        this->ctx[h+1].nodes[this->ctx[h+1].nr] = *inner_node;
        *node_pos = this->begin + this->cur;
        bit_node_encode(inner_node, this->bit_key, NULL);
        memcpy(this->buffer + this->cur, inner_node, BIT_INNER_NODE_SIZE);
        this->cur += BIT_INNER_NODE_SIZE;

        this->ctx[h+1].nr += 1;
        this->ctx[h].nr = 0;
        h += 1;

	j_record.bit_node.is_leaf = false;
	j_record.bit_node.is_done = false;
	j_record.bit_node.pos = *node_pos;
	memcpy(j_record.bit_node.key, this->bit_key, AES_GCM_KEY_SIZE);
	memcpy(j_record.bit_node.mac, inner_node->mac, AES_GCM_AUTH_SIZE);
	j_record.bit_node.timestamp = ktime_get_real_ns();
	journal->jops->add_record(journal, &j_record);
    }

    leaf_node->leaf.next_pos = this->begin + this->cur;
    bit_node_encode(leaf_node, this->bit_key, NULL);
    memcpy(this->buffer + cur, leaf_node, BIT_LEAF_NODE_SIZE);
    this->cur_leaf.nr_record = 0;

    j_record.bit_node.is_leaf = true;
    j_record.bit_node.is_done = false;
    j_record.bit_node.pos = pos;
    memcpy(j_record.bit_node.key, this->bit_key, AES_GCM_KEY_SIZE);
    memcpy(j_record.bit_node.mac, leaf_node->mac, AES_GCM_AUTH_SIZE);
    j_record.bit_node.timestamp = ktime_get_real_ns();
    journal->jops->add_record(journal, &j_record);

exit:
    if (leaf_node)
        kfree(leaf_node);
    if (inner_node)
        kfree(inner_node);
    return 0;
}

struct lsm_file* bit_builder_complete(struct lsm_file_builder* builder) {
    struct bit_builder* this = container_of(builder, struct bit_builder, lsm_file_builder);
    size_t h = 0, cur, start, end;
    loff_t addr = this->begin, root, filter_begin;
    struct bit_node *inner_node = NULL, *leaf_node = NULL;
    struct lsm_catalogue *catalogue = sworndisk->lsm_tree->catalogue;
    struct journal_region *journal = sworndisk->meta->journal;
    struct journal_record j_record;
    size_t pos = this->begin + this->cur;

    if (this->ctx[this->height-1].nr) 
        goto exit;

    bit_builder_buffer_flush_if_full(this);

    inner_node = kmalloc(sizeof(struct bit_node), GFP_KERNEL);
    leaf_node = kmalloc(sizeof(struct bit_node), GFP_KERNEL);
    leaf_node->is_leaf = true;
    leaf_node->leaf = this->cur_leaf;
    if (this->cur_leaf.nr_record > 0) {
        this->ctx[h].nodes[this->ctx[h].nr] = *leaf_node;
        this->ctx[h].pos[this->ctx[h].nr] = pos;
        cur = this->cur;
        this->cur += BIT_LEAF_NODE_SIZE;
    }

    j_record.type = BIT_NODE;
    j_record.bit_node.bit_id = this->id;

    while (h < this->height - 1) {
        size_t *node_pos = &(this->ctx[h+1].pos[this->ctx[h+1].nr]);

        if (!this->ctx[h].nr) {
            h += 1;
            continue;
        }

        *inner_node = __bit_inner(&this->ctx[h]);
        this->ctx[h+1].nodes[this->ctx[h+1].nr] = *inner_node;
        *node_pos = this->begin + this->cur;
        bit_node_encode(inner_node, this->bit_key, NULL);
        memcpy(this->buffer + this->cur, inner_node, BIT_INNER_NODE_SIZE);
        this->cur += BIT_INNER_NODE_SIZE;

        this->ctx[h+1].nr += 1;
        this->ctx[h].nr = 0;
        h += 1;

	j_record.bit_node.is_leaf = false;
	j_record.bit_node.is_done = false;
	j_record.bit_node.pos = *node_pos;
	memcpy(j_record.bit_node.key, this->bit_key, AES_GCM_KEY_SIZE);
	memcpy(j_record.bit_node.mac, inner_node->mac, AES_GCM_AUTH_SIZE);
	j_record.bit_node.timestamp = ktime_get_real_ns();
	journal->jops->add_record(journal, &j_record);
    }

    if (this->cur_leaf.nr_record > 0) {
        bit_node_encode(leaf_node, this->bit_key, NULL);
        memcpy(this->buffer + cur, leaf_node, BIT_LEAF_NODE_SIZE);

	j_record.bit_node.is_leaf = true;
	j_record.bit_node.is_done = false;
	j_record.bit_node.pos = pos;
	memcpy(j_record.bit_node.key, this->bit_key, AES_GCM_KEY_SIZE);
	memcpy(j_record.bit_node.mac, leaf_node->mac, AES_GCM_AUTH_SIZE);
	j_record.bit_node.timestamp = ktime_get_real_ns();
	journal->jops->add_record(journal, &j_record);
    }

exit:
    if (leaf_node)
        kfree(leaf_node);
    if (inner_node)
        kfree(inner_node);

    kernel_write(this->file, this->buffer, this->cur, &addr);
    root = this->begin + this->cur - BIT_INNER_NODE_SIZE;
    filter_begin = addr = root + BIT_INNER_NODE_SIZE;
    kernel_write(this->file, this->filter->bits, this->filter->size, &addr);

    start = catalogue->start + this->id * catalogue->file_size;
    end = start + catalogue->file_size;
    vfs_fsync_range(this->file, start, end, 0);
    j_record.bit_node.is_done = true;
    j_record.bit_node.timestamp = ktime_get_real_ns();
    journal->jops->add_record(journal, &j_record);

    return bit_file_create(this->file, root, this->id, this->level, this->version, this->first_key, this->last_key,
        this->bit_key, NULL, filter_begin);
}

void bit_builder_destroy(struct lsm_file_builder* builder) {
    struct bit_builder* this = container_of(builder, struct bit_builder, lsm_file_builder);
    
    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->ctx))
            kfree(this->ctx);
        if (!IS_ERR_OR_NULL(this->buffer))
            vfree(this->buffer);
        if (!IS_ERR_OR_NULL(this->filter))
            bloom_filter_destroy(this->filter);
        kfree(this);
    }
}


struct bloom_filter* bit_bloom_filter_create(void) {
    struct bloom_filter* filter = 
        bloom_filter_create(BIT_BLOOM_FILTER_SIZE);

    if (!filter)
        return NULL;
    bloom_filter_add_hash(filter, djb2);
    bloom_filter_add_hash(filter, jenkins);
    bloom_filter_add_hash(filter, shash);
    return filter;
}

int bit_builder_init(struct bit_builder* this, struct file* file, size_t begin, size_t id, size_t level, size_t version) {
    int err = 0;
    
    this->file = file;
    this->begin = begin;
    this->cur = 0;
    this->id = id;
    this->level = level;
    this->version = version;
    this->has_first_key = false;
    this->height = __bit_height(DEFAULT_LSM_FILE_CAPACITY, DEFAULT_BIT_DEGREE);
    this->filter = bit_bloom_filter_create();

    get_random_bytes(this->bit_key, AES_GCM_KEY_SIZE);
    this->buffer = vmalloc(DEFAULT_LSM_FILE_BUILDER_BUFFER_SIZE);
    if (!this->buffer) {
        err = -ENOMEM;
        goto bad;
    }

    this->ctx = kzalloc(this->height * sizeof(struct bit_builder_context), GFP_KERNEL);
    if (!this->ctx) {
        err = -ENOMEM;
        goto bad;
    }

    this->lsm_file_builder.size = 0;
    this->lsm_file_builder.add_entry = bit_builder_add_entry;
    this->lsm_file_builder.complete = bit_builder_complete;
    this->lsm_file_builder.destroy = bit_builder_destroy;

    return 0;
bad:
    if (this->buffer)
        vfree(this->buffer);
    if (this->ctx)
        kfree(this->ctx);
    if (this->filter)
        bloom_filter_destroy(this->filter);
    return err;
}

struct lsm_file_builder* bit_builder_create(struct file* file, size_t begin, size_t id, size_t level, size_t version) {
    int err = 0;
    struct bit_builder* this = NULL;

    this = kzalloc(sizeof(struct bit_builder), GFP_KERNEL);
    if (!this)
        goto bad;
    
    err = bit_builder_init(this, file, begin, id, level, version);
    if (err)
        goto bad;
    
    return &this->lsm_file_builder;
bad:
    if (this)
        kfree(this);
    return NULL;
}

// block index table file implementation
struct entry __entry(memtable_key_t key, void* val) {
    struct entry entry = {
        .key = key,
        .val = val
    };

    return entry;
}

int bit_leaf_search(struct bit_leaf* leaf, uint32_t key, struct record* record) {
    size_t i;

    for (i = 0; i < leaf->nr_record; ++i) {
        if (leaf->keys[i] == key) {
            *record = leaf->records[i];
            return 0;
        }
    }

    return -ENODATA;
}

uint32_t bit_leaf_range_search(struct bit_leaf *leaf, uint32_t start, uint32_t end,
			       struct memtable *results)
{
	int err, i;
	struct record *valid;

//	DMINFO("bit_leaf_range_search first_key:%d last_key:%d start:%d end:%d\n", leaf->keys[0], leaf->keys[leaf->nr_record - 1], start, end);
	for (i = 0; i < leaf->nr_record; i++) {
		if (leaf->keys[i] >= start && leaf->keys[i] <= end) {
			err = results->get(results, leaf->keys[i], (void **)&valid);
			if (!err)
				continue;
			results->put(results, leaf->keys[i], record_copy(&leaf->records[i]),
				     record_destroy);
		}
	}
	if (leaf->keys[leaf->nr_record] <= end)
		return leaf->keys[leaf->nr_record - 1] + 1;
	else
		return end + 1;
}

int bit_file_search_leaf(struct bit_file* this, uint32_t key, struct bit_leaf* leaf) {
    int err = 0;
    size_t i;
    bool is_leaf = false;
    loff_t addr;
    struct bit_node bit_node;

    addr = this->root;
next:
    kernel_read(this->file, &bit_node, sizeof(struct bit_node), &addr);
    err = bit_node_decode((char*)&bit_node, is_leaf, this->root_key, NULL);
    if (err) 
        return -ENODATA;

    if (is_leaf) {
        struct record record;

        err = bit_leaf_search(&bit_node.leaf, key, &record);
        if (!err) {
            *leaf = bit_node.leaf;
            return 0;
        }

        return -ENODATA;
    }

    for (i = 0; i < bit_node.inner.nr_child; ++i) {
        if (key <= bit_node.inner.children[i].key) {
            is_leaf = bit_node.inner.children[i].is_leaf;
            addr = bit_node.inner.children[i].pos;
            goto next;
        }
    }

    return -ENODATA;
}

int bit_file_first_leaf(struct bit_file* this, struct bit_leaf* leaf) {
    return bit_file_search_leaf(this, this->first_key, leaf);
}

int bit_file_search(struct lsm_file* lsm_file, uint32_t key, void* val) {
    int err = 0;
    struct bit_leaf leaf;
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    if (!bloom_filter_contains(this->filter, &key, sizeof(uint32_t)))
        return -ENODATA;

    down_read(&this->lock);
    err = bit_leaf_search(&this->cached_leaf, key, val);
    up_read(&this->lock);
    if (!err) 
        return 0;

    err = bit_file_search_leaf(this, key, &leaf);
    if (err)
        return err;

    down_write(&this->lock);
    this->cached_leaf = leaf;
    up_write(&this->lock);
    return bit_leaf_search(&leaf, key, val);
}

uint32_t bit_file_range_search(struct lsm_file *lsm_file, uint32_t start,
			       uint32_t end, struct memtable *results)
{
	int err = 0;
	uint32_t key;
	struct bit_leaf leaf;
	struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

	if (start > this->last_key || end < this->first_key)
		return start;

	if (end > this->last_key)
		end = this->last_key;

//	DMINFO("bit_file_range_search id:%ld level:%ld first_key:%d last_key:%d start:%d end:%d\n", this->lsm_file.id, this->lsm_file.level, this->first_key, this->last_key, start, end);
	for (key = start; key <= end;) {
		if (!bloom_filter_contains(this->filter, &key, sizeof(uint32_t))) {
			key += 1;
			continue;
		}
		err = bit_file_search_leaf(this, key, &leaf);
		if (err) {
			key += 1;
			continue;
		}
		key = bit_leaf_range_search(&leaf, key, end, results);
	}
	if (start < this->first_key)
		return start;
	else
		return key;
}

// block index table iterator implementation
struct bit_iterator {
    struct iterator iterator;

    size_t cur_record;
    bool has_next;
    struct bit_file* bit_file;
    struct bit_leaf leaf;
};

bool bit_iterator_has_next(struct iterator* iter) {
    struct bit_iterator* this = container_of(iter, struct bit_iterator, iterator);

    return this->has_next;
}

int bit_iterator_next(struct iterator* iter, void* data) {
    loff_t pos;
    uint32_t key;
    struct record record;
    struct bit_node bit_node;
    struct bit_iterator* this = container_of(iter, struct bit_iterator, iterator);

    if (!iter->has_next(iter))
        return -ENODATA;

    key = this->leaf.keys[this->cur_record];
    record = this->leaf.records[this->cur_record];
    *(struct entry*)data = __entry(key, record_copy(&record));
    if (key >= this->bit_file->last_key) {
        this->has_next = false;
        return 0;
    }

    this->cur_record += 1;
    if (this->cur_record == BIT_LEAF_LEN) {
        pos = this->leaf.next_pos;
        kernel_read(this->bit_file->file, &bit_node, sizeof(struct bit_node), &pos);
        bit_node_decode((char*)&bit_node, true, this->bit_file->root_key, NULL);
        this->leaf = bit_node.leaf;
        this->cur_record = 0;
    }
    return 0;
}

void bit_iterator_destroy(struct iterator* iter) {
    struct bit_iterator* this = container_of(iter, struct bit_iterator, iterator);

    if (!IS_ERR_OR_NULL(this)) 
        kfree(this);
}


int bit_iterator_init(struct bit_iterator* this, struct bit_file* bit_file, void* private) {
    int err = 0;

    this->cur_record = 0;
    this->has_next = true;
    this->bit_file = bit_file;
    err = bit_file_first_leaf(this->bit_file, &this->leaf);
//    DMINFO("bit_iterator_init first_key:%d last_key:%d root:%lld\n", bit_file->first_key, bit_file->last_key, bit_file->root);
    if (err) {
        DMERR("bit_iterator_init find first leaf error");
        return err;
    }
       

    this->iterator.private = private;
    this->iterator.has_next = bit_iterator_has_next;
    this->iterator.next = bit_iterator_next;
    this->iterator.destroy = bit_iterator_destroy;
    
    return 0;
}

struct iterator* bit_iterator_create(struct bit_file* bit_file, void* private) {
    int err = 0;
    struct bit_iterator* this;

    this = kmalloc(sizeof(struct bit_iterator), GFP_KERNEL);
    if (!this) 
        goto bad;

    err = bit_iterator_init(this, bit_file, private);
    if (err)
        goto bad;

    return &this->iterator;
bad:
    if (this)
        kfree(this);
    return NULL;
}

struct iterator* bit_file_iterator(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    return bit_iterator_create(this, lsm_file);
}

uint32_t bit_file_get_first_key(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    return this->first_key;
}

uint32_t bit_file_get_last_key(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    return this->last_key;
}

struct file_stat bit_file_get_stats(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);
    struct file_stat stats = {
        .root = this->root,
        .first_key = this->first_key,
        .last_key = this->last_key,
        .id = this->lsm_file.id,
        .level = this->lsm_file.level,
        .version = this->lsm_file.version,
        .filter_begin = this->filter_begin
    };
    
    memcpy(stats.root_key, this->root_key, AES_GCM_KEY_SIZE);
    return stats;
}

void bit_file_destroy(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->filter))
            bloom_filter_destroy(this->filter);
        kfree(this);
    }
}

int bit_file_init(struct bit_file* this, struct file* file, loff_t root, size_t id, size_t level, size_t version, uint32_t first_key, uint32_t last_key, char* root_key, char* root_iv, loff_t filter_begin) {
    int err = 0;
    
    this->file = file;
    this->root = root;
    this->first_key = first_key;
    this->last_key = last_key;
    memcpy(this->root_key, root_key, AES_GCM_KEY_SIZE);
    init_rwsem(&this->lock);
    this->cached_leaf.nr_record = 0;
    this->filter_begin = filter_begin;
    this->filter = bit_bloom_filter_create();
    bloom_filter_load(this->filter, file, filter_begin);

    this->lsm_file.id = id;
    this->lsm_file.level = level;
    this->lsm_file.version = version;
    this->lsm_file.search = bit_file_search;
    this->lsm_file.iterator = bit_file_iterator;
    this->lsm_file.get_first_key = bit_file_get_first_key;
    this->lsm_file.get_last_key = bit_file_get_last_key;
    this->lsm_file.get_stats = bit_file_get_stats;
    this->lsm_file.destroy = bit_file_destroy;
    return err;
}

struct lsm_file* bit_file_create(struct file* file, loff_t root, size_t id, size_t level, size_t version, uint32_t first_key, uint32_t last_key, char* root_key, char* root_iv, loff_t filter_begin) {
    int err = 0;
    struct bit_file* this = NULL;

    this = kmalloc(sizeof(struct bit_file), GFP_KERNEL);
    if (!this) {
        err = -ENOMEM;
        goto bad;
    }

    err = bit_file_init(this, file, root, id, level, version, first_key, last_key, root_key, root_iv, filter_begin);
    if (err) {
        err = -EAGAIN;
        goto bad;
    }

    return &this->lsm_file;
bad:
    if (this)
        kfree(this);
    return NULL;
}

// block index table level implementaion
bool bit_level_is_full(struct lsm_level* lsm_level) {
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

//    DMINFO("is_full level: %ld, size: %ld, capacity: %ld", lsm_level->level, this->size, this->capacity);
    return this->size >= this->capacity;
}

int64_t bit_file_cmp(struct bit_file* file1, struct bit_file* file2) {
    if (file1->first_key == file2->first_key) 
        return (int64_t)(file1->last_key) - (int64_t)(file2->last_key);

    return (int64_t)(file1->first_key) - (int64_t)(file2->first_key);
}

size_t bit_level_search_file(struct bit_level* this, struct bit_file* file) {
    size_t low = 0, high = this->size - 1, mid;

    if (!this->size)
        return 0;

    if (bit_file_cmp(this->bit_files[low], file) >= 0)
        return low;

    if (bit_file_cmp(this->bit_files[high], file) <= 0)
        return high + 1;

    while (low < high) {
        mid = low + ((high - low) >> 1);
        if (bit_file_cmp(this->bit_files[mid], file) < 0)
            low = mid + 1;
        else 
            high = mid;
    }

    return low;
}

int bit_file_cmp_key(const void* p_key, const void* p_file) {
    uint32_t key = *(uint32_t*)p_key;
    const struct bit_file* file = *(struct bit_file**)p_file;

    if (key >= file->first_key && key <= file->last_key)
        return 0;
    
    if (key < file->first_key)
        return -1;

    return 1;
}

struct bit_file** bit_level_locate_file_pointer(struct bit_level* this, uint32_t key) {
    return bsearch(&key, this->bit_files, this->size, sizeof(struct bit_file*), bit_file_cmp_key);
}

struct bit_file* bit_level_locate_file(struct bit_level* this, uint32_t key) {
    struct bit_file** result = bit_level_locate_file_pointer(this, key);
    
    if (!result)
        return NULL;
    return *(struct bit_file**)result;
}

int bit_level_add_file(struct lsm_level* lsm_level, struct lsm_file* file) {
    size_t pos;
    struct bit_file* bit_file = container_of(file, struct bit_file, lsm_file);
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    if (this->size >= this->max_size)
        return -ENOSPC;
    pos = bit_level_search_file(this, bit_file);

//    DMINFO("add file, level: %ld, id: %ld, first key: %u, last key: %u, pos: %ld root:%lld\n", lsm_level->level, file->id, file->get_first_key(file), file->get_last_key(file), pos, bit_file->root);

    if (pos + 1 < this->max_size)
        memmove(this->bit_files + pos + 1, this->bit_files + pos, (this->size - pos) * sizeof(struct bit_file*));
    this->bit_files[pos] = bit_file;
    this->size += 1;
    return 0;
}

int bit_level_linear_search(struct bit_level* this, uint32_t key, void* val) {
    int err = 0;
    bool found = false;
    size_t i, cur_version = 0;

    for (i = 0; i < this->size; ++i) {
        if (this->bit_files[i]->lsm_file.version < cur_version)
            continue;
        err = bit_file_search(&this->bit_files[i]->lsm_file, key, val);
        if (!err) {
            found = true;
            cur_version = this->bit_files[i]->lsm_file.version;
        }
    }
    
    return found ? 0 : -ENODATA;
}

int bit_level_search(struct lsm_level* lsm_level, uint32_t key, void* val) {
    struct bit_file* file;
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    if (lsm_level->level == 0) 
        return bit_level_linear_search(this, key, val);

    file = bit_level_locate_file(this, key);
    if (!file)
        return -ENODATA;
    return bit_file_search(&file->lsm_file, key, val);
}

// return the start of next range_search
uint32_t bit_level_range_search(struct lsm_level *lsm_level, uint32_t start,
				uint32_t end, struct memtable *results)
{
	uint32_t key;
	struct bit_file *file;
	struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

	// FATAL: not work if there are multiple bit_files in level 0
	if (lsm_level->level == 0 && this->size > 0)
		return bit_file_range_search(&this->bit_files[0]->lsm_file, start, end, results);
	// search level 1
	for (key = start; key <= end;) {
		file = bit_level_locate_file(this, key);
		if (!file) {
			key += 1;
			continue;
		}
		key = bit_file_range_search(&file->lsm_file, key, end, results);
	}
	return key;
}

int bit_level_remove_file(struct lsm_level* lsm_level, size_t id) {
    size_t pos;
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

//    DMINFO("remove file, level: %ld, id: %ld", lsm_level->level, id);
    for (pos = 0; pos < this->size; ++pos) {
        if (this->bit_files[pos]->lsm_file.id == id) {
            memmove(this->bit_files + pos, this->bit_files + pos + 1, (this->size - pos - 1) * sizeof(struct bit_file*));
            this->size -= 1;
            return 0;
        }
    }

    return -EINVAL;
}

int bit_level_pick_demoted_files(struct lsm_level* lsm_level, struct list_head* demoted_files) {
    size_t i;
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    INIT_LIST_HEAD(demoted_files);
    if (!this->size) {
        DMERR("bit_level_pick_demoted_files has NOFILE\n");
        return -EINVAL;
    }

    if (this->lsm_level.level != 0) {
        list_add_tail(&this->bit_files[0]->lsm_file.node, demoted_files);
        return 0;
    }

    for (i = 0; i < this->size; ++i)
        list_add_tail(&this->bit_files[i]->lsm_file.node, demoted_files);
    return 0;
}
 
// should carefully check bit level has files
uint32_t bit_level_get_first_key(struct bit_level* this) {
    return this->bit_files[0]->first_key;
}

uint32_t bit_level_get_last_key(struct bit_level* this) {
    return this->bit_files[this->size - 1]->last_key;
}

// assume there are no intersections between files
int bit_level_lower_bound(struct bit_level* this, uint32_t key) {
    int low = 0, high = this->size - 1, mid;

    if (key < this->bit_files[low]->first_key)
        return 0;

    if (key > this->bit_files[high]->last_key)
        return high + 1;

    while (low < high) {
        mid = low + ((high - low) >> 1);
        if (key >= this->bit_files[mid]->first_key && key <= this->bit_files[mid]->last_key)
            return mid;
        if (key < this->bit_files[mid]->first_key)
            high = mid - 1;
        else 
            low = mid + 1;
    }

    return low;
}


int bit_level_find_relative_files(struct lsm_level* lsm_level, struct list_head* files, struct list_head* relatives) {
    size_t pos;
    struct lsm_file* file;
    uint32_t first_key = 0xffffffff, last_key = 0;
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    INIT_LIST_HEAD(relatives);
    if (!this->size)
        return 0;

    list_for_each_entry(file, files, node) {
        first_key = min(first_key, file->get_first_key(file));
        last_key = max(last_key, file->get_last_key(file));
    }

    if (last_key < bit_level_get_first_key(this) || first_key > bit_level_get_last_key(this)) 
        return 0;
    
    pos = bit_level_lower_bound(this, first_key);
    while(pos < this->size && this->bit_files[pos]->first_key <= last_key) {
        list_add_tail(&this->bit_files[pos]->lsm_file.node, relatives);
        pos += 1;
    }

    return 0;
}

struct lsm_file_builder* bit_level_get_builder(struct lsm_level* lsm_level, struct file* file, size_t begin, size_t id, size_t level, size_t version) {
    return bit_builder_create(file, begin, id, level, version);
}

void bit_level_destroy(struct lsm_level* lsm_level) {
    size_t i;
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    if (!IS_ERR_OR_NULL(this)) {
        for (i = 0; i < this->size; ++i)
            bit_file_destroy(&this->bit_files[i]->lsm_file);
        kfree(this);
    }
}

int bit_level_init(struct bit_level* this, size_t level, size_t capacity) {
    int err = 0;

    this->size = 0;
    this->max_size = 2 * capacity + DEFAULT_LSM_LEVEL0_NR_FILE;
    this->capacity = capacity;
    this->bit_files = kmalloc(this->max_size * sizeof(struct bit_file*), GFP_KERNEL);
    if (!this->bit_files) {
        err = -ENOMEM;
        goto bad;
    }

    this->lsm_level.level = level;
    this->lsm_level.is_full = bit_level_is_full;
    this->lsm_level.add_file = bit_level_add_file;
    this->lsm_level.remove_file = bit_level_remove_file;
    this->lsm_level.search = bit_level_search;
    this->lsm_level.pick_demoted_files = bit_level_pick_demoted_files;
    this->lsm_level.find_relative_files = bit_level_find_relative_files;
    this->lsm_level.get_builder = bit_level_get_builder;
    this->lsm_level.destroy = bit_level_destroy;

    return 0;
bad:
    if (this->bit_files)
        kfree(this->bit_files);
    return err;
}

struct lsm_level* bit_level_create(size_t level, size_t capacity) {
    int err = 0;
    struct bit_level* this = NULL;

    this = kzalloc(sizeof(struct bit_level), GFP_KERNEL);
    if (!this)
        goto bad;

    err = bit_level_init(this, level, capacity);
    if (err)
        goto bad;

    return &this->lsm_level;
bad:
    if (this)
        kfree(this);
    return NULL;
}

// compaction job implementation
struct kway_merge_node {
    struct iterator* iter;
    struct entry entry;
};

struct kway_merge_node __kway_merge_node(struct iterator* iter, struct entry entry) {
    struct kway_merge_node node = {
        .iter = iter,
        .entry = entry
    };
    return node;
}

bool kway_merge_node_less(const void *lhs, const void *rhs) {
    const struct kway_merge_node *node1 = lhs, *node2 = rhs;

    return node1->entry.key < node2->entry.key;
}

void kway_merge_node_swap(void *lhs, void *rhs) {
    struct kway_merge_node *node1 = lhs, *node2 = rhs, temp;

    temp = *node1;
    *node1 = *node2;
    *node2 = temp;
}

bool interval_overlapping(int64_t begin1, int64_t end1, int64_t begin2, int64_t end2) {
    return !(end1 < begin2 || begin1 > end2);
}

bool lsm_file_overlapping(struct list_head* files) {
    struct lsm_file *f1, *f2;

    list_for_each_entry(f1, files, node) {
        list_for_each_entry(f2, files, node) {
            int64_t begin1 = f1->get_first_key(f1);
            int64_t end1 = f1->get_last_key(f1);
            int64_t begin2 = f2->get_first_key(f2);
            int64_t end2 = f2->get_last_key(f2);

            if (f1->id == f2->id)
                continue;
            if (interval_overlapping(begin1, end1, begin2, end2))
                return true;
        }
    }

    return false;
}

int compaction_job_run(struct compaction_job* this) {
    int err = 0;
    size_t fd, version;
    struct min_heap heap = {
        .data = NULL,
        .nr = 0,
        .size = 0
    };
    struct min_heap_callbacks comparator = {
        .elem_size = sizeof(struct kway_merge_node),
        .less = kway_merge_node_less,
        .swp = kway_merge_node_swap
    };
    struct kway_merge_node kway_merge_node, distinct, first;
    struct entry entry;
    struct lsm_file *file;
    struct iterator *iter;
    struct list_head demoted_files, relative_files, iters;
    struct lsm_file_builder* builder = NULL;
    struct journal_region *journal = sworndisk->meta->journal;
    struct journal_record j_record;

    this->level1->pick_demoted_files(this->level1, &demoted_files);
    this->level2->find_relative_files(this->level2, &demoted_files, &relative_files);

    if (list_empty(&relative_files) && !lsm_file_overlapping(&demoted_files)) {
        list_for_each_entry(file, &demoted_files, node) {
            file->version = this->catalogue->get_next_version(this->catalogue);
            file->level = this->level2->level;
            this->catalogue->set_file_stats(this->catalogue, file->id, file->get_stats(file));
            this->level2->add_file(this->level2, file);
            this->level1->remove_file(this->level1, file->id);
        }
        return 0;
    }

    INIT_LIST_HEAD(&iters);
    list_for_each_entry(file, &demoted_files, node) {
        list_add(&file->iterator(file)->node, &iters);
	bitmap_set(j_record.bit_compaction.upper_bits, file->id, 1);
        heap.size += 1;
    }

    list_for_each_entry(file, &relative_files, node) {
        list_add(&file->iterator(file)->node, &iters);
	bitmap_set(j_record.bit_compaction.lower_bits, file->id, 1);
        heap.size += 1;
    }

    heap.data = kmalloc(heap.size * sizeof(struct kway_merge_node), GFP_KERNEL);
    if (!heap.data) {
        err = -ENOMEM;
        goto exit;
    }

    list_for_each_entry(iter, &iters, node) {
        if (iter->has_next(iter)) {
            iter->next(iter, &entry);
            kway_merge_node = __kway_merge_node(iter, entry);
            min_heap_push(&heap, &kway_merge_node, &comparator);
        }
    }

    distinct = *(struct kway_merge_node*)heap.data;
    this->catalogue->alloc_file(this->catalogue, &fd);
    version = this->catalogue->get_next_version(this->catalogue);
    builder = this->level2->get_builder(this->level2, this->file, this->catalogue->start + fd * this->catalogue->file_size, fd, this->level2->level, version);

    j_record.type = BIT_COMPACTION;
    j_record.bit_compaction.bit_id = fd;
    j_record.bit_compaction.level = this->level2->level;
    j_record.bit_compaction.version = version;
    j_record.bit_compaction.timestamp = ktime_get_real_ns();
    journal->jops->add_record(journal, &j_record);

    while (heap.nr > 0) {
        iter = ((struct kway_merge_node*)heap.data)->iter;
        first = *(struct kway_merge_node*)heap.data;
        min_heap_pop(&heap, &comparator);

        if (iter->has_next(iter)) {
            iter->next(iter, &entry);
            kway_merge_node = __kway_merge_node(iter, entry);
            min_heap_push(&heap, &kway_merge_node, &comparator);
        }

        if (distinct.entry.key == first.entry.key) {
            if (((struct lsm_file*)(distinct.iter->private))->version < ((struct lsm_file*)(first.iter->private))->version) {
                record_destroy(distinct.entry.val);
                distinct = first;
            } else if (((struct lsm_file*)(distinct.iter->private))->id != ((struct lsm_file*)(first.iter->private))->id) {
                record_destroy(first.entry.val);
            }
            continue;
        }
        
        builder->add_entry(builder, &distinct.entry);
        record_destroy(distinct.entry.val);
        distinct = first;

        if (builder->size >= DEFAULT_LSM_FILE_CAPACITY) {
            file = builder->complete(builder);
            this->catalogue->set_file_stats(this->catalogue, file->id, file->get_stats(file));
            this->level2->add_file(this->level2, file);

            this->catalogue->alloc_file(this->catalogue, &fd);

            builder->destroy(builder);
	    version = this->catalogue->get_next_version(this->catalogue);
	    builder = this->level2->get_builder(this->level2, this->file, this->catalogue->start + fd * this->catalogue->file_size, fd, this->level2->level, version);

	    j_record.bit_compaction.bit_id = fd;
	    j_record.bit_compaction.level = this->level2->level;
	    j_record.bit_compaction.version = version;
	    j_record.bit_compaction.timestamp = ktime_get_real_ns();
	    journal->jops->add_record(journal, &j_record);
        }
    }

    builder->add_entry(builder, &distinct.entry);
    record_destroy(distinct.entry.val);
    file = builder->complete(builder);
    this->catalogue->set_file_stats(this->catalogue, file->id, file->get_stats(file));
    this->level2->add_file(this->level2, file);

    list_for_each_entry(file, &demoted_files, node) {
        this->level1->remove_file(this->level1, file->id);
        this->catalogue->release_file(this->catalogue, file->id);
        file->destroy(file);
    }
    list_for_each_entry(file, &relative_files, node) {
        this->level2->remove_file(this->level2, file->id);
        this->catalogue->release_file(this->catalogue, file->id);
        file->destroy(file);
    }

exit:
    list_for_each_entry(iter, &iters, node) 
        iter->destroy(iter);
    if (heap.data)
        kfree(heap.data);
    if (builder)
        builder->destroy(builder);
    return err;   
}

void compaction_job_destroy(struct compaction_job* this) {
    if (!IS_ERR_OR_NULL(this))
        kfree(this);
}

int compaction_job_init(struct compaction_job* this, struct file* file, struct lsm_catalogue* catalogue, struct lsm_level* level1, struct lsm_level* level2) {
    this->file = file;
    this->catalogue = catalogue;
    this->level1 = level1;
    this->level2 = level2;
    this->run = compaction_job_run;
    this->destroy = compaction_job_destroy;
    return 0;
}

struct compaction_job* compaction_job_create(struct file* file, struct lsm_catalogue* catalogue, struct lsm_level* level1, struct lsm_level* level2) {
    int err = 0;
    struct compaction_job* this;

    this = kzalloc(sizeof(struct compaction_job), GFP_KERNEL);
    if (!this)
        goto bad;

    err = compaction_job_init(this, file, catalogue, level1, level2);
    if (err)
        goto bad;

    return this;
bad:
    if (this)
        kfree(this);
    return NULL;
}

// log-structured merge tree implementation
int lsm_tree_major_compaction(struct lsm_tree* this, size_t level) {
    int err = 0;
    struct compaction_job* job = NULL;

    if (this->levels[level + 1]->is_full(this->levels[level + 1]))
        lsm_tree_major_compaction(this, level + 1);

    job = compaction_job_create(this->file, this->catalogue, this->levels[level], this->levels[level + 1]);
    err = job->run(job);
    if (err)
        goto exit;
exit:
    if (job)
        job->destroy(job);
    return err;
}

int lsm_tree_minor_compaction(struct lsm_tree* this, struct memtable *memtable) {
    int err = 0;
    size_t fd, version;
    struct lsm_file* file;
    struct lsm_file_builder* builder;
    struct memtable_entry* entry;
    struct list_head entries;
    struct journal_region *journal = sworndisk->meta->journal;
    struct journal_record j_record;

//    DMINFO("minor_compaction memtable size:%d\n", memtable->size);
    if (this->levels[0]->is_full(this->levels[0]))
        lsm_tree_major_compaction(this, 0);

    memtable->get_all_entry(memtable, &entries);
    this->catalogue->alloc_file(this->catalogue, &fd);

    version = this->catalogue->get_next_version(this->catalogue);
    builder = this->levels[0]->get_builder(this->levels[0], this->file, this->catalogue->start + fd * this->catalogue->file_size, fd, 0, version);

    j_record.type = BIT_COMPACTION;
    j_record.bit_compaction.bit_id = fd;
    j_record.bit_compaction.level = 0;
    j_record.bit_compaction.version = version;
    j_record.bit_compaction.timestamp = ktime_get_real_ns();
    journal->jops->add_record(journal, &j_record);

    list_for_each_entry(entry, &entries, list) {
        builder->add_entry(builder, (struct entry*)entry);
    }

    file = builder->complete(builder);
    this->catalogue->set_file_stats(this->catalogue, file->id, file->get_stats(file));
    this->levels[0]->add_file(this->levels[0], file);

    if (builder)
        builder->destroy(builder);
    return err;
}

void minor_compaction_handler(struct work_struct *ws)
{
	struct compaction_work *cw = container_of(ws, struct compaction_work, work);
	struct lsm_tree *this = cw->data;

	down_read(&this->im_lock);
	lsm_tree_minor_compaction(this, this->immutable_memtable);
	up_read(&this->im_lock);
	kfree(cw);
}

int lsm_tree_search(struct lsm_tree* this, uint32_t key, void* val) {
    int err = 0;
    size_t i;
    struct record* record;

    // record = this->cache->get(this->cache, key);
    // if (record) {
    //     *(struct record*)val = *record;
    //     return 0;
    // }

    down_read(&this->m_lock);
    err = this->memtable->get(this->memtable, key, (void**)&record);
    up_read(&this->m_lock);
    if (!err) {
        *(struct record*)val = *record;
        // this->cache->put(this->cache, key, record_copy(record), record_destroy);
        return 0;
    }

    down_read(&this->im_lock);
    if (this->immutable_memtable) {
	err = this->immutable_memtable->get(this->immutable_memtable,
					    key, (void**)&record);
	up_read(&this->im_lock);
	if (!err) {
		*(struct record*)val = *record;
		return 0;
	}
    } else
	up_read(&this->im_lock);

    for (i = 0; i < this->catalogue->nr_disk_level; ++i) {
        err = this->levels[i]->search(this->levels[i], key, val);
        if (!err) {
            // this->cache->put(this->cache, key, record_copy(val), record_destroy);
            return 0;
        }   
    }
    return -ENODATA;
}

void lsm_tree_put(struct lsm_tree* this, uint32_t key, void* val) {
    struct record* record;
    struct compaction_work *cw;

    down_write(&this->m_lock);
    record = this->memtable->put(this->memtable, key, val, record_destroy);
    if (record)
        record_destroy(record);
    // this->cache->put(this->cache, key, record_copy(val), record_destroy);

    if (this->memtable->size >= DEFAULT_MEMTABLE_CAPACITY) {
        down_write(&this->im_lock);
        if (this->immutable_memtable)
            this->immutable_memtable->destroy(this->immutable_memtable);
        this->immutable_memtable = this->memtable;
        up_write(&this->im_lock);
        this->memtable = rbtree_memtable_create();

        cw = kzalloc(sizeof(struct compaction_work), GFP_KERNEL);
        cw->data = this;
        INIT_WORK(&cw->work, minor_compaction_handler);
        queue_work(compaction_wq, &cw->work);
    }
    up_write(&this->m_lock);
}

// search records for each lba in [start, end]
struct memtable *lsm_tree_range_search(struct lsm_tree *this, uint32_t start,
				       uint32_t end)
{
	int err, i;
	uint32_t key;
	struct record *valid;
	struct memtable *results = rbtree_memtable_create();

	if (start > end)
		goto out;

	for (key = start; key <= end; key++) {
		err = this->memtable->get(this->memtable, key, (void **)&valid);
		if (!err) {
			results->put(results, key, record_copy(valid), record_destroy);
			if (key == start)
				start = key + 1;
		}
	}
	if (start > end)
		goto out;

	down_read(&this->im_lock);
	if (this->immutable_memtable) {
		for (key = start; key <= end; key++) {
			err = results->get(results, key, (void **)&valid);
			if (!err)
				continue;

			err = this->immutable_memtable->get(this->immutable_memtable,
							    key, (void **)&valid);
			if (!err) {
				results->put(results, key, record_copy(valid),
					     record_destroy);
				if (key == start)
					start = key + 1;
			}
		}
		up_read(&this->im_lock);
	} else {
		up_read(&this->im_lock);
	}
	if (start > end)
		goto out;

	// bit_file range_search
	for (i = 0; i < this->catalogue->nr_disk_level; ++i) {
		start = bit_level_range_search(this->levels[i], start, end, results);
		if (start > end)
			goto out;
	}
out:
	if (results->size == 0) {
		results->destroy(results);
		results = NULL;
	}
	return results;
}

void lsm_tree_destroy(struct lsm_tree* this) {
    size_t i;

    if (compaction_wq)
        destroy_workqueue(compaction_wq);

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->memtable)) {
		if (this->immutable_memtable)
			this->immutable_memtable->destroy(this->immutable_memtable);
		if (this->memtable->size)
			lsm_tree_minor_compaction(this, this->memtable);
		this->memtable->destroy(this->memtable);
            // this->cache->destroy(this->cache);
        }  
        if (!IS_ERR_OR_NULL(this->levels)) {
            for (i = 0; i < this->catalogue->nr_disk_level; ++i)
                this->levels[i]->destroy(this->levels[i]);
        }
        if (this->file)
            filp_close(this->file, NULL);
        kfree(this);
    }
}

int lsm_tree_init(struct lsm_tree* this, const char* filename, struct lsm_catalogue* catalogue, struct aead_cipher* cipher) {
    int err = 0;
    size_t i, capacity;
    struct lsm_file* lsm_file;
    struct file_stat* stat;
    struct list_head file_stats;

    global_cipher = cipher;
    this->file = filp_open(filename, O_RDWR, 0);
    if (!this->file) {
        err = -EINVAL;
        goto bad;
    }
    compaction_wq = alloc_workqueue("kxdisk-compaction", WQ_UNBOUND, 1);
    if (!compaction_wq) {
        err = -EAGAIN;
        goto bad;
    }

    this->catalogue = catalogue;
    this->memtable = rbtree_memtable_create();
    this->immutable_memtable = NULL;
    init_rwsem(&this->m_lock);
    init_rwsem(&this->im_lock);
    this->levels = kzalloc(catalogue->nr_disk_level * sizeof(struct lsm_level*), GFP_KERNEL);
    if (!this->levels) {
        err = -ENOMEM;
        goto bad;
    }

    capacity = catalogue->max_level_nr_file;
    for (i = catalogue->nr_disk_level - 1; i >= 1; --i) {
        this->levels[i] = bit_level_create(i, capacity);
        capacity /= catalogue->common_ratio;
    }
    this->levels[0] = bit_level_create(0, DEFAULT_LSM_LEVEL0_NR_FILE);

    catalogue->get_all_file_stats(catalogue, &file_stats);
    list_for_each_entry(stat, &file_stats, node) {
//        DMINFO("load file, id: %ld, level: %ld, fist key: %u, last key: %u", stat->id, stat->level, stat->first_key, stat->last_key);
        lsm_file = bit_file_create(this->file, stat->root, stat->id, stat->level, stat->version, stat->first_key, stat->last_key,
            stat->root_key, stat->root_iv, stat->filter_begin);
        this->levels[stat->level]->add_file(this->levels[stat->level], lsm_file);
        kfree(stat);
    }

    // this->cache = lru_cache_create(DEFAULT_LSM_FILE_CAPACITY << 4);
    this->put = lsm_tree_put;
    this->search = lsm_tree_search;
    this->range_search = lsm_tree_range_search;
    this->destroy = lsm_tree_destroy;

    return 0;
bad:
    if (compaction_wq)
        destroy_workqueue(compaction_wq);
    if (this->file) 
        filp_close(this->file, NULL);
    if (this->levels) 
        kfree(this->levels);

    return err;
}

struct lsm_tree* lsm_tree_create(const char* filename, struct lsm_catalogue* catalogue, struct aead_cipher* cipher) {
    int err = 0;
    struct lsm_tree* this = NULL;

    this = kzalloc(sizeof(struct lsm_tree), GFP_KERNEL);
    if (!this) 
        goto bad;
    
    err = lsm_tree_init(this, filename, catalogue, cipher);
    if (err)
        goto bad;

    return this;
bad:
    if (this)
        kfree(this);
    return NULL;
}
