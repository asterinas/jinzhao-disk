/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include <linux/bsearch.h>
#include <linux/mempool.h>
#include <linux/random.h>
#include <linux/slab.h>

#include "../include/dm_jindisk.h"
#include "../include/lsm_tree.h"
#include "../include/memtable.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"

struct compaction_work {
	struct work_struct work;
	void *data;
};
static struct workqueue_struct *compaction_wq;

static struct aead_cipher *global_cipher; // global cipher

// block index table node implementaion
void bit_node_print(struct bit_node *bit_node)
{
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

int bit_node_encode(struct bit_node *node, char *key, char *iv)
{
	char *mac = NULL;
	size_t data_len = BIT_INNER_NODE_SIZE - AES_GCM_AUTH_SIZE;

	if (node->is_leaf)
		data_len = BIT_LEAF_NODE_SIZE - AES_GCM_AUTH_SIZE;
	mac = ((char *)node) + data_len;

	return global_cipher->encrypt(global_cipher, (char *)node, data_len,
				      key, iv, mac, 0, (char *)node);
}

// we don't know whether the node is leaf when decrypting
int bit_node_decode(char *data, bool is_leaf, char *key, char *iv)
{
	int err = 0;
	char *mac = NULL;
	size_t len = BIT_INNER_NODE_SIZE - AES_GCM_AUTH_SIZE;

	if (is_leaf)
		len = BIT_LEAF_NODE_SIZE - AES_GCM_AUTH_SIZE;
	mac = data + len;
	err = global_cipher->decrypt(global_cipher, data, len, key, iv, mac, 0,
				     data);
	if (err)
		return err;

	memcpy(((struct bit_node *)data)->mac, mac, AES_GCM_AUTH_SIZE);
	return 0;
}

// block index table builder implementaion
size_t __bit_height(size_t nr_record, size_t nr_degree)
{
	uint32_t rem = 0;
	size_t height = 1, size = 1, nr_leaf;

	if (!nr_record)
		return 0;

	nr_leaf = div_u64_rem(nr_record, BIT_LEAF_LEN, &rem);
	if (rem)
		nr_leaf += 1;

	while (size < nr_leaf) {
		height += 1;
		size *= nr_degree;
	}
	return height;
}

size_t __bit_array_len(size_t nr_record, size_t nr_degree)
{
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

size_t calculate_bit_size(size_t nr_record, size_t nr_degree)
{
	uint32_t rem = 0;
	size_t nr_leaf;

	if (!nr_record)
		return 0;

	nr_leaf = div_u64_rem(nr_record, BIT_LEAF_LEN, &rem);
	if (rem)
		nr_leaf += 1;

	return (__bit_array_len(nr_record, nr_degree) - nr_leaf) *
		       BIT_INNER_NODE_SIZE +
	       nr_leaf * BIT_LEAF_NODE_SIZE;
}

void __bit_inner(struct bit_builder_context *ctx, struct bit_node *node)
{
	size_t i;

	node->is_leaf = false;
	node->inner.nr_child = ctx->nr;

	for (i = 0; i < ctx->nr; ++i) {
		node->inner.children[i].is_leaf = ctx->nodes[i].is_leaf;
		node->inner.children[i].key =
			ctx->nodes[i].is_leaf ?
				ctx->nodes[i]
					.leaf
					.keys[ctx->nodes[i].leaf.nr_record - 1] :
				ctx->nodes[i]
					.inner
					.children[ctx->nodes[i].inner.nr_child -
						  1]
					.key;
		node->inner.children[i].pos = ctx->pos[i];
	}
}

void bit_builder_buffer_flush_if_full(struct bit_builder *this)
{
	loff_t pos = this->begin;

	if (this->cur + this->height * sizeof(struct bit_node) >
	    DEFAULT_LSM_FILE_BUILDER_BUFFER_SIZE) {
		kernel_write(this->file, this->buffer, this->cur, &pos);
		this->begin += this->cur;
		this->cur = 0;
	}
}

int bit_builder_add_entry(struct lsm_file_builder *builder, struct entry *entry)
{
	struct bit_builder *this =
		container_of(builder, struct bit_builder, lsm_file_builder);
	struct bit_node *inner_node = NULL, *leaf_node = NULL;
	size_t h = 0, cur, nr_record = this->cur_leaf.nr_record;
	size_t pos = this->begin + this->cur;
#if ENABLE_JOURNAL
	struct journal_region *journal = jindisk->meta->journal;
	struct journal_record j_record;
#endif
	if (!this->has_first_key) {
		this->first_key = entry->key;
		this->has_first_key = true;
	}
	this->last_key = entry->key;
	this->lsm_file_builder.size += 1;

	DMDEBUG("bit_builder_add_entry id:%lu level:%lu version:%lu "
		"lba:%u pba:%llu",
		this->id, this->level, this->version, entry->key,
		((struct record *)entry->val)->pba);
	this->cur_leaf.keys[nr_record] = entry->key;
	this->cur_leaf.records[nr_record] = *(struct record *)entry->val;
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
#if ENABLE_JOURNAL
	j_record.type = BIT_NODE;
	j_record.bit_node.bit_id = this->id;
#endif
	this->ctx[h].nr += 1;
	while (this->ctx[h].nr == DEFAULT_BIT_DEGREE) {
		size_t *node_pos = &(this->ctx[h + 1].pos[this->ctx[h + 1].nr]);

		__bit_inner(&this->ctx[h], inner_node);
		this->ctx[h + 1].nodes[this->ctx[h + 1].nr] = *inner_node;
		*node_pos = this->begin + this->cur;
		DMDEBUG("encode inner_node pos:%lu", *node_pos);
		bit_node_encode(inner_node, this->bit_key, NULL);
		memcpy(this->buffer + this->cur, inner_node,
		       BIT_INNER_NODE_SIZE);
		this->cur += BIT_INNER_NODE_SIZE;

		this->ctx[h + 1].nr += 1;
		this->ctx[h].nr = 0;
		h += 1;
#if ENABLE_JOURNAL
		j_record.bit_node.is_leaf = false;
		j_record.bit_node.is_done = false;
		j_record.bit_node.pos = *node_pos;
		memcpy(j_record.bit_node.key, this->bit_key, AES_GCM_KEY_SIZE);
		memcpy(j_record.bit_node.mac, inner_node->mac,
		       AES_GCM_AUTH_SIZE);
		j_record.bit_node.timestamp = ktime_get_real_ns();
		journal->jops->add_record(journal, &j_record);
#endif
	}
	leaf_node->leaf.next_pos = this->begin + this->cur;
	DMDEBUG("encode leaf_node pos:%lu", pos);
	bit_node_encode(leaf_node, this->bit_key, NULL);
	memcpy(this->buffer + cur, leaf_node, BIT_LEAF_NODE_SIZE);
	this->cur_leaf.nr_record = 0;
#if ENABLE_JOURNAL
	j_record.bit_node.is_leaf = true;
	j_record.bit_node.is_done = false;
	j_record.bit_node.pos = pos;
	memcpy(j_record.bit_node.key, this->bit_key, AES_GCM_KEY_SIZE);
	memcpy(j_record.bit_node.mac, leaf_node->mac, AES_GCM_AUTH_SIZE);
	j_record.bit_node.timestamp = ktime_get_real_ns();
	journal->jops->add_record(journal, &j_record);
#endif
exit:
	if (leaf_node)
		kfree(leaf_node);
	if (inner_node)
		kfree(inner_node);
	return 0;
}

struct lsm_file *bit_builder_complete(struct lsm_file_builder *builder)
{
	struct bit_builder *this =
		container_of(builder, struct bit_builder, lsm_file_builder);
	size_t h = 0, cur;
	loff_t addr, root;
	struct bit_node *inner_node = NULL, *leaf_node = NULL;
	size_t pos = this->begin + this->cur;
#if ENABLE_JOURNAL
	size_t start, end;
	struct lsm_catalogue *catalogue = jindisk->lsm_tree->catalogue;
	struct journal_region *journal = jindisk->meta->journal;
	struct journal_record j_record;
#endif
	if (this->ctx[this->height - 1].nr)
		goto exit;

	bit_builder_buffer_flush_if_full(this);

	inner_node = kmalloc(sizeof(struct bit_node), GFP_KERNEL);
	leaf_node = kmalloc(sizeof(struct bit_node), GFP_KERNEL);
	leaf_node->is_leaf = true;
	leaf_node->leaf = this->cur_leaf;
	if (this->cur_leaf.nr_record > 0) {
		this->ctx[h].nodes[this->ctx[h].nr] = *leaf_node;
		this->ctx[h].pos[this->ctx[h].nr] = pos;
		this->ctx[h].nr += 1;
		cur = this->cur;
		this->cur += BIT_LEAF_NODE_SIZE;
	}
#if ENABLE_JOURNAL
	j_record.type = BIT_NODE;
	j_record.bit_node.bit_id = this->id;
#endif
	while (h < this->height - 1) {
		size_t *node_pos = &(this->ctx[h + 1].pos[this->ctx[h + 1].nr]);

		if (!this->ctx[h].nr) {
			h += 1;
			continue;
		}
		__bit_inner(&this->ctx[h], inner_node);
		this->ctx[h + 1].nodes[this->ctx[h + 1].nr] = *inner_node;
		*node_pos = this->begin + this->cur;
		DMDEBUG("encode inner_node pos:%lu", *node_pos);
		bit_node_encode(inner_node, this->bit_key, NULL);
		memcpy(this->buffer + this->cur, inner_node,
		       BIT_INNER_NODE_SIZE);
		this->cur += BIT_INNER_NODE_SIZE;

		this->ctx[h + 1].nr += 1;
		this->ctx[h].nr = 0;
		h += 1;
#if ENABLE_JOURNAL
		j_record.bit_node.is_leaf = false;
		j_record.bit_node.is_done = false;
		j_record.bit_node.pos = *node_pos;
		memcpy(j_record.bit_node.key, this->bit_key, AES_GCM_KEY_SIZE);
		memcpy(j_record.bit_node.mac, inner_node->mac,
		       AES_GCM_AUTH_SIZE);
		j_record.bit_node.timestamp = ktime_get_real_ns();
		journal->jops->add_record(journal, &j_record);
#endif
	}

	if (this->cur_leaf.nr_record > 0) {
		DMDEBUG("encode leaf_node pos:%lu", pos);
		bit_node_encode(leaf_node, this->bit_key, NULL);
		memcpy(this->buffer + cur, leaf_node, BIT_LEAF_NODE_SIZE);
#if ENABLE_JOURNAL
		j_record.bit_node.is_leaf = true;
		j_record.bit_node.is_done = false;
		j_record.bit_node.pos = pos;
		memcpy(j_record.bit_node.key, this->bit_key, AES_GCM_KEY_SIZE);
		memcpy(j_record.bit_node.mac, leaf_node->mac,
		       AES_GCM_AUTH_SIZE);
		j_record.bit_node.timestamp = ktime_get_real_ns();
		journal->jops->add_record(journal, &j_record);
#endif
	}
exit:
	if (leaf_node)
		kfree(leaf_node);
	if (inner_node)
		kfree(inner_node);

	addr = this->begin;
	kernel_write(this->file, this->buffer, this->cur, &addr);
	root = this->begin + this->cur - BIT_INNER_NODE_SIZE;
#if ENABLE_JOURNAL
	start = catalogue->start + this->id * catalogue->file_size;
	end = start + catalogue->file_size;
	vfs_fsync_range(this->file, start, end, 0);
	j_record.bit_node.is_done = true;
	j_record.bit_node.timestamp = ktime_get_real_ns();
	journal->jops->add_record(journal, &j_record);
#endif
	return bit_file_create(this->file, root, this->id, this->level,
			       this->version, this->first_key, this->last_key,
			       builder->size, this->bit_key, NULL);
}

void bit_builder_destroy(struct lsm_file_builder *builder)
{
	struct bit_builder *this =
		container_of(builder, struct bit_builder, lsm_file_builder);
	if (!IS_ERR_OR_NULL(this)) {
		if (!IS_ERR_OR_NULL(this->ctx))
			kfree(this->ctx);
		if (!IS_ERR_OR_NULL(this->buffer))
			vfree(this->buffer);
		kfree(this);
	}
}

int bit_builder_init(struct bit_builder *this, struct file *file, size_t begin,
		     size_t id, size_t level, size_t version)
{
	int err = 0;

	this->file = file;
	this->begin = begin;
	this->cur = 0;
	this->id = id;
	this->level = level;
	this->version = version;
	this->has_first_key = false;
	this->height =
		__bit_height(DEFAULT_LSM_FILE_CAPACITY, DEFAULT_BIT_DEGREE);

	get_random_bytes(this->bit_key, AES_GCM_KEY_SIZE);
	this->buffer = vmalloc(DEFAULT_LSM_FILE_BUILDER_BUFFER_SIZE);
	if (!this->buffer) {
		err = -ENOMEM;
		goto bad;
	}

	this->ctx = kzalloc(this->height * sizeof(struct bit_builder_context),
			    GFP_KERNEL);
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
	return err;
}

struct lsm_file_builder *bit_builder_create(struct file *file, size_t begin,
					    size_t id, size_t level,
					    size_t version)
{
	int err = 0;
	struct bit_builder *this = NULL;

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
struct entry __entry(memtable_key_t key, void *val)
{
	struct entry entry = { .key = key, .val = val };
	return entry;
}

int bit_leaf_search(struct bit_leaf *leaf, uint32_t key)
{
	size_t i;

	for (i = 0; i < leaf->nr_record; ++i) {
		if (leaf->keys[i] == key)
			return 0;
	}
	return -ENODATA;
}

void bit_file_build_cached_root(struct bit_file *this)
{
	loff_t addr;
	int i, err = 0;
	struct bit_node *bit_node =
		kzalloc(sizeof(struct bit_node), GFP_KERNEL);

	if (!bit_node) {
		DMERR("bit_file_build_cached_root kzalloc bit_node failed");
		return;
	}

	this->cached_root = kzalloc(sizeof(struct cached_inner), GFP_KERNEL);
	if (!this->cached_root) {
		DMERR("bit_file_build_cached_root kzalloc bit_inner failed");
		goto out;
	}

	addr = this->root;
	kernel_read(this->file, (char *)bit_node, BIT_INNER_NODE_SIZE, &addr);
	err = bit_node_decode((char *)bit_node, false, this->root_key, NULL);
	if (err) {
		DMERR("decode root_node failed id:%lu level:%lu version:%lu "
		      "root:%llu",
		      this->lsm_file.id, this->lsm_file.level,
		      this->lsm_file.version, this->root);
		kfree(this->cached_root);
		this->cached_root = NULL;
		goto out;
	}
	this->cached_root->nr_child = bit_node->inner.nr_child;
	for (i = 0; i < this->cached_root->nr_child; ++i)
		this->cached_root->children[i] = bit_node->inner.children[i];
	this->cached_root->child_nodes = kzalloc(
		this->cached_root->nr_child * sizeof(struct cached_inner),
		GFP_KERNEL);
	if (!this->cached_root->child_nodes) {
		DMERR("bit_file_build_cached_root kzalloc child_nodes failed");
		kfree(this->cached_root);
		this->cached_root = NULL;
		goto out;
	}

	for (i = 0; i < this->cached_root->nr_child; ++i) {
		struct cached_inner *inner =
			&(this->cached_root->child_nodes[i]);
		int j = 0;

		addr = this->cached_root->children[i].pos;
		kernel_read(this->file, (char *)bit_node, BIT_INNER_NODE_SIZE,
			    &addr);
		err = bit_node_decode((char *)bit_node, false, this->root_key,
				      NULL);
		if (err) {
			DMERR("decode inner_node failed id:%lu level:%lu "
			      "version:%lu pos:%llu",
			      this->lsm_file.id, this->lsm_file.level,
			      this->lsm_file.version, addr);
			break;
		}
		inner->nr_child = bit_node->inner.nr_child;
		inner->child_nodes = NULL;
		for (j = 0; j < inner->nr_child; ++j)
			inner->children[j] = bit_node->inner.children[j];
	}

	if (i != this->cached_root->nr_child) {
		kfree(this->cached_root->child_nodes);
		kfree(this->cached_root);
		this->cached_root = NULL;
	}
out:
	kfree(bit_node);
	return;
}

void bit_file_destroy_cached_root(struct bit_file *this)
{
	if (this->cached_root) {
		kfree(this->cached_root->child_nodes);
		kfree(this->cached_root);
	}
}

int bit_file_search_leaf_key_pos(struct bit_file *this, uint32_t key,
				 uint32_t *leaf_key, loff_t *leaf_pos)
{
	int i;
	struct cached_inner *inner;

	if (key < this->first_key || key > this->last_key)
		goto out;

	for (i = 0; i < this->cached_root->nr_child; ++i) {
		if (key <= this->cached_root->children[i].key)
			break;
	}
	inner = &(this->cached_root->child_nodes[i]);
	for (i = 0; i < inner->nr_child; ++i) {
		if (key <= inner->children[i].key) {
			*leaf_key = inner->children[i].key;
			*leaf_pos = inner->children[i].pos;
			return 0;
		}
	}
out:
	return -ENODATA;
}

int bit_file_search_leaf(struct bit_file *this, uint32_t key,
			 struct bit_leaf *leaf)
{
	int err = 0;
	uint32_t leaf_key;
	loff_t leaf_pos;
	struct bit_node *bit_node =
		kzalloc(sizeof(struct bit_node), GFP_KERNEL);

	if (!bit_node) {
		DMERR("bit_file_search_leaf kzalloc bit_node failed");
		return -ENOMEM;
	}
	err = bit_file_search_leaf_key_pos(this, key, &leaf_key, &leaf_pos);
	if (err)
		return err;

	kernel_read(this->file, (char *)bit_node, sizeof(struct bit_node),
		    &leaf_pos);
	err = bit_node_decode((char *)bit_node, true, this->root_key, NULL);
	if (err) {
		DMERR("bit_file_search_leaf decode leaf_node failed");
		goto out;
	}
	err = bit_leaf_search(&bit_node->leaf, key);
	if (!err)
		*leaf = bit_node->leaf;
out:
	kfree(bit_node);
	return err;
}

int bit_file_first_leaf(struct bit_file *this, struct bit_leaf *leaf)
{
	return bit_file_search_leaf(this, this->first_key, leaf);
}

struct record *bit_file_search_cached_leaf(struct bit_file *this, uint32_t key)
{
	int i, err;
	uint32_t leaf_key;
	loff_t leaf_pos;
	struct bit_leaf *leaf;

	err = bit_file_search_leaf_key_pos(this, key, &leaf_key, &leaf_pos);
	if (err)
		return NULL;

	leaf = this->cached_leaf->get(this->cached_leaf, leaf_key);
	if (!leaf) {
		disk_counter.bit_node_cache_miss += 1;
		return NULL;
	}

	disk_counter.bit_node_cache_hit += 1;
	for (i = 0; i < leaf->nr_record; ++i) {
		if (leaf->keys[i] == key) {
			return &(leaf->records[i]);
		}
	}
	return NULL;
}

void cached_leaf_destroy(void *p)
{
	struct bit_leaf *leaf = p;

	if (leaf)
		kfree(leaf);
}

int bit_file_search(struct lsm_file *lsm_file, uint32_t key, void *val)
{
	int err = 0, i;
	struct bit_leaf *leaf;
	struct record *record;
	struct bit_file *this =
		container_of(lsm_file, struct bit_file, lsm_file);

	leaf = kzalloc(sizeof(struct bit_leaf), GFP_KERNEL);
	if (!leaf) {
		DMERR("bit_file_search kzalloc bit_leaf failed");
		return -ENOMEM;
	}

	record = bit_file_search_cached_leaf(this, key);
	if (record) {
		DMDEBUG("bit_file_search cache found id:%lu level:%lu "
			"key:%u pba:%llu",
			lsm_file->id, lsm_file->level, key, record->pba);
		*(struct record *)val = *record;
		goto out;
	}
	err = bit_file_search_leaf(this, key, leaf);
	if (err)
		goto out;

	this->cached_leaf->put(this->cached_leaf,
			       leaf->keys[leaf->nr_record - 1], leaf,
			       cached_leaf_destroy);
	for (i = 0; i < leaf->nr_record; ++i) {
		if (leaf->keys[i] == key) {
			*(struct record *)val = leaf->records[i];
			break;
		}
	}
	return 0;
out:
	kfree(leaf);
	return err;
}

void bit_file_range_search(struct lsm_file *lsm_file, uint32_t start,
			   uint32_t end, struct memtable *results,
			   unsigned long *found)
{
	int err = 0, i;
	uint32_t key;
	struct record *record;
	struct bit_leaf *leaf;
	struct bit_file *this =
		container_of(lsm_file, struct bit_file, lsm_file);

	if (start > this->last_key || end < this->first_key)
		return;

	if (end > this->last_key)
		end = this->last_key;

	leaf = kzalloc(sizeof(struct bit_leaf), GFP_KERNEL);
	if (!leaf) {
		DMERR("bit_file_range_search kzalloc bit_leaf failed");
		return;
	}
	DMDEBUG("bit_file_range_search id:%lu level:%lu first_key:%u "
		"last_key:%u start:%u end:%u",
		lsm_file->id, lsm_file->level, this->first_key, this->last_key,
		start, end);
	for (key = start; key <= end; ++key) {
		if (key < this->first_key)
			key = this->first_key;

		if (test_bit(key - start, found))
			continue;

		record = bit_file_search_cached_leaf(this, key);
		if (record) {
			results->put(results, key, record_copy(record),
				     record_destroy);
			set_bit(key - start, found);
			continue;
		}

		if (!leaf)
			leaf = kzalloc(sizeof(struct bit_leaf), GFP_KERNEL);

		err = bit_file_search_leaf(this, key, leaf);
		if (err)
			continue;

		this->cached_leaf->put(this->cached_leaf,
				       leaf->keys[leaf->nr_record - 1], leaf,
				       cached_leaf_destroy);
		for (i = 0; i < leaf->nr_record; ++i) {
			if (leaf->keys[i] == key) {
				results->put(results, key,
					     record_copy(&leaf->records[i]),
					     record_destroy);
				set_bit(key - start, found);
			}
		}
		leaf = NULL;
	}
	if (leaf)
		kfree(leaf);
	return;
}

// block index table iterator implementation
struct bit_iterator {
	struct iterator iterator;

	size_t cur_record, count;
	bool has_next;
	struct bit_file *bit_file;
	struct bit_leaf leaf;
};

bool bit_iterator_has_next(struct iterator *iter)
{
	struct bit_iterator *this =
		container_of(iter, struct bit_iterator, iterator);
	return this->has_next;
}

int bit_iterator_next(struct iterator *iter, void *data)
{
	loff_t pos;
	uint32_t key;
	struct record record;
	struct bit_node *bit_node;
	struct bit_iterator *this =
		container_of(iter, struct bit_iterator, iterator);
	if (!iter->has_next(iter))
		return -ENODATA;

	bit_node = kzalloc(sizeof(struct bit_node), GFP_KERNEL);
	if (!bit_node) {
		DMERR("bit_iterator_next kzalloc bit_node failed");
		return -ENOMEM;
	}
	key = this->leaf.keys[this->cur_record];
	record = this->leaf.records[this->cur_record];
	*(struct entry *)data = __entry(key, record_copy(&record));
	this->count += 1;
	if (this->count >= this->bit_file->nr_record) {
		this->has_next = false;
		goto out;
	}

	this->cur_record += 1;
	if (this->cur_record == BIT_LEAF_LEN) {
		pos = this->leaf.next_pos;
		kernel_read(this->bit_file->file, (char *)bit_node,
			    sizeof(struct bit_node), &pos);
		bit_node_decode((char *)bit_node, true,
				this->bit_file->root_key, NULL);
		this->leaf = bit_node->leaf;
		this->cur_record = 0;
	}
out:
	kfree(bit_node);
	return 0;
}

void bit_iterator_destroy(struct iterator *iter)
{
	struct bit_iterator *this =
		container_of(iter, struct bit_iterator, iterator);
	if (!IS_ERR_OR_NULL(this))
		kfree(this);
}

int bit_iterator_init(struct bit_iterator *this, struct bit_file *bit_file,
		      void *private)
{
	int err = 0;

	this->cur_record = 0;
	this->count = 0;
	this->has_next = true;
	this->bit_file = bit_file;
	err = bit_file_first_leaf(this->bit_file, &this->leaf);
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

struct iterator *bit_iterator_create(struct bit_file *bit_file, void *private)
{
	int err = 0;
	struct bit_iterator *this;

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

struct iterator *bit_file_iterator(struct lsm_file *lsm_file)
{
	struct bit_file *this =
		container_of(lsm_file, struct bit_file, lsm_file);

	return bit_iterator_create(this, lsm_file);
}

uint32_t bit_file_get_first_key(struct lsm_file *lsm_file)
{
	struct bit_file *this =
		container_of(lsm_file, struct bit_file, lsm_file);

	return this->first_key;
}

uint32_t bit_file_get_last_key(struct lsm_file *lsm_file)
{
	struct bit_file *this =
		container_of(lsm_file, struct bit_file, lsm_file);

	return this->last_key;
}

struct file_stat bit_file_get_stats(struct lsm_file *lsm_file)
{
	struct bit_file *this =
		container_of(lsm_file, struct bit_file, lsm_file);
	struct file_stat stats = {
		.root = this->root,
		.first_key = this->first_key,
		.last_key = this->last_key,
		.nr_record = this->nr_record,
		.id = this->lsm_file.id,
		.level = this->lsm_file.level,
		.version = this->lsm_file.version,
	};
	memcpy(stats.root_key, this->root_key, AES_GCM_KEY_SIZE);
	return stats;
}

void bit_file_destroy(struct lsm_file *lsm_file)
{
	struct bit_file *this =
		container_of(lsm_file, struct bit_file, lsm_file);

	if (!IS_ERR_OR_NULL(this)) {
		if (this->cached_root)
			bit_file_destroy_cached_root(this);
		if (this->cached_leaf)
			this->cached_leaf->destroy(this->cached_leaf);
		kfree(this);
	}
}

int bit_file_init(struct bit_file *this, struct file *file, loff_t root,
		  size_t id, size_t level, size_t version, uint32_t first_key,
		  uint32_t last_key, uint32_t nr_record, char *root_key,
		  char *root_iv)
{
	this->file = file;
	this->root = root;
	this->first_key = first_key;
	this->last_key = last_key;
	this->nr_record = nr_record;
	memcpy(this->root_key, root_key, AES_GCM_KEY_SIZE);
	init_rwsem(&this->lock);
	this->cached_leaf = lru_cache_create(MAX_LEAF_NODE_CACHED);

	this->lsm_file.id = id;
	this->lsm_file.level = level;
	this->lsm_file.version = version;
	this->lsm_file.search = bit_file_search;
	this->lsm_file.iterator = bit_file_iterator;
	this->lsm_file.get_first_key = bit_file_get_first_key;
	this->lsm_file.get_last_key = bit_file_get_last_key;
	this->lsm_file.get_stats = bit_file_get_stats;
	this->lsm_file.destroy = bit_file_destroy;

	bit_file_build_cached_root(this);
	return 0;
}

struct lsm_file *bit_file_create(struct file *file, loff_t root, size_t id,
				 size_t level, size_t version,
				 uint32_t first_key, uint32_t last_key,
				 uint32_t nr_record, char *root_key,
				 char *root_iv)
{
	int err = 0;
	struct bit_file *this = NULL;

	DMDEBUG("bit_file_create id:%lu level:%lu version:%lu pos:%llu "
		"first_key:%u last_key:%u nr_record:%u",
		id, level, version, root, first_key, last_key, nr_record);
	this = kmalloc(sizeof(struct bit_file), GFP_KERNEL);
	if (!this) {
		err = -ENOMEM;
		goto bad;
	}
	err = bit_file_init(this, file, root, id, level, version, first_key,
			    last_key, nr_record, root_key, root_iv);
	if (err) {
		err = -EAGAIN;
		goto bad;
	}
	disk_counter.bit_created += 1;

	return &this->lsm_file;
bad:
	if (this)
		kfree(this);
	return NULL;
}

// block index table level implementaion
bool bit_level_is_full(struct lsm_level *lsm_level)
{
	struct bit_level *this =
		container_of(lsm_level, struct bit_level, lsm_level);
	DMDEBUG("level:%lu size:%lu capacity:%lu", lsm_level->level, this->size,
		this->capacity);
	return this->size >= this->capacity;
}

int64_t bit_file_cmp(struct bit_file *file1, struct bit_file *file2)
{
	if (file1->first_key == file2->first_key)
		return (int64_t)(file1->last_key) - (int64_t)(file2->last_key);

	return (int64_t)(file1->first_key) - (int64_t)(file2->first_key);
}

size_t bit_level_search_file(struct bit_level *this, struct bit_file *file)
{
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

int bit_file_cmp_key(const void *p_key, const void *p_file)
{
	uint32_t key = *(uint32_t *)p_key;
	const struct bit_file *file = *(struct bit_file **)p_file;

	if (key >= file->first_key && key <= file->last_key)
		return 0;
	if (key < file->first_key)
		return -1;
	return 1;
}

struct bit_file **bit_level_locate_file_pointer(struct bit_level *this,
						uint32_t key)
{
	return bsearch(&key, this->bit_files, this->size,
		       sizeof(struct bit_file *), bit_file_cmp_key);
}

struct bit_file *bit_level_locate_file(struct bit_level *this, uint32_t key)
{
	struct bit_file **result = bit_level_locate_file_pointer(this, key);

	if (!result)
		return NULL;
	return *(struct bit_file **)result;
}

int bit_level_add_file(struct lsm_level *lsm_level, struct lsm_file *file)
{
	size_t pos;
	struct bit_file *bit_file =
		container_of(file, struct bit_file, lsm_file);
	struct bit_level *this =
		container_of(lsm_level, struct bit_level, lsm_level);

	if (this->size >= this->max_size)
		return -ENOSPC;

	DMDEBUG("add bit_file id:%lu level:%lu version:%lu pos:%llu "
		"first_key:%u last_key:%u nr_record:%u",
		file->id, file->level, file->version, bit_file->root,
		bit_file->first_key, bit_file->last_key, bit_file->nr_record);
	down_write(&lsm_level->l_lock);
	pos = bit_level_search_file(this, bit_file);
	if (pos + 1 < this->max_size)
		memmove(this->bit_files + pos + 1, this->bit_files + pos,
			(this->size - pos) * sizeof(struct bit_file *));
	this->bit_files[pos] = bit_file;
	this->size += 1;
	up_write(&lsm_level->l_lock);
	return 0;
}

int bit_level_linear_search(struct bit_level *this, uint32_t key, void *val)
{
	int err = 0;
	bool found = false;
	size_t i, cur_version = 0;

	for (i = 0; i < this->size; ++i) {
		if (this->bit_files[i]->lsm_file.version < cur_version)
			continue;
		if (key < this->bit_files[i]->first_key ||
		    key > this->bit_files[i]->last_key)
			continue;

		err = bit_file_search(&this->bit_files[i]->lsm_file, key, val);
		if (!err) {
			found = true;
			cur_version = this->bit_files[i]->lsm_file.version;
		}
	}
	return found ? 0 : -ENODATA;
}

int bit_level_search(struct lsm_level *lsm_level, uint32_t key, void *val)
{
	int ret;
	struct bit_file *file;
	struct bit_level *this =
		container_of(lsm_level, struct bit_level, lsm_level);
	down_read(&lsm_level->l_lock);
	if (lsm_level->level == 0) {
		ret = bit_level_linear_search(this, key, val);
		goto out;
	}

	file = bit_level_locate_file(this, key);
	if (!file) {
		ret = -ENODATA;
		goto out;
	}
	ret = bit_file_search(&file->lsm_file, key, val);
out:
	up_read(&lsm_level->l_lock);
	return ret;
}

// return the start of next range_search
void bit_level_range_search(struct lsm_level *lsm_level, uint32_t start,
			    uint32_t end, struct memtable *results,
			    unsigned long *found)
{
	uint32_t key;
	struct bit_file *file;
	struct bit_level *this =
		container_of(lsm_level, struct bit_level, lsm_level);
	// FATAL: not work if there are multiple bit_files in level 0
	if (lsm_level->level == 0 && this->size > 0) {
		bit_file_range_search(&this->bit_files[0]->lsm_file, start, end,
				      results, found);
		return;
	}
	// search level 1
	for (key = start; key <= end; key++) {
		if (test_bit(key - start, found))
			continue;

		file = bit_level_locate_file(this, key);
		if (!file)
			continue;
		bit_file_range_search(&file->lsm_file, start, end, results,
				      found);
	}
	return;
}

int bit_level_remove_file(struct lsm_level *lsm_level, size_t id)
{
	size_t pos;
	struct bit_level *this =
		container_of(lsm_level, struct bit_level, lsm_level);
	down_write(&lsm_level->l_lock);
	for (pos = 0; pos < this->size; ++pos) {
		if (this->bit_files[pos]->lsm_file.id == id) {
			memmove(this->bit_files + pos,
				this->bit_files + pos + 1,
				(this->size - pos - 1) *
					sizeof(struct bit_file *));
			this->size -= 1;
			disk_counter.bit_removed += 1;
			DMDEBUG("remove bit_file id:%lu level:%lu version:%lu",
				id, this->bit_files[pos]->lsm_file.level,
				this->bit_files[pos]->lsm_file.version);
			up_write(&lsm_level->l_lock);
			return 0;
		}
	}
	up_write(&lsm_level->l_lock);
	return -EINVAL;
}

int bit_level_pick_demoted_files(struct lsm_level *lsm_level,
				 struct list_head *demoted_files)
{
	size_t i;
	struct bit_level *this =
		container_of(lsm_level, struct bit_level, lsm_level);
	INIT_LIST_HEAD(demoted_files);
	if (!this->size) {
		DMERR("bit_level_pick_demoted_files has NOFILE");
		return -EINVAL;
	}

	if (this->lsm_level.level != 0) {
		list_add_tail(&this->bit_files[0]->lsm_file.node,
			      demoted_files);
		return 0;
	}

	for (i = 0; i < this->size; ++i)
		list_add_tail(&this->bit_files[i]->lsm_file.node,
			      demoted_files);
	return 0;
}

// should carefully check bit level has files
uint32_t bit_level_get_first_key(struct bit_level *this)
{
	return this->bit_files[0]->first_key;
}

uint32_t bit_level_get_last_key(struct bit_level *this)
{
	return this->bit_files[this->size - 1]->last_key;
}

// assume there are no intersections between files
int bit_level_lower_bound(struct bit_level *this, uint32_t key)
{
	int low = 0, high = this->size - 1, mid;

	if (key < this->bit_files[low]->first_key)
		return 0;

	if (key > this->bit_files[high]->last_key)
		return high + 1;

	while (low < high) {
		mid = low + ((high - low) >> 1);
		if (key >= this->bit_files[mid]->first_key &&
		    key <= this->bit_files[mid]->last_key)
			return mid;
		if (key < this->bit_files[mid]->first_key)
			high = mid - 1;
		else
			low = mid + 1;
	}
	return low;
}

int bit_level_find_relative_files(struct lsm_level *lsm_level,
				  struct list_head *files,
				  struct list_head *relatives)
{
	size_t pos;
	struct lsm_file *file;
	uint32_t first_key = 0xffffffff, last_key = 0;
	struct bit_level *this =
		container_of(lsm_level, struct bit_level, lsm_level);
	INIT_LIST_HEAD(relatives);
	if (!this->size)
		return 0;

	list_for_each_entry (file, files, node) {
		first_key = min(first_key, file->get_first_key(file));
		last_key = max(last_key, file->get_last_key(file));
	}

	if (last_key < bit_level_get_first_key(this) ||
	    first_key > bit_level_get_last_key(this))
		return 0;

	pos = bit_level_lower_bound(this, first_key);
	while (pos < this->size &&
	       this->bit_files[pos]->first_key <= last_key) {
		list_add_tail(&this->bit_files[pos]->lsm_file.node, relatives);
		pos += 1;
	}
	return 0;
}

struct lsm_file_builder *bit_level_get_builder(struct lsm_level *lsm_level,
					       struct file *file, size_t begin,
					       size_t id, size_t level,
					       size_t version)
{
	return bit_builder_create(file, begin, id, level, version);
}

void bit_level_destroy(struct lsm_level *lsm_level)
{
	size_t i;
	struct bit_level *this =
		container_of(lsm_level, struct bit_level, lsm_level);
	if (!IS_ERR_OR_NULL(this)) {
		for (i = 0; i < this->size; ++i)
			bit_file_destroy(&this->bit_files[i]->lsm_file);
		kfree(this);
	}
}

int bit_level_init(struct bit_level *this, size_t level, size_t capacity)
{
	int err = 0;

	this->size = 0;
	this->max_size = 2 * capacity + DEFAULT_LSM_LEVEL0_NR_FILE;
	this->capacity = capacity;
	this->bit_files =
		kmalloc(this->max_size * sizeof(struct bit_file *), GFP_KERNEL);
	if (!this->bit_files) {
		err = -ENOMEM;
		goto bad;
	}
	this->lsm_level.level = level;
	init_rwsem(&this->lsm_level.l_lock);
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

struct lsm_level *bit_level_create(size_t level, size_t capacity)
{
	int err = 0;
	struct bit_level *this = NULL;

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
	struct iterator *iter;
	struct entry entry;
};

struct kway_merge_node __kway_merge_node(struct iterator *iter,
					 struct entry entry)
{
	struct kway_merge_node node = { .iter = iter, .entry = entry };
	return node;
}

bool kway_merge_node_less(const void *lhs, const void *rhs)
{
	const struct kway_merge_node *node1 = lhs, *node2 = rhs;

	return node1->entry.key < node2->entry.key;
}

void kway_merge_node_swap(void *lhs, void *rhs)
{
	struct kway_merge_node *node1 = lhs, *node2 = rhs, temp;

	temp = *node1;
	*node1 = *node2;
	*node2 = temp;
}

bool interval_overlapping(int64_t begin1, int64_t end1, int64_t begin2,
			  int64_t end2)
{
	return !(end1 < begin2 || begin1 > end2);
}

bool lsm_file_overlapping(struct list_head *files)
{
	struct lsm_file *f1, *f2;
	uint64_t begin1, end1, begin2, end2;

	list_for_each_entry (f1, files, node) {
		list_for_each_entry (f2, files, node) {
			begin1 = f1->get_first_key(f1);
			end1 = f1->get_last_key(f1);
			begin2 = f2->get_first_key(f2);
			end2 = f2->get_last_key(f2);

			if (f1->id == f2->id)
				continue;
			if (interval_overlapping(begin1, end1, begin2, end2))
				return true;
		}
	}
	return false;
}

static inline bool negative_record(struct record *val)
{
	return val->pba == INF_ADDR;
}

int compaction_job_run(struct compaction_job *this)
{
	int err = 0;
	size_t fd, version;
	struct min_heap heap = { .data = NULL, .nr = 0, .size = 0 };
	struct min_heap_callbacks comparator = {
		.elem_size = sizeof(struct kway_merge_node),
		.less = kway_merge_node_less,
		.swp = kway_merge_node_swap
	};
	struct kway_merge_node kway_merge_node, distinct, first;
	struct entry entry;
	struct lsm_file *file, *df, *ff;
	struct iterator *iter;
	struct list_head demoted_files, relative_files, iters;
	struct lsm_file_builder *builder = NULL;
	struct entry new, negative, old;
	dm_block_t pba, old_lba, new_lba;
#if ENABLE_JOURNAL
	struct journal_region *journal = jindisk->meta->journal;
	struct journal_record j_record;
#endif

	this->level1->pick_demoted_files(this->level1, &demoted_files);
	this->level2->find_relative_files(this->level2, &demoted_files,
					  &relative_files);

	if (list_empty(&relative_files) &&
	    !lsm_file_overlapping(&demoted_files)) {
		list_for_each_entry (file, &demoted_files, node) {
			file->version = this->catalogue->get_next_version(
				this->catalogue);
			file->level = this->level2->level;
			this->catalogue->set_file_stats(this->catalogue,
							file->id,
							file->get_stats(file));
			this->level2->add_file(this->level2, file);
			this->level1->remove_file(this->level1, file->id);
		}
		return 0;
	}

	INIT_LIST_HEAD(&iters);
	list_for_each_entry (file, &demoted_files, node) {
		list_add(&file->iterator(file)->node, &iters);
#if ENABLE_JOURNAL
		bitmap_set(j_record.bit_compaction.upper_bits, file->id, 1);
#endif
		heap.size += 1;
	}

	list_for_each_entry (file, &relative_files, node) {
		list_add(&file->iterator(file)->node, &iters);
#if ENABLE_JOURNAL
		bitmap_set(j_record.bit_compaction.lower_bits, file->id, 1);
#endif
		heap.size += 1;
	}

	heap.data =
		kmalloc(heap.size * sizeof(struct kway_merge_node), GFP_KERNEL);
	if (!heap.data) {
		err = -ENOMEM;
		goto exit;
	}
	list_for_each_entry (iter, &iters, node) {
		if (iter->has_next(iter)) {
			iter->next(iter, &entry);
			kway_merge_node = __kway_merge_node(iter, entry);
			min_heap_push(&heap, &kway_merge_node, &comparator);
		}
	}

	distinct = *(struct kway_merge_node *)heap.data;
	this->catalogue->alloc_file(this->catalogue, &fd);
	version = this->catalogue->get_next_version(this->catalogue);
	builder = this->level2->get_builder(
		this->level2, this->file,
		this->catalogue->start + fd * this->catalogue->file_size, fd,
		this->level2->level, version);
#if ENABLE_JOURNAL
	j_record.type = BIT_COMPACTION;
	j_record.bit_compaction.bit_id = fd;
	j_record.bit_compaction.level = this->level2->level;
	j_record.bit_compaction.version = version;
	j_record.bit_compaction.timestamp = ktime_get_real_ns();
	journal->jops->add_record(journal, &j_record);
#endif
	new.val = NULL;
	negative.val = NULL;
	old.val = NULL;
	while (heap.nr > 0) {
		iter = ((struct kway_merge_node *)heap.data)->iter;
		first = *(struct kway_merge_node *)heap.data;
		min_heap_pop(&heap, &comparator);

		if (iter->has_next(iter)) {
			iter->next(iter, &entry);
			kway_merge_node = __kway_merge_node(iter, entry);
			min_heap_push(&heap, &kway_merge_node, &comparator);
		}

		if (distinct.entry.key == first.entry.key) {
			df = (struct lsm_file *)distinct.iter->private;
			ff = (struct lsm_file *)first.iter->private;
			if (df->version < ff->version) {
				old = distinct.entry;
				distinct = first;
			} else if (df->id != ff->id) {
				old = first.entry;
			} else if (distinct.entry.val != first.entry.val) {
				new = distinct.entry;
				distinct = first;
			}
			continue;
		} else {
			if (negative_record(distinct.entry.val))
				negative = distinct.entry;
			else
				new = distinct.entry;
		}

		if (new.val) {
			builder->add_entry(builder, &new);
			record_destroy(new.val);
		}
		if (negative.val) {
			record_destroy(negative.val);
			record_destroy(old.val);
		} else if (old.val) {
			pba = ((struct record *)old.val)->pba;
			old_lba = old.key;
			jindisk->meta->rit->reset(jindisk->meta->rit, pba,
						  old_lba, &new_lba);
			if (old_lba == new_lba)
				jindisk->meta->dst->return_block(
					jindisk->meta->dst, pba);
			record_destroy(old.val);
		}
		new.val = NULL;
		negative.val = NULL;
		old.val = NULL;
		distinct = first;

		if (builder->size >= DEFAULT_LSM_FILE_CAPACITY) {
			file = builder->complete(builder);
			this->catalogue->set_file_stats(this->catalogue,
							file->id,
							file->get_stats(file));
			this->level2->add_file(this->level2, file);

			this->catalogue->alloc_file(this->catalogue, &fd);

			builder->destroy(builder);
			version = this->catalogue->get_next_version(
				this->catalogue);
			builder = this->level2->get_builder(
				this->level2, this->file,
				this->catalogue->start +
					fd * this->catalogue->file_size,
				fd, this->level2->level, version);
#if ENABLE_JOURNAL
			j_record.bit_compaction.bit_id = fd;
			j_record.bit_compaction.level = this->level2->level;
			j_record.bit_compaction.version = version;
			j_record.bit_compaction.timestamp = ktime_get_real_ns();
			journal->jops->add_record(journal, &j_record);
#endif
		}
	}

	if (negative_record(distinct.entry.val))
		negative = distinct.entry;
	else
		new = distinct.entry;

	if (new.val) {
		builder->add_entry(builder, &new);
		record_destroy(new.val);
	}
	if (negative.val) {
		record_destroy(negative.val);
		record_destroy(old.val);
	} else if (old.val) {
		pba = ((struct record *)old.val)->pba;
		old_lba = old.key;
		jindisk->meta->rit->reset(jindisk->meta->rit, pba, old_lba,
					  &new_lba);
		if (old_lba == new_lba)
			jindisk->meta->dst->return_block(jindisk->meta->dst,
							 pba);
		record_destroy(old.val);
	}

	file = builder->complete(builder);
	this->catalogue->set_file_stats(this->catalogue, file->id,
					file->get_stats(file));
	this->level2->add_file(this->level2, file);

	list_for_each_entry (file, &demoted_files, node) {
		this->level1->remove_file(this->level1, file->id);
		this->catalogue->release_file(this->catalogue, file->id);
		file->destroy(file);
	}
	list_for_each_entry (file, &relative_files, node) {
		this->level2->remove_file(this->level2, file->id);
		this->catalogue->release_file(this->catalogue, file->id);
		file->destroy(file);
	}
	disk_counter.major_compaction += 1;
exit:
	list_for_each_entry (iter, &iters, node)
		iter->destroy(iter);
	if (heap.data)
		kfree(heap.data);
	if (builder)
		builder->destroy(builder);
	return err;
}

void compaction_job_destroy(struct compaction_job *this)
{
	if (!IS_ERR_OR_NULL(this))
		kfree(this);
}

int compaction_job_init(struct compaction_job *this, struct file *file,
			struct lsm_catalogue *catalogue,
			struct lsm_level *level1, struct lsm_level *level2)
{
	this->file = file;
	this->catalogue = catalogue;
	this->level1 = level1;
	this->level2 = level2;
	this->run = compaction_job_run;
	this->destroy = compaction_job_destroy;
	return 0;
}

struct compaction_job *compaction_job_create(struct file *file,
					     struct lsm_catalogue *catalogue,
					     struct lsm_level *level1,
					     struct lsm_level *level2)
{
	int err = 0;
	struct compaction_job *this;

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
int lsm_tree_major_compaction(struct lsm_tree *this, size_t level)
{
	int err = 0;
	struct compaction_job *job = NULL;

	if (this->levels[level + 1]->is_full(this->levels[level + 1]))
		lsm_tree_major_compaction(this, level + 1);

	job = compaction_job_create(this->file, this->catalogue,
				    this->levels[level],
				    this->levels[level + 1]);
	if (!job) {
		DMERR("compaction_job_create failed");
		goto exit;
	}
	err = job->run(job);
exit:
	if (job)
		job->destroy(job);
	return err;
}

int lsm_tree_minor_compaction(struct lsm_tree *this, struct memtable *memtable)
{
	int err = 0;
	size_t fd, version;
	struct lsm_file *file;
	struct lsm_file_builder *builder;
	struct memtable_entry *ep;
	struct entry entry;
	struct list_head entries;
#if ENABLE_JOURNAL
	struct journal_region *journal = jindisk->meta->journal;
	struct journal_record j_record;
#endif
	DMDEBUG("minor_compaction memtable size:%lu", memtable->size);
	if (this->levels[0]->is_full(this->levels[0]))
		lsm_tree_major_compaction(this, 0);

	memtable->get_all_entry(memtable, &entries);
	this->catalogue->alloc_file(this->catalogue, &fd);

	version = this->catalogue->get_next_version(this->catalogue);
	builder = this->levels[0]->get_builder(
		this->levels[0], this->file,
		this->catalogue->start + fd * this->catalogue->file_size, fd, 0,
		version);
#if ENABLE_JOURNAL
	j_record.type = BIT_COMPACTION;
	j_record.bit_compaction.bit_id = fd;
	j_record.bit_compaction.level = 0;
	j_record.bit_compaction.version = version;
	j_record.bit_compaction.timestamp = ktime_get_real_ns();
	journal->jops->add_record(journal, &j_record);
#endif
	list_for_each_entry (ep, &entries, list) {
		entry.key = ep->key;
		if (ep->val) {
			entry.val = ep->val;
			builder->add_entry(builder, &entry);
		}
		if (ep->negative_val) {
			entry.val = ep->negative_val;
			builder->add_entry(builder, &entry);
		}
	}

	file = builder->complete(builder);
	this->catalogue->set_file_stats(this->catalogue, file->id,
					file->get_stats(file));
	this->levels[0]->add_file(this->levels[0], file);

	disk_counter.minor_compaction += 1;
	if (builder)
		builder->destroy(builder);
	return err;
}

void minor_compaction_handler(struct work_struct *ws)
{
	struct compaction_work *cw =
		container_of(ws, struct compaction_work, work);
	struct lsm_tree *this = cw->data;

	down_read(&this->im_lock);
	lsm_tree_minor_compaction(this, this->immutable_memtable);
	up_read(&this->im_lock);
	kfree(cw);
}

int lsm_tree_search(struct lsm_tree *this, uint32_t key, void *val)
{
	int err = 0;
	size_t i;
	struct record *record;

	down_read(&this->m_lock);
	err = this->memtable->get(this->memtable, key, (void **)&record);
	up_read(&this->m_lock);
	if (!err) {
		*(struct record *)val = *record;
		DMDEBUG("lsm_tree_search found in memtable lba:%u pba:%llu",
			key, record->pba);
		return 0;
	}

	down_read(&this->im_lock);
	if (this->immutable_memtable) {
		err = this->immutable_memtable->get(this->immutable_memtable,
						    key, (void **)&record);
		up_read(&this->im_lock);
		if (!err) {
			*(struct record *)val = *record;
			DMDEBUG("lsm_tree_search found in immutable_memtable "
				"lba:%u pba:%llu",
				key, record->pba);
			return 0;
		}
	} else
		up_read(&this->im_lock);

	for (i = 0; i < this->catalogue->nr_disk_level; ++i) {
		err = this->levels[i]->search(this->levels[i], key, val);
		if (!err) {
			DMDEBUG("lsm_tree_search found in bit lba:%u pba:%llu",
				key, ((struct record *)val)->pba);
			return 0;
		}
	}
	DMDEBUG("lsm_tree_search found nodata lba:%u", key);
	return -ENODATA;
}

void lsm_tree_put(struct lsm_tree *this, uint32_t key, void *val)
{
	dm_block_t old_lba, new_lba;
	struct record *old;
	struct compaction_work *cw;

#if defined(DEBUG)
	if (val)
		DMDEBUG("lsm_tree_put lba:%u pba:%llu", key,
			((struct record *)val)->pba);
	else
		DMDEBUG("lsm_tree_put lba:%u negative", key);
#endif
	down_write(&this->m_lock);
	old = this->memtable->put(this->memtable, key, val, record_destroy);
	if (old) {
		old_lba = key;
		jindisk->meta->rit->reset(jindisk->meta->rit, old->pba, old_lba,
					  &new_lba);
		if (old_lba == new_lba)
			jindisk->meta->dst->return_block(jindisk->meta->dst,
							 old->pba);
		record_destroy(old);
	}

	if (this->memtable->size >= DEFAULT_MEMTABLE_CAPACITY) {
		down_write(&this->im_lock);
		if (this->immutable_memtable)
			this->immutable_memtable->destroy(
				this->immutable_memtable);
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
	uint32_t key, count;
	struct record *valid;
	struct memtable *results = rbtree_memtable_create();
	unsigned long *found = NULL;

	if (start > end)
		goto out;

	DMDEBUG("lsm_tree_range_search [%u, %u]", start, end);
	count = end - start + 1;
	found = bitmap_zalloc(count, GFP_KERNEL);
	if (!found) {
		DMERR("lsm_tree_range_search bitmap_zalloc failed");
		goto out;
	}
	down_read(&this->m_lock);
	for (key = start; key <= end; key++) {
		err = this->memtable->get(this->memtable, key, (void **)&valid);
		if (!err) {
			results->put(results, key, record_copy(valid),
				     record_destroy);
			set_bit(key - start, found);
		}
	}
	up_read(&this->m_lock);
	if (results->size == count)
		goto out;

	down_read(&this->im_lock);
	if (this->immutable_memtable) {
		for (key = start; key <= end; key++) {
			if (test_bit(key - start, found))
				continue;

			err = this->immutable_memtable->get(
				this->immutable_memtable, key, (void **)&valid);
			if (!err) {
				results->put(results, key, record_copy(valid),
					     record_destroy);
				set_bit(key - start, found);
			}
		}
		up_read(&this->im_lock);
	} else {
		up_read(&this->im_lock);
	}
	if (results->size == count)
		goto out;

	// bit_file range_search
	for (i = 0; i < this->catalogue->nr_disk_level; ++i) {
		down_read(&this->levels[i]->l_lock);
		bit_level_range_search(this->levels[i], start, end, results,
				       found);
		up_read(&this->levels[i]->l_lock);
		if (results->size == count)
			goto out;
	}
out:
	if (found)
		kfree(found);
	if (results->size == 0) {
		results->destroy(results);
		results = NULL;
		DMDEBUG("lsm_tree_range_search found nodata [%u, %u]", start,
			end);
	}
	return results;
}

void lsm_tree_destroy(struct lsm_tree *this)
{
	size_t i;

	if (compaction_wq)
		destroy_workqueue(compaction_wq);

	if (!IS_ERR_OR_NULL(this)) {
		if (this->immutable_memtable)
			this->immutable_memtable->destroy(
				this->immutable_memtable);
		if (!IS_ERR_OR_NULL(this->memtable)) {
			if (this->memtable->size)
				lsm_tree_minor_compaction(this, this->memtable);
			this->memtable->destroy(this->memtable);
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

int lsm_tree_init(struct lsm_tree *this, const char *filename,
		  struct lsm_catalogue *catalogue, struct aead_cipher *cipher)
{
	int err = 0;
	size_t i, capacity;
	struct lsm_file *lsm_file;
	struct file_stat *stat;
	struct list_head file_stats;

	global_cipher = cipher;
	this->file = filp_open(filename, O_RDWR, 0);
	if (!this->file) {
		err = -EINVAL;
		goto bad;
	}
	compaction_wq = alloc_workqueue("jindisk-comp", WQ_UNBOUND, 1);
	if (!compaction_wq) {
		DMERR("alloc_workqueue jindisk-comp failed");
		err = -EAGAIN;
		goto bad;
	}

	this->catalogue = catalogue;
	this->memtable = rbtree_memtable_create();
	this->immutable_memtable = NULL;
	init_rwsem(&this->m_lock);
	init_rwsem(&this->im_lock);
	this->levels =
		kzalloc(catalogue->nr_disk_level * sizeof(struct lsm_level *),
			GFP_KERNEL);
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
	list_for_each_entry (stat, &file_stats, node) {
		lsm_file = bit_file_create(this->file, stat->root, stat->id,
					   stat->level, stat->version,
					   stat->first_key, stat->last_key,
					   stat->nr_record, stat->root_key,
					   stat->root_iv);

		this->levels[stat->level]->add_file(this->levels[stat->level],
						    lsm_file);
		kfree(stat);
	}

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

struct lsm_tree *lsm_tree_create(const char *filename,
				 struct lsm_catalogue *catalogue,
				 struct aead_cipher *cipher)
{
	int err = 0;
	struct lsm_tree *this = NULL;

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
