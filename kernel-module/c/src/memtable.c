/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include <linux/random.h>
#include <linux/slab.h>
#include <linux/sort.h>

#include "../include/crypto.h"
#include "../include/dm_jindisk.h"
#include "../include/memtable.h"
#include "../include/lsm_tree.h"

// memtable record definition
void __copy_or_random(void *dst, void *src, size_t len)
{
	if (src == NULL) {
		get_random_bytes(dst, len);
		return;
	}
	memcpy(dst, src, len);
}

struct record *record_create(dm_block_t pba, char *key, char *mac)
{
	struct record *record;

	record = (struct record *)kzalloc(sizeof(struct record), GFP_KERNEL);
	if (!record) {
		DMERR("memtable value create alloc mem error\n");
		return NULL;
	}

	if (pba != INF_ADDR)
		__copy_or_random(record->key, key, AES_GCM_KEY_SIZE);
	if (mac)
		memcpy(record->mac, mac, AES_GCM_AUTH_SIZE);

	record->pba = pba;
	return record;
}

struct record *record_copy(struct record *old)
{
	struct record *new;

	if (!old)
		return NULL;

	new = kzalloc(sizeof(struct record), GFP_KERNEL);
	if (!new)
		return NULL;

	*new = *old;
	return new;
}

void record_destroy(void *p)
{
	struct record *record = p;

	if (record)
		kfree(record);
}

struct memtable_entry *new_memtable_entry(memtable_key_t key, void *val,
					  dtr_fn_t dtr_fn)
{
	struct memtable_entry *entry =
		kmalloc(sizeof(struct memtable_entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->key = key;
	entry->val = val;
	if (val == NULL)
		entry->negative_val = record_create(INF_ADDR, NULL, NULL);
	else
		entry->negative_val = NULL;
	entry->dtr_fn = dtr_fn;

	return entry;
}
void delete_memtable_entry(struct memtable_entry *entry)
{
	if (!entry)
		return;

	if (entry->dtr_fn) {
		entry->dtr_fn(entry->val);
		entry->dtr_fn(entry->negative_val);
	}
	kfree(entry);
}

int memtable_entry_cmp(struct memtable_entry *node,
		       struct memtable_entry *parent)
{
	return (int64_t)node->key - (int64_t)parent->key;
}

int memtable_entry_cmp_rb(struct rb_node *node, const struct rb_node *parent)
{
	struct memtable_entry *n = rb_entry(node, struct memtable_entry, rb);
	struct memtable_entry *p = rb_entry(parent, struct memtable_entry, rb);

	return memtable_entry_cmp(n, p);
}

int memtable_entry_cmp_rb_key(const void *key, const struct rb_node *node)
{
	struct memtable_entry *entry =
		rb_entry(node, struct memtable_entry, rb);

	return (int64_t)(*(int *)key) - (int64_t)(entry->key);
}

// rbtree memtable implementation
void *__rbtree_memtable_search(struct rb_root *root, memtable_key_t key)
{
	struct memtable_entry *cur;
	struct rb_node *node = root->rb_node; /* top of the tree */

	while (node) {
		cur = rb_entry(node, struct memtable_entry, rb);

		if (cur->key > key)
			node = node->rb_left;
		else if (cur->key < key)
			node = node->rb_right;
		else {
			if (cur->val)
				return cur->val;
			else
				return cur->negative_val;
		}
	}
	return NULL;
}

// negative record if val == NULL
void *rbtree_memtable_put(struct memtable *memtable, memtable_key_t key,
			  void *val, dtr_fn_t dtr_fn)
{
	void *old_val = NULL;
	struct rb_node *node = NULL;
	struct memtable_entry *old_entry = NULL, *new_entry = NULL;
	struct rbtree_memtable *this =
		container_of(memtable, struct rbtree_memtable, memtable);

	new_entry = new_memtable_entry(key, val, dtr_fn);
	if (!new_entry)
		return NULL;

	node = rb_find_add(&new_entry->rb, &this->root, memtable_entry_cmp_rb);
	if (node) {
		old_entry = rb_entry(node, struct memtable_entry, rb);
		if (val == NULL) {
			if (old_entry->val) {
				record_destroy(old_entry->val);
				memtable->size -= 1;
			}
			if (old_entry->negative_val) {
				record_destroy(old_entry->negative_val);
				memtable->size -= 1;
			}
			old_entry->val = NULL;
			old_entry->negative_val = new_entry->negative_val;
			new_entry->negative_val = NULL;
			old_val = NULL;
		} else {
			if (old_entry->val) {
				memtable->size -= 1;
			}
			old_val = old_entry->val;
			old_entry->val = new_entry->val;
			new_entry->val = NULL;
		}
		delete_memtable_entry(new_entry);
	}
	memtable->size += 1;
	return old_val;
}

int rbtree_memtable_get(struct memtable *memtable, memtable_key_t key,
			void **p_val)
{
	struct rbtree_memtable *this =
		container_of(memtable, struct rbtree_memtable, memtable);

	*p_val = __rbtree_memtable_search(&this->root, key);
	if (*p_val)
		return 0;
	else
		return -ENODATA;
}

void *rbtree_memtable_remove(struct memtable *memtable, memtable_key_t key)
{
	void *val;
	struct memtable_entry *entry;
	struct rb_node *node;
	struct rbtree_memtable *this =
		container_of(memtable, struct rbtree_memtable, memtable);

	node = rb_find(&key, &this->root, memtable_entry_cmp_rb_key);
	if (!node)
		return NULL;

	rb_erase(node, &this->root);
	entry = rb_entry(node, struct memtable_entry, rb);
	if (entry->val)
		memtable->size -= 1;
	if (entry->negative_val) {
		memtable->size -= 1;
		record_destroy(entry->negative_val);
	}
	val = entry->val;

	kfree(entry);
	return val;
}

bool rbtree_memtable_contains(struct memtable *memtable, memtable_key_t key)
{
	struct rbtree_memtable *this =
		container_of(memtable, struct rbtree_memtable, memtable);

	return __rbtree_memtable_search(&this->root, key);
}

int rbtree_memtable_get_all_entry(struct memtable *memtable,
				  struct list_head *entries)
{
	struct rb_node *node;
	struct rbtree_memtable *this =
		container_of(memtable, struct rbtree_memtable, memtable);

	INIT_LIST_HEAD(entries);
	for (node = rb_first(&this->root); node; node = rb_next(node)) {
		struct memtable_entry *entry =
			rb_entry(node, struct memtable_entry, rb);
		list_add_tail(&entry->list, entries);
	}
	return 0;
}

void rbtree_memtable_clear(struct memtable *memtable)
{
	struct memtable_entry *entry;
	struct rbtree_memtable *this =
		container_of(memtable, struct rbtree_memtable, memtable);

	while (!RB_EMPTY_ROOT(&this->root)) {
		entry = rb_entry(rb_first(&this->root), struct memtable_entry,
				 rb);
		rb_erase(&entry->rb, &this->root);
		delete_memtable_entry(entry);
	}
	memtable->size = 0;
}

void rbtree_memtable_destroy(struct memtable *memtable)
{
	struct rbtree_memtable *this =
		container_of(memtable, struct rbtree_memtable, memtable);

	rbtree_memtable_clear(memtable);
	kfree(this);
}

void rbtree_memtable_init(struct rbtree_memtable *this)
{
	this->root = RB_ROOT;
	// memtable
	this->memtable.size = 0;
	this->memtable.put = rbtree_memtable_put;
	this->memtable.get = rbtree_memtable_get;
	this->memtable.get_all_entry = rbtree_memtable_get_all_entry;
	this->memtable.contains = rbtree_memtable_contains;
	this->memtable.destroy = rbtree_memtable_destroy;
	this->memtable.remove = rbtree_memtable_remove;
	this->memtable.clear = rbtree_memtable_clear;
}

struct memtable *rbtree_memtable_create(void)
{
	struct rbtree_memtable *this = NULL;

	this = kmalloc(sizeof(struct rbtree_memtable), GFP_KERNEL);
	if (!this)
		return NULL;

	rbtree_memtable_init(this);
	return &this->memtable;
}
