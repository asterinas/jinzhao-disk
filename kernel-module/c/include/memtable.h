/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef DM_JINDISK_MEMTABLE_H
#define DM_JINDISK_MEMTABLE_H

#include <linux/rbtree.h>
#include <linux/rwsem.h>

#define DEFAULT_MEMTABLE_CAPACITY DEFAULT_LSM_FILE_CAPACITY

typedef uint32_t memtable_key_t;
typedef void (*dtr_fn_t)(void *);

struct memtable_entry {
	memtable_key_t key;
	void *val;
	void *negative_val;
	struct list_head list;
	dtr_fn_t dtr_fn;
	struct rb_node rb;
};

struct memtable {
	size_t size;

	void *(*put)(struct memtable *memtable, memtable_key_t key, void *val,
		     dtr_fn_t dtr_fn);
	int (*get)(struct memtable *memtable, memtable_key_t key, void **p_val);
	int (*get_all_entry)(struct memtable *memtable,
			     struct list_head *entries);
	void *(*remove)(struct memtable *memtable, memtable_key_t key);
	bool (*contains)(struct memtable *memtable, memtable_key_t key);
	void (*clear)(struct memtable *memtable);
	void (*destroy)(struct memtable *memtable);
};

// rbtree memtable definition
struct rbtree_memtable {
	struct rb_root root;
	struct memtable memtable;
};

struct memtable *rbtree_memtable_create(void);

#endif
