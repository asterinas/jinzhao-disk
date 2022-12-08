/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef DM_JINDISK_CACHE_H
#define DM_JINDISK_CACHE_H

#define MAX_LEAF_NODE_CACHED 128

struct lru_cache_node {
	uint64_t key;
	void *val;
	void (*dtr_fn)(void *);
	struct list_head list;
};

struct cache {
	int (*put)(struct cache *cache, uint64_t key, void *val,
		   void (*dtr_fn)(void *));
	void (*delete)(struct cache *cache, uint64_t key);
	void *(*get)(struct cache *cache, uint64_t key);
	void (*destroy)(struct cache *cache);
};

struct lru_cache {
	struct cache cache;

	struct mutex lock;
	size_t size, capacity;
	struct radix_tree_root root;
	struct list_head entries;
};

struct cache *lru_cache_create(size_t capacity);

#endif
