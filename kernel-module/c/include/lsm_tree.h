/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef DM_JINDISK_LSM_TREE_H
#define DM_JINDISK_LSM_TREE_H

#include <linux/fs.h>
#include <linux/list.h>

#include "cache.h"
#include "crypto.h"
#include "disk_structs.h"
#include "iterator.h"

#define DEFAULT_LSM_TREE_NR_DISK_LEVEL 2
#define DEFAULT_LSM_LEVEL0_NR_FILE 1
#define DEFAULT_LSM_FILE_CAPACITY (131072) // 512M/4K records

// record, lba => (pba, key, iv, mac)
struct record {
	dm_block_t pba; // physical block address
	char mac[AES_GCM_AUTH_SIZE];
	char key[AES_GCM_KEY_SIZE];
} __packed;

struct record *record_create(dm_block_t pba, char *key, char *mac);
struct record *record_copy(struct record *old);
void record_destroy(void *record);

#define DEFAULT_BIT_DEGREE 32
struct bit_child {
	bool is_leaf : 1;
	uint32_t key;
	size_t pos;
} __packed;

#define BIT_LEAF_LEN 128
struct bit_leaf {
	size_t nr_record;
	uint32_t keys[BIT_LEAF_LEN];
	struct record records[BIT_LEAF_LEN];
	size_t next_pos;
} __packed;

struct bit_inner {
	size_t nr_child;
	struct bit_child children[DEFAULT_BIT_DEGREE];
} __packed;

struct cached_inner {
	size_t nr_child;
	struct bit_child children[DEFAULT_BIT_DEGREE];
	struct cached_inner *child_nodes;
};

#define BIT_NODE_SIZE sizeof(struct bit_node)
#define BIT_LEAF_SIZE sizeof(struct bit_leaf)
#define BIT_INNER_SIZE sizeof(struct bit_inner)
#define BIT_NODE_UNION_SIZE max(BIT_LEAF_SIZE, BIT_INNER_SIZE)
#define BIT_LEAF_NODE_SIZE (BIT_NODE_SIZE - BIT_NODE_UNION_SIZE + BIT_LEAF_SIZE)
#define BIT_INNER_NODE_SIZE                                                    \
	(BIT_NODE_SIZE - BIT_NODE_UNION_SIZE + BIT_INNER_SIZE)
struct bit_node {
	bool is_leaf : 1;
	union {
		struct bit_leaf leaf;
		struct bit_inner inner;
	};
	char mac[AES_GCM_AUTH_SIZE];
} __packed;

void bit_node_print(struct bit_node *bit_node);
size_t __bit_array_len(size_t capacity, size_t nr_degree);
size_t calculate_bit_size(size_t nr_record, size_t nr_degree);

struct lsm_file {
	size_t id, level, version;
	struct list_head node;

	struct iterator *(*iterator)(struct lsm_file *lsm_file);
	uint32_t (*get_first_key)(struct lsm_file *lsm_file);
	uint32_t (*get_last_key)(struct lsm_file *lsm_file);
	int (*search)(struct lsm_file *lsm_file, uint32_t key, void *val);
	struct file_stat (*get_stats)(struct lsm_file *lsm_file);
	void (*destroy)(struct lsm_file *lsm_file);
};

struct bit_file {
	struct lsm_file lsm_file;

	struct file *file;
	loff_t root;
	char root_key[AES_GCM_KEY_SIZE];
	char root_iv[AES_GCM_IV_SIZE];
	uint32_t first_key, last_key;
	uint32_t nr_record;
	struct rw_semaphore lock;
	struct cache *cached_leaf;
	struct cached_inner *cached_root;
};

struct lsm_file *bit_file_create(struct file *file, loff_t root, size_t id,
				 size_t level, size_t version,
				 uint32_t first_key, uint32_t last_key,
				 uint32_t nr_record, char *root_key,
				 char *root_iv);

#define DEFAULT_LSM_FILE_BUILDER_BUFFER_SIZE SEGMENT_BUFFER_SIZE
struct lsm_file_builder {
	size_t size;

	int (*add_entry)(struct lsm_file_builder *builder, struct entry *entry);
	struct lsm_file *(*complete)(struct lsm_file_builder *builder);
	void (*destroy)(struct lsm_file_builder *builder);
};

struct bit_builder_context {
	size_t nr;
	struct bit_node nodes[DEFAULT_BIT_DEGREE];
	size_t pos[DEFAULT_BIT_DEGREE];
};

struct bit_builder {
	struct lsm_file_builder lsm_file_builder;

	struct file *file;
	loff_t begin;
	bool has_first_key;
	uint32_t first_key, last_key;
	size_t cur, height, id, level, version;
	void *buffer;
	struct bit_builder_context *ctx;
	char bit_key[AES_GCM_KEY_SIZE];
	struct bit_leaf cur_leaf;
};

struct lsm_file_builder *bit_builder_create(struct file *file, size_t begin,
					    size_t id, size_t level,
					    size_t version);

struct lsm_level {
	size_t level;
	struct rw_semaphore l_lock;

	bool (*is_full)(struct lsm_level *lsm_level);
	int (*add_file)(struct lsm_level *lsm_level, struct lsm_file *file);
	int (*remove_file)(struct lsm_level *lsm_level, size_t id);
	int (*search)(struct lsm_level *lsm_level, uint32_t key, void *val);
	int (*pick_demoted_files)(struct lsm_level *lsm_level,
				  struct list_head *demoted_files);
	int (*find_relative_files)(struct lsm_level *lsm_level,
				   struct list_head *files,
				   struct list_head *relatives);
	struct lsm_file_builder *(*get_builder)(struct lsm_level *lsm_level,
						struct file *file, size_t begin,
						size_t id, size_t level,
						size_t version);
	void (*destroy)(struct lsm_level *lsm_level);
};

struct bit_level {
	struct lsm_level lsm_level;

	size_t capacity, size, max_size;
	struct bit_file **bit_files;
};

struct lsm_level *bit_level_create(size_t level, size_t capacity);

struct lsm_catalogue {
	loff_t start;
	size_t nr_disk_level, common_ratio, max_level_nr_file;
	size_t total_file, file_size;

	size_t (*get_next_version)(struct lsm_catalogue *lsm_catalogue);
	int (*alloc_file)(struct lsm_catalogue *lsm_catalogue, size_t *fd);
	int (*release_file)(struct lsm_catalogue *lsm_catalogue, size_t fd);
	int (*set_file_stats)(struct lsm_catalogue *lsm_catalogue, size_t fd,
			      struct file_stat stats);
	int (*get_file_stats)(struct lsm_catalogue *lsm_catalogue, size_t fd,
			      void *stats);
	int (*get_all_file_stats)(struct lsm_catalogue *lsm_catalogue,
				  struct list_head *stats);
};

struct compaction_job {
	struct file *file;
	struct lsm_catalogue *catalogue;
	struct lsm_level *level1, *level2;

	int (*run)(struct compaction_job *this);
	void (*destroy)(struct compaction_job *this);
};

struct compaction_job *compaction_job_create(struct file *file,
					     struct lsm_catalogue *catalogue,
					     struct lsm_level *level1,
					     struct lsm_level *level2);

struct lsm_tree {
	struct file *file;
	struct lsm_catalogue *catalogue;
	struct memtable *memtable;
	struct rw_semaphore m_lock;
	struct memtable *immutable_memtable;
	struct rw_semaphore im_lock;
	struct lsm_level **levels;
	struct aead_cipher *cipher;

	void (*put)(struct lsm_tree *this, uint32_t key, void *val);
	int (*search)(struct lsm_tree *this, uint32_t key, void *val);
	struct memtable *(*range_search)(struct lsm_tree *this, uint32_t start,
					 uint32_t end);
	void (*destroy)(struct lsm_tree *this);
};

struct lsm_tree *lsm_tree_create(const char *filename,
				 struct lsm_catalogue *catalogue,
				 struct aead_cipher *cipher);

#endif
