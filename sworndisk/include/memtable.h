#ifndef DM_SWORNDISK_MEMTABLE_H
#define DM_SWORNDISK_MEMTABLE_H

#include <linux/rwsem.h>
#include <linux/rbtree.h>

#include "../../persistent-data/dm-block-manager.h"
#include "hashmap.h"
#include "lsm_tree.h"

#define DEFAULT_MEMTABLE_CAPACITY 65536

struct memtable {
    struct lsm_level lsm_level;

    void* (*put)(struct memtable* mt, uint32_t key, void* val);
    int (*get)(struct memtable* mt, uint32_t key, void** p_val);
    void* (*remove)(struct memtable* mt, uint32_t ket);
    bool (*contains)(struct memtable* mt, uint32_t key);
    void (*destroy)(struct memtable* mt);
};

// hash memtable definition
struct hash_memtable {
    struct rw_semaphore rwsem;
    struct hashmap map;
    struct memtable memtable;
};

struct memtable* hash_memtable_init(struct hash_memtable* this);

// radix tree memtable definition
struct radix_tree_memtable {
    struct rw_semaphore rwsem;
    struct radix_tree_root tree;
    struct memtable memtable; 
};

struct memtable* radix_tree_memtable_init(struct radix_tree_memtable* this);

// rbtree memtable definition
struct memtable_rbnode {
    uint32_t key;
    void* val;
    void (*dtr_fn)(void*);
    struct rb_node node;
};

struct rbtree_memtable {
    struct rb_root root;
    struct memtable memtable;
};

struct memtable* rbtree_memtable_create(size_t capacity);

#endif