#ifndef DM_SWORNDISK_GENERIC_CACHE_H
#define DM_SWORNDISK_GENERIC_CACHE_H

#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <linux/list.h>

#include "hashmap.h"

#define DEFAULT_MAX_LOCKED_ENTRY 2048
#define DEFAULT_CACHE_CAPACITY 4096

typedef struct list_head list_node_t;
#define INIT_LIST_NODE(x) INIT_LIST_HEAD(x)

struct cache_entry {
    uint32_t key;
    void* data;
    size_t data_len;
    bool locked;
    list_node_t node;
};

struct cache_policy;

struct generic_cache {
    struct rw_semaphore rwsem;
    size_t size;
    size_t capacity;
    // struct semaphore sema; // the number of locked entry in memory is limited
    struct cache_policy *policy;
    struct list_head entry_list;
    struct list_head locked_entry_list;

    void (*set)(struct generic_cache* cache, uint32_t key, struct cache_entry* entry);
    void (*delete)(struct generic_cache* cache, uint32_t key);
    void (*unlock)(struct generic_cache* cache, uint32_t key);
    struct cache_entry* (*get)(struct generic_cache* cache, uint32_t key);
};

struct cache_policy {
    void (*add_entry)(struct cache_policy* policy, uint32_t key, struct cache_entry* new_entry);
    void (*remove_entry)(struct cache_policy* policy, uint32_t key);
    void (*unlock_entry)(struct cache_policy* policy, uint32_t key);
    struct cache_entry* (*get_entry)(struct cache_policy* policy, uint32_t key);
    void (*destroy)(struct cache_policy* policy);
};

struct fifo_cache_policy {
    struct generic_cache* base_cache;
    struct radix_tree_root index_table;
    struct cache_policy cache_policy;
};

struct lru_cache_policy {
    struct cache_policy cache_policy;
};

struct cache_entry* cache_entry_create(uint32_t key, void* data, size_t data_len, bool locked);
struct generic_cache* generic_cache_create(size_t capacity, size_t max_locked_entry);
void generic_cache_destroy(struct generic_cache* cache);

#endif