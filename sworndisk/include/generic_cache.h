#ifndef DM_SWORNDISK_GENERIC_CACHE_H
#define DM_SWORNDISK_GENERIC_CACHE_H

#include <linux/rwsem.h>
#include <linux/list.h>

#define DEFAULT_CACHE_CAPACITY 65536

struct cache_entry {
    bool locked;
    void* data;
    int data_len;
    struct list_head list;
};

struct cache_policy;

struct generic_cache {
    rwlock_t lock;
    int capacity;
    struct cache_policy policy;
    struct list_head entry_list;

    void (*set)(int key, struct cache_entry* ce);
    void (*delete)(int key);
    struct cache_entry* (*get)(int key);
};

struct cache_policy {
    void (*add_entry)(int key, struct cache_entry* entry);
    void (*remove_entry)(int key);
    struct cache_entry* (*get_entry)(int key);
};

struct lru_cache_policy {
    struct cache_policy interface;
};

void generic_cache_init(struct generic_cache* cache) {
    cache->capacity = DEFAULT_CACHE_CAPACITY;
    rwlock_init(&cache->lock);
    INIT_LIST_HEAD(&cache->entry_list);
}

#endif