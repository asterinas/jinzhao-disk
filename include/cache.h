#ifndef SWORNDISK_CACHE_H
#define SWORNDISK_CACHE_H

#define MAX_LEAF_NODE_CACHED 1024
#define DEFAULT_LRU_CACHE_CAPACITY (MAX_LEAF_NODE_CACHED * BIT_LEAF_LEN)

struct cache {
    int (*put)(struct cache* cache, uint64_t key, void* val, void (*dtr_fn)(void*));
    void (*delete)(struct cache* cache, uint64_t key);
    void* (*get)(struct cache* cache, uint64_t key);
    void (*destroy)(struct cache* cache);
};

struct cache* lru_cache_create(size_t capacity);

#endif
