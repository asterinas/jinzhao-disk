#ifndef SWORNDISK_CACHE_H
#define SWORNDISK_CACHE_H

struct cache {
    int (*put)(struct cache* cache, uint64_t key, void* val, void (*dtr_fn)(void*));
    void (*delete)(struct cache* cache, uint64_t key);
    void* (*get)(struct cache* cache, uint64_t key);
    void (*destroy)(struct cache* cache);
};

struct cache* lru_cache_create(size_t capacity);

#endif