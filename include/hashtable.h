#ifndef __SWORNDISK_HASHTABLE_H__
#define __SWORNDISK_HASHTABLE_H__

#include "iterator.h"

typedef int64_t hash_key_t;

struct hashtable {
    size_t size;

    void* (*put)(struct hashtable* hashtable, hash_key_t key, void* val);
    int (*get)(struct hashtable* hashtable, hash_key_t key, void** val);
    bool (*contains)(struct hashtable* hashtable, hash_key_t key);
    void* (*remove)(struct hashtable* hashtable, hash_key_t key);
    void (*clear)(struct hashtable* hashtable);
    struct iterator* (*iterator)(struct hashtable* hashtable);
    void (*destroy)(struct hashtable* hashtable);
};

struct hashtable* linked_hashtable_create(void);

#endif