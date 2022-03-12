#ifndef DM_SWORNDISK_MEMTABLE_H
#define DM_SWORNDISK_MEMTABLE_H

#include <linux/rwsem.h>

#include "hashmap.h"

// memtable value
struct mt_value {
    int pba; // physical block address
    char *mac;
    char *key;
    char *iv;
};  

struct memtable {
    void (*put)(struct memtable* mt, int lba, struct mt_value* val);
    int (*get)(struct memtable* mt, int lba, struct mt_value** p_val);
    bool (*contains)(struct memtable* mt, int lba);
    void (*destroy)(struct memtable* mt);
};

struct hash_memtable {
    struct rw_semaphore rwsem;
    struct hashmap map;
    struct memtable memtable;
};

struct mt_value* mt_value_create(int pba, char* key, char* iv, char* mac);
void hash_memtable_put(struct memtable* mt, int lba, struct mt_value* val);
int hash_memtable_get(struct memtable* mt, int lba, struct mt_value** p_mv);
bool hash_memtable_contains(struct memtable* mt, int lba);
void hash_memtable_destroy(struct memtable* mt);
struct memtable* hash_memtable_init(struct hash_memtable* mt);

#endif