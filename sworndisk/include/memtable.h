#ifndef DM_SWORNDISK_MEMTABLE_H
#define DM_SWORNDISK_MEMTABLE_H

#include <linux/rwsem.h>
#include <linux/btree.h>

#include "hashmap.h"

// memtable value
struct mt_value {
    uint32_t pba; // physical block address
    char *mac;
    char *key;
    char *iv;
};  

struct mt_value* mt_value_create(uint32_t pba, char* key, char* iv, char* mac);

struct memtable {
    void (*put)(struct memtable* mt, uint32_t lba, struct mt_value* val);
    int (*get)(struct memtable* mt, uint32_t lba, struct mt_value** p_val);
    bool (*contains)(struct memtable* mt, uint32_t lba);
    void (*destroy)(struct memtable* mt);
};

struct hash_memtable {
    struct rw_semaphore rwsem;
    struct hashmap map;
    struct memtable memtable;
};


void hash_memtable_put(struct memtable* mt, uint32_t lba, struct mt_value* val);
int hash_memtable_get(struct memtable* mt, uint32_t lba, struct mt_value** p_mv);
bool hash_memtable_contains(struct memtable* mt, uint32_t lba);
void hash_memtable_destroy(struct memtable* mt);
struct memtable* hash_memtable_init(struct hash_memtable* mt);

struct radix_tree_memtable {
    struct rw_semaphore rwsem;
    struct radix_tree_root tree;
    struct memtable memtable; 
};

void radix_tree_memtable_put(struct memtable* mt, uint32_t lba, struct mt_value* val);
int radix_tree_memtable_get(struct memtable* mt, uint32_t lba, struct mt_value** p_mv);
bool radix_tree_memtable_contains(struct memtable* mt, uint32_t lba);
void radix_tree_memtable_destroy(struct memtable* mt);
struct memtable* radix_tree_memtable_init(struct radix_tree_memtable* mt);

#endif