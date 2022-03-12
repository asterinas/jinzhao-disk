#include <linux/slab.h>

#include "../include/dm_sworndisk.h"
#include "../include/memtable.h"

#define HASH_MEMTABLE_THIS_POINTER_DECLARE struct hash_memtable* this; \
        this = container_of(mt, struct hash_memtable, memtable);

struct mt_value* mt_value_create(int pba, char* key, char* iv, char* mac) {
    struct mt_value* val;

    val = (struct mt_value*) kmalloc(sizeof(struct mt_value), GFP_KERNEL);
    if (!val) {
        DMERR("mt value create alloc mem error\n");
        return NULL;
    }

    val->pba = pba;
    val->key = key;
    val->iv = iv;
    val->mac = mac;
    return val;
}

void hash_memtable_put(struct memtable* mt, int lba, struct mt_value* val) {
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    down_write(&this->rwsem);
    hashmap_add(&this->map, lba, val);
    up_write(&this->rwsem);
}

int hash_memtable_get(struct memtable* mt, int lba, struct mt_value** p_mv) {
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    *p_mv = hashmap_getval(&this->map, lba);
    up_read(&this->rwsem);
    if (*p_mv == NULL) 
        return -ENODATA;
    return 0;
}

bool hash_memtable_contains(struct memtable* mt, int lba) {
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    return hashmap_exists(&this->map, lba);
}

void hash_memtable_destory(struct memtable* mt) {
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    hashmap_destroy(&this->map);
    kfree(this);
}

struct memtable* hash_memtable_init(struct hash_memtable* this) {
    if (IS_ERR_OR_NULL(this))
        return NULL;
    
    init_rwsem(&this->rwsem);
    hashmap_init(&this->map, DEFAULT_HASHMAP_CAPACITY_BITS);
    this->memtable.put = hash_memtable_put;
    this->memtable.get = hash_memtable_get;
    this->memtable.contains = hash_memtable_contains;

    return &this->memtable;
}
