#include <linux/slab.h>

#include "../include/dm_sworndisk.h"
#include "../include/memtable.h"
#include "../include/crypto.h"

// memtable value definition
struct mt_value* mt_value_create(uint32_t pba, char* key, char* iv, char* mac) {
    struct mt_value* val;

    val = (struct mt_value*) kmalloc(sizeof(struct mt_value), GFP_KERNEL);
    if (!val) {
        DMERR("mt value create alloc mem error\n");
        return NULL;
    }

    if (key == NULL)
        __get_random_bytes(&key, AES_GCM_KEY_SIZE);
    if (iv == NULL)
        __get_random_bytes(&iv, AES_GCM_IV_SIZE);
    if (mac == NULL)
        mac = kmalloc(AES_GCM_AUTH_SIZE, GFP_KERNEL);
    
    if (IS_ERR_OR_NULL(key) || IS_ERR_OR_NULL(iv) || IS_ERR_OR_NULL(mac))
        return NULL;

    val->pba = pba;
    val->key = key;
    val->iv = iv;
    val->mac = mac;
    return val;
}

void mt_value_destroy(struct mt_value* mv) {
    if (!IS_ERR_OR_NULL(mv)) {
        if (!IS_ERR_OR_NULL(mv->key))
            kfree(mv->key);
        if (!IS_ERR_OR_NULL(mv->iv))
            kfree(mv->iv);
        if (!IS_ERR_OR_NULL(mv->mac))
            kfree(mv->mac);
        kfree(mv);
    }
}

// hash memtable definition

#define HASH_MEMTABLE_THIS_POINTER_DECLARE struct hash_memtable* this; \
        this = container_of(mt, struct hash_memtable, memtable);

void hash_memtable_put(struct memtable* mt, uint32_t lba, struct mt_value* val) {
    void* old;
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    down_write(&this->rwsem);
    old = hashmap_add(&this->map, lba, val);
    up_write(&this->rwsem);

    if (!IS_ERR_OR_NULL(old))
        mt_value_destroy(old);
}

int hash_memtable_get(struct memtable* mt, uint32_t lba, struct mt_value** p_mv) {
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    *p_mv = hashmap_getval(&this->map, lba);
    up_read(&this->rwsem);
    if (*p_mv == NULL) 
        return -ENODATA;
    return 0;
}

bool hash_memtable_contains(struct memtable* mt, uint32_t lba) {
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
    this->memtable.destroy = hash_memtable_destory;

    return &this->memtable;
}

// radix tree memtable definition

#define RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE struct radix_tree_memtable* this; \
        this = container_of(mt, struct radix_tree_memtable, memtable);

void radix_tree_memtable_put(struct memtable* mt, uint32_t lba, struct mt_value* val) {
    void* data;
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    down_write(&this->rwsem);
    data = radix_tree_lookup(&this->tree, lba);
    if (data) {
        radix_tree_delete(&this->tree, lba);
        kfree(data);
    }
    radix_tree_insert(&this->tree, lba, val);
    up_write(&this->rwsem);
}

int radix_tree_memtable_get(struct memtable* mt, uint32_t lba, struct mt_value** p_mv) {
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    *p_mv = radix_tree_lookup(&this->tree, lba);
    up_read(&this->rwsem);
    if (*p_mv == NULL)
        return -ENODATA;
    return 0;
}

bool radix_tree_memtable_contains(struct memtable* mt, uint32_t lba) {
    bool ret;
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    ret = radix_tree_lookup(&this->tree, lba);
    up_read(&this->rwsem);

    return ret;
}

void radix_tree_memtable_destroy(struct memtable* mt) {
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    kfree(this);
}

struct memtable* radix_tree_memtable_init(struct radix_tree_memtable* this) {
    if (IS_ERR_OR_NULL(this))
        return NULL;
    
    init_rwsem(&this->rwsem);
    INIT_RADIX_TREE(&this->tree, GFP_KERNEL);
    this->memtable.put = radix_tree_memtable_put;
    this->memtable.get = radix_tree_memtable_get;
    this->memtable.contains = radix_tree_memtable_contains;
    this->memtable.destroy = radix_tree_memtable_destroy;
    return &this->memtable;
}