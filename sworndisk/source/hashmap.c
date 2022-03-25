#include <linux/hash.h>
#include <linux/slab.h>

#include "../include/dm_sworndisk.h"
#include "../include/hashmap.h"


void hashmap_init(struct hashmap* map, unsigned int capacity_bits) {
    int i;
    uint32_t nr_bucket;

    nr_bucket = (1 << capacity_bits);
    map->capacity_bits = capacity_bits;
    map->hlists = (struct hlist_head*)kmalloc(sizeof(struct hlist_head)*nr_bucket, GFP_KERNEL);
    for(i=0; i<nr_bucket; ++i) 
        INIT_HLIST_HEAD(&map->hlists[i]);
}

void hashmap_destroy(struct hashmap* map) {
    kfree(map->hlists);
}

void* hashmap_add(struct hashmap* map, uint32_t key, void* data) {
    void* old;
    struct hashmap_value* value = (struct hashmap_value*)kmalloc(sizeof(struct hashmap_value), GFP_KERNEL);

    old = hashmap_delete(map, key);
    value->key = key;
    value->data = data;
    hlist_add_head(&value->node, &map->hlists[hash_64_generic(key, map->capacity_bits)]);

    return old;
}

bool hashmap_exists(struct hashmap* map, uint32_t key) {
    struct hashmap_value* obj;

    hlist_for_each_entry(obj, &map->hlists[hash_64_generic(key, map->capacity_bits)], node) {
        if(obj->key == key) 
            return true;
    }
    return false;
}

void* hashmap_delete(struct hashmap* map, uint32_t key) {
    struct hashmap_value* obj;

    hlist_for_each_entry(obj, &map->hlists[hash_64_generic(key, map->capacity_bits)], node) {
        if(obj->key == key) {
            hlist_del_init(&obj->node);
            return obj->data;
        }
    }

    return NULL;
}

void* hashmap_getval(struct hashmap* map, uint32_t key) {
    struct hashmap_value* obj;

    hlist_for_each_entry(obj, &map->hlists[hash_64_generic(key, map->capacity_bits)], node) {
        if(obj->key == key) {
            return obj->data;
        }
    }

    return NULL;
}