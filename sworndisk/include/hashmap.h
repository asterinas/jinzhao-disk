#ifndef DM_SWORNDISK_HASHMAP_H
#define DM_SWORNDISK_HASHMAP_H

#include <linux/types.h>

struct hashmap {
    // the count of buckets with a hashmap should be 1, 2, 4, 8, ...
    unsigned int capacity_bits; 
    struct hlist_head *hlists;
};

struct hashmap_value {
    uint64_t key;
    void* data;
    struct hlist_node node;
};

void hashmap_init(struct hashmap* map, uint32_t nr_bucket);
void hashmap_destroy(struct hashmap* map);
void hashmap_add(struct hashmap* map, uint32_t key, void* data);
bool hashmap_delete(struct hashmap* map, uint32_t key);
bool hashmap_exists(struct hashmap* map, uint32_t key);
void* hashmap_getval(struct hashmap* map, uint32_t key);
#endif