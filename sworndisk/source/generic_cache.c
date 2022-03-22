#include <linux/slab.h>

#include "../include/dm_sworndisk.h"
#include "../include/generic_cache.h"

void cache_entry_init(struct cache_entry *entry, uint32_t key, void* data, size_t data_len, bool locked) {
    entry->key = key;
    entry->data = data;
    entry->data_len = data_len;
    entry->locked = locked;
    INIT_LIST_NODE(&entry->node);
}

struct cache_entry* cache_entry_create(uint32_t key, void* data, size_t data_len, bool locked) {
    struct cache_entry* entry;

    entry = kmalloc(sizeof(struct cache_entry), GFP_KERNEL);
    if (!entry)
        return NULL;
    cache_entry_init(entry, key, data, data_len, locked);
    return entry;
}

void cache_entry_destroy(struct cache_entry* entry) {
    kfree(entry->data);
    kfree(entry);
}

#define FIFO_CACHE_POLICY_THIS_POINTER_DECLARE struct fifo_cache_policy* this; \
            this = container_of(policy, struct fifo_cache_policy, cache_policy);

void __fifo_remove_entry(struct cache_policy* policy, uint32_t key) {
    list_node_t* node;
    struct cache_entry* entry;
    struct generic_cache* cache;
    FIFO_CACHE_POLICY_THIS_POINTER_DECLARE

    // DMINFO("__fifo_remove_entry: %d", key);
    cache = this->base_cache;
    node = hashmap_getval(&this->index_table, key);
    if (!node)
        return;
    list_del(node);
    entry = list_entry(node, struct cache_entry, node);
    if (!entry->locked)
        cache->size -= 1;
    hashmap_delete(&this->index_table, key);
    cache_entry_destroy(entry);
}

void fifo_remove_entry(struct cache_policy* policy, uint32_t key) {
    struct generic_cache* cache;
    FIFO_CACHE_POLICY_THIS_POINTER_DECLARE

    cache = this->base_cache;
    down_write(&cache->rwsem);
    __fifo_remove_entry(policy, key);
    up_write(&cache->rwsem);
}

void fifo_add_entry(struct cache_policy* policy, uint32_t key, struct cache_entry* new_entry) {
    struct cache_entry* entry;
    struct generic_cache* cache;
    struct list_head* entry_list;
    struct list_head* locked_entry_list;
    FIFO_CACHE_POLICY_THIS_POINTER_DECLARE

    // DMINFO("fifo_add_entry: %d");
    cache = this->base_cache;
    down_write(&cache->rwsem);
    entry_list = &cache->entry_list;
    locked_entry_list = &cache->locked_entry_list;
    __fifo_remove_entry(policy, key);
    while(cache->size >= cache->capacity) {
        entry = list_first_entry(entry_list, struct cache_entry, node);
        __fifo_remove_entry(policy, entry->key);
    }
    list_add_tail(&new_entry->node, new_entry->locked ? locked_entry_list : entry_list);
    hashmap_add(&this->index_table, key, &new_entry->node);
    if (!new_entry->locked)
        cache->size += 1;
    up_write(&cache->rwsem);
}


struct cache_entry* fifo_get_entry(struct cache_policy* policy, uint32_t key) {
    list_node_t* node;
    struct cache_entry* entry;
    struct generic_cache* cache;
    struct list_head* entry_list;
    FIFO_CACHE_POLICY_THIS_POINTER_DECLARE

    entry = NULL;
    cache = this->base_cache;
    down_read(&cache->rwsem);
    entry_list = &cache->entry_list;
    node = hashmap_getval(&this->index_table, key);
    if (!node)
        goto exit;
    entry = list_entry(node, struct cache_entry, node);
exit:
    up_read(&cache->rwsem);
    return entry;
}

void fifo_unlock_entry(struct cache_policy* policy, uint32_t key) {
    list_node_t* node;
    struct cache_entry* entry;
    struct generic_cache* cache;
    struct list_head* entry_list;
    FIFO_CACHE_POLICY_THIS_POINTER_DECLARE

    // DMINFO("fifo_unlock_entry: %d", key);
    cache = this->base_cache;
    down_write(&cache->rwsem);
    entry_list = &cache->entry_list;
    node = hashmap_getval(&this->index_table, key);
    if (!node)
        goto exit;
    entry = list_entry(node, struct cache_entry, node);
    entry->locked = false;
    list_move_tail(&entry->node, entry_list);
    cache->size += 1;
    while(cache->size >= cache->capacity) {
        entry = list_first_entry(entry_list, struct cache_entry, node);
        __fifo_remove_entry(policy, entry->key);
    }
exit:
    up_write(&cache->rwsem);
}

void fifo_destroy(struct cache_policy* policy) {
    FIFO_CACHE_POLICY_THIS_POINTER_DECLARE

    hashmap_destroy(&this->index_table);
}

void fifo_cache_policy_init(struct fifo_cache_policy* this, struct generic_cache* base_cache) {
    this->base_cache = base_cache;
    hashmap_init(&this->index_table, get_order(DEFAULT_CACHE_CAPACITY));

    this->cache_policy.add_entry = fifo_add_entry;
    this->cache_policy.remove_entry = fifo_remove_entry;
    this->cache_policy.unlock_entry = fifo_unlock_entry;
    this->cache_policy.get_entry = fifo_get_entry;
    this->cache_policy.destroy = fifo_destroy;
}

struct cache_policy* fifo_cache_policy_create(struct generic_cache* base_cache) {
    struct fifo_cache_policy* policy;

    policy = kmalloc(sizeof(struct fifo_cache_policy), GFP_KERNEL);
    if (!policy) 
        return NULL;
    fifo_cache_policy_init(policy, base_cache);
    return &policy->cache_policy;
}

void generic_cache_set(struct generic_cache* cache, uint32_t key, struct cache_entry* entry) {
    cache->policy->add_entry(cache->policy, key, entry);
}

struct cache_entry* generic_cache_get(struct generic_cache* cache, uint32_t key) {
    return cache->policy->get_entry(cache->policy, key);
}

void generic_cache_delete(struct generic_cache* cache, uint32_t key) {
    cache->policy->remove_entry(cache->policy, key);
}

void generic_cache_unlock(struct generic_cache* cache, uint32_t key) {
    cache->policy->unlock_entry(cache->policy, key);
}

int generic_cache_init(struct generic_cache* this, size_t capacity,  size_t max_locked_entry) {
    this->size = 0;
    this->capacity = capacity;
    this->policy = fifo_cache_policy_create(this);
    if (IS_ERR_OR_NULL(this->policy))
        return -ENOMEM;
    
    init_rwsem(&this->rwsem);
    INIT_LIST_HEAD(&this->entry_list);
    INIT_LIST_HEAD(&this->locked_entry_list);

    this->set = generic_cache_set;
    this->get = generic_cache_get;
    this->unlock = generic_cache_unlock;
    this->delete = generic_cache_delete;

    return 0;
}

struct generic_cache* generic_cache_create(size_t capacity, size_t max_locked_entry) {
    int r;
    struct generic_cache* cache;

    cache = kmalloc(sizeof(struct generic_cache), GFP_KERNEL);
    if (!cache)
        return NULL;
    r = generic_cache_init(cache, capacity, max_locked_entry);
    if (r)
        return NULL;
    return cache;
}

void generic_cache_destroy(struct generic_cache* cache) {
    if (!IS_ERR_OR_NULL(cache)) {
        if (!IS_ERR_OR_NULL(cache->policy))
            cache->policy->destroy(cache->policy);
        kfree(cache);
    }
}