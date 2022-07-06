#include <linux/types.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>

#include "../include/cache.h"
#include "../include/memtable.h"

struct lru_cache_node {
    uint64_t key;
    void* val;
    void (*dtr_fn)(void*);
    struct list_head list;
};

struct lru_cache_node* lru_cache_node_create(uint64_t key, void* val, void (*dtr_fn)(void*)) {
    struct lru_cache_node* node = kzalloc(sizeof(struct lru_cache_node), GFP_KERNEL);

    if (!node)
        return NULL;
    
    node->key = key;
    node->val = val;
    node->dtr_fn = dtr_fn;
    INIT_LIST_HEAD(&node->list);
    return node;
}

void lru_cache_node_destroy(struct lru_cache_node* node) {
    if (!node) return;
    if (node->dtr_fn)
        node->dtr_fn(node->val);
    kfree(node);
}

struct lru_cache {
    struct cache cache;

    struct mutex lock;
    size_t size, capacity;
    struct radix_tree_root root;
    struct list_head entries;
};

int lru_cache_put(struct cache* cache, uint64_t key, void* val, void (*dtr_fn)(void*)) {
    struct lru_cache* this = container_of(cache, struct lru_cache, cache);
    struct lru_cache_node* node = NULL;
    
    mutex_lock(&this->lock);
    node = radix_tree_lookup(&this->root, key);
    if (node) {
        if (node->dtr_fn)
            node->dtr_fn(node->val);
        node->val = val;
        node->dtr_fn = dtr_fn;
        list_del(&node->list);
        list_add(&node->list, &this->entries);
        mutex_unlock(&this->lock);
        return 0;
    }

    while (this->size >= this->capacity) {
        node = list_last_entry(&this->entries, struct lru_cache_node, list);
        list_del(&node->list);
        radix_tree_delete(&this->root, node->key);
        lru_cache_node_destroy(node);
        this->size -= 1;
    }

    node = lru_cache_node_create(key, val, dtr_fn);
    radix_tree_insert(&this->root, key, node);
    list_add(&node->list, &this->entries);
    this->size += 1;
    mutex_unlock(&this->lock);
    return 0;
}

void* lru_cache_get(struct cache* cache, uint64_t key) {
    struct lru_cache* this = container_of(cache, struct lru_cache, cache);
    struct lru_cache_node* node = NULL;

    mutex_lock(&this->lock);
    node = radix_tree_lookup(&this->root, key);
    if (!node) {
        mutex_unlock(&this->lock);
        return NULL;
    }

    list_del(&node->list);
    list_add(&node->list, &this->entries);
    mutex_unlock(&this->lock);
    return node->val;
}

void lru_cache_delete(struct cache* cache, uint64_t key) {
    struct lru_cache* this = container_of(cache, struct lru_cache, cache);
    struct lru_cache_node* node = NULL;

    mutex_lock(&this->lock);
    node = radix_tree_delete(&this->root, key);
    if (node) {
        list_del(&node->list);
        lru_cache_node_destroy(node);
        this->size -= 1;
    }
    
    mutex_unlock(&this->lock);
}

void lru_cache_destroy(struct cache* cache) {
    struct lru_cache_node *node, *temp;
    struct lru_cache* this = container_of(cache, struct lru_cache, cache);

    list_for_each_entry_safe(node, temp, &this->entries, list) 
        lru_cache_node_destroy(node);
    kfree(this);
}

void lru_cache_init(struct lru_cache* this, size_t capacity) {
    this->size = 0;
    this->capacity = capacity;
    mutex_init(&this->lock);
    INIT_RADIX_TREE(&this->root, GFP_KERNEL);
    INIT_LIST_HEAD(&this->entries);

    this->cache.put = lru_cache_put;
    this->cache.get = lru_cache_get;
    this->cache.delete = lru_cache_delete;
    this->cache.destroy = lru_cache_destroy;
}


struct cache* lru_cache_create(size_t capacity) {
    struct lru_cache* this = kzalloc(sizeof(struct lru_cache), GFP_KERNEL);

    if (!this) 
        goto bad;

    lru_cache_init(this, capacity);
    return &this->cache;
bad:
    return NULL;
}
