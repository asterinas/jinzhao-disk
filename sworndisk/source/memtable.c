#include <linux/slab.h>
#include <linux/random.h>

#include "../include/dm_sworndisk.h"
#include "../include/memtable.h"
#include "../include/crypto.h"

// memtable record definition
void __copy_or_random(void* dst, void* src, size_t len) {
    if (src == NULL) {
        get_random_bytes(dst, len);
        return;
    }
    memcpy(dst, src, len);
}

struct record* record_create(dm_block_t pba, char* key, char* iv, char* mac) {
    struct record* record;

    record = (struct record*) kzalloc(sizeof(struct record), GFP_KERNEL);
    if (!record) {
        DMERR("memtable value create alloc mem error\n");
        return NULL;
    }

    __copy_or_random(record->key, key, AES_GCM_KEY_SIZE);
    __copy_or_random(record->iv, iv, AES_GCM_IV_SIZE);
    if (mac)
        memcpy(record->mac, mac, AES_GCM_AUTH_SIZE);

    record->pba = pba;
    return record;
}

struct record* record_copy(struct record* old) {
    struct record* new;

    if (!old)
        return NULL;

    new = kzalloc(sizeof(struct record), GFP_KERNEL);
    if (!new)
        return NULL;
    
    *new = *old;
    return new;
}

void record_destroy(void* p) {
    struct record* record = p;

    if (!IS_ERR_OR_NULL(record))
        kfree(record);
}

// hash memtable definition

#define HASH_MEMTABLE_THIS_POINTER_DECLARE struct hash_memtable* this; \
        this = container_of(memtable, struct hash_memtable, memtable);

void* hash_memtable_put(struct memtable* memtable, uint32_t key, void* val) {
    void* old;
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    down_write(&this->rwsem);
    old = hashmap_add(&this->map, key, val);
    up_write(&this->rwsem);

    return old;
}

int hash_memtable_get(struct memtable* memtable, uint32_t key, void** p_val) {
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    *p_val = hashmap_getval(&this->map, key);
    up_read(&this->rwsem);
    if (*p_val == NULL) 
        return -ENODATA;
    return 0;
}

bool hash_memtable_contains(struct memtable* memtable, uint32_t key) {
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    return hashmap_exists(&this->map, key);
}

void hash_memtable_destory(struct memtable* memtable) {
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
        this = container_of(memtable, struct radix_tree_memtable, memtable);

void* radix_tree_memtable_put(struct memtable* memtable, uint32_t key, void* val) {
    void* old;
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    down_write(&this->rwsem);
    old = radix_tree_delete(&this->tree, key);
    radix_tree_insert(&this->tree, key, val);
    up_write(&this->rwsem);

    return old;
}

int radix_tree_memtable_get(struct memtable* memtable, uint32_t key, void** p_val) {
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    *p_val = radix_tree_lookup(&this->tree, key);
    up_read(&this->rwsem);
    if (*p_val == NULL)
        return -ENODATA;
    return 0;
}

bool radix_tree_memtable_contains(struct memtable* memtable, uint32_t key) {
    bool ret;
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    ret = radix_tree_lookup(&this->tree, key);
    up_read(&this->rwsem);

    return ret;
}

void radix_tree_memtable_destroy(struct memtable* memtable) {
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

// rbtree memtable implementation
struct memtable_rbnode* memtable_rbnode_create(uint32_t key, void* val, void (*dtr_fn)(void*)) {
    struct memtable_rbnode* entry;

    entry = kmalloc(sizeof(struct memtable_rbnode), GFP_KERNEL);
    if (!entry)
        return NULL;
    
    entry->key = key;
    entry->val = val;
    entry->dtr_fn = dtr_fn;
    
    return entry;
}

int memtable_rbnode_cmp(struct rb_node* node1, const struct rb_node* node2) {
    struct memtable_rbnode *entry1, *entry2;

    entry1 = rb_entry(node1, struct memtable_rbnode, node);
    entry2 = rb_entry(node2, struct memtable_rbnode, node);
    return (int64_t)entry1->key - (int64_t)entry2->key;
}

int memtable_rbnode_cmp_key(const void* key, const struct rb_node* node) {
    struct memtable_rbnode* entry;

    entry = rb_entry(node, struct memtable_rbnode, node);
    return (int64_t)(*(int*)key) - (int64_t)(entry->key);
}

void memtable_rbnode_destroy(struct memtable_rbnode* entry) {
    if (!IS_ERR_OR_NULL(entry)) {
        if (!IS_ERR_OR_NULL(entry->val) && !IS_ERR_OR_NULL(entry->dtr_fn)) 
            entry->dtr_fn(entry->val);
        kfree(entry);
    }
}


#define RBTREE_MEMTABLE_THIS_POINTER_DECLARE struct rbtree_memtable* this; \
        this = container_of(memtable, struct rbtree_memtable, memtable);

// memtable interface implementation
void* __rbtree_memtable_search(struct rb_root* root, uint32_t key) {
    struct memtable_rbnode* cur;
    struct rb_node *node = root->rb_node;  /* top of the tree */

    while (node)
	{
	    cur = rb_entry(node, struct memtable_rbnode, node);

	    if (cur->key > key)
		    node = node->rb_left;
	    else if (cur->key < key)
		    node = node->rb_right;
	    else
		    return cur->val;  /* Found it */
  	}
	return NULL;
}

void* rbtree_memtable_put(struct memtable* memtable, uint32_t key, void* val) {
    void* oldval = NULL;
    struct rb_node* node = NULL;
    struct memtable_rbnode *old = NULL, *new = NULL;
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    new = memtable_rbnode_create(key, val, record_destroy);
    if (!new)
        return NULL;

next:
    node = rb_find_add(&new->node, &this->root, memtable_rbnode_cmp);
    if (node) {
        old = rb_entry(node, struct memtable_rbnode, node);
        rb_erase(node, &this->root);
        oldval = old->val;
        kfree(old);
        goto next;
    }
    if (!oldval)
        memtable->size += 1;
    return oldval;
}

int rbtree_memtable_get(struct memtable* memtable, uint32_t key, void** p_val) {
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    *p_val = __rbtree_memtable_search(&this->root, key);
    if (*p_val) {
        return 0;
    }
        
    return -ENODATA;
}

void* rbtree_memtable_remove(struct memtable* memtable, uint32_t key) {
    void* val;
    struct memtable_rbnode* entry;
    struct rb_node* node;
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    node = rb_find(&key, &this->root, memtable_rbnode_cmp_key);
    if (!node)
        return NULL;
    
    memtable->size -= 1;
    rb_erase(node, &this->root);
    entry = rb_entry(node, struct memtable_rbnode, node);
    val = entry->val;
    kfree(entry);

    return val;
}

bool rbtree_memtable_contains(struct memtable* memtable, uint32_t key) {
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    return __rbtree_memtable_search(&this->root, key);
}

int rbtree_memtable_get_all_entry(struct memtable* memtable, struct list_head* entries) {
    struct memtable_rbnode* memtable_rbnode;
    struct rb_node* node;
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    INIT_LIST_HEAD(entries);
    for (node = rb_first(&this->root); node; node = rb_next(node)) {
        memtable_rbnode = rb_entry(node, struct memtable_rbnode, node);
        list_add_tail(&memtable_rbnode->list, entries);
    }

    return 0;
}

void rbtree_memtable_clear(struct memtable* memtable) {
    struct memtable_rbnode* entry;
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    while(!RB_EMPTY_ROOT(&this->root)) {
        entry = rb_entry(rb_first(&this->root), struct memtable_rbnode, node);
        rb_erase(&entry->node, &this->root);
        memtable_rbnode_destroy(entry);
    }
    memtable->size = 0;
}

void rbtree_memtable_destroy(struct memtable* memtable) {
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    if (!IS_ERR_OR_NULL(this)) {
        rbtree_memtable_clear(memtable);
        kfree(this);
    }
}


void rbtree_memtable_init(struct rbtree_memtable* this, size_t capacity) {
    this->root = RB_ROOT;
    // memtable
    this->memtable.size = 0;
    this->memtable.put = rbtree_memtable_put;
    this->memtable.get = rbtree_memtable_get;
    this->memtable.get_all_entry = rbtree_memtable_get_all_entry;
    this->memtable.contains = rbtree_memtable_contains;
    this->memtable.destroy = rbtree_memtable_destroy;
    this->memtable.remove = rbtree_memtable_remove;
    this->memtable.clear = rbtree_memtable_clear;
}

struct memtable* rbtree_memtable_create(size_t capacity) {
    struct rbtree_memtable* this;

    this = kmalloc(sizeof(struct rbtree_memtable), GFP_KERNEL);
    if (!this)
        return NULL;
    
    rbtree_memtable_init(this, capacity);

    return &this->memtable;
}