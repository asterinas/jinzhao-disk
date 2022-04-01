#include <linux/slab.h>

#include "../include/dm_sworndisk.h"
#include "../include/memtable.h"
#include "../include/crypto.h"

// memtable value definition
struct record* record_create(dm_block_t pba, char* key, char* iv, char* mac) {
    struct record* val;

    val = (struct record*) kmalloc(sizeof(struct record), GFP_KERNEL);
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

void record_destroy(void* val) {
    struct record* record = val;

    if (!IS_ERR_OR_NULL(record)) {
        if (!IS_ERR_OR_NULL(record->key))
            kfree(record->key);
        if (!IS_ERR_OR_NULL(record->iv))
            kfree(record->iv);
        if (!IS_ERR_OR_NULL(record->mac))
            kfree(record->mac);
        kfree(record);
    }
}

// hash memtable definition

#define HASH_MEMTABLE_THIS_POINTER_DECLARE struct hash_memtable* this; \
        this = container_of(mt, struct hash_memtable, memtable);

void hash_memtable_put(struct memtable* mt, uint32_t key, void* val) {
    void* old;
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    down_write(&this->rwsem);
    old = hashmap_add(&this->map, key, val);
    up_write(&this->rwsem);

    if (!IS_ERR_OR_NULL(old))
        record_destroy(old);
}

int hash_memtable_get(struct memtable* mt, uint32_t key, void** p_val) {
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    *p_val = hashmap_getval(&this->map, key);
    up_read(&this->rwsem);
    if (*p_val == NULL) 
        return -ENODATA;
    return 0;
}

bool hash_memtable_contains(struct memtable* mt, uint32_t key) {
    HASH_MEMTABLE_THIS_POINTER_DECLARE

    return hashmap_exists(&this->map, key);
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

void radix_tree_memtable_put(struct memtable* mt, uint32_t key, void* val) {
    void* old;
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    down_write(&this->rwsem);
    old = radix_tree_delete(&this->tree, key);
    if (!IS_ERR_OR_NULL(old))
        record_destroy(old);
    radix_tree_insert(&this->tree, key, val);
    up_write(&this->rwsem);
}

int radix_tree_memtable_get(struct memtable* mt, uint32_t key, void** p_val) {
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    *p_val = radix_tree_lookup(&this->tree, key);
    up_read(&this->rwsem);
    if (*p_val == NULL)
        return -ENODATA;
    return 0;
}

bool radix_tree_memtable_contains(struct memtable* mt, uint32_t key) {
    bool ret;
    RADIX_TREE_MEMTABLE_THIS_POINTER_DECLARE

    down_read(&this->rwsem);
    ret = radix_tree_lookup(&this->tree, key);
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

    if (node1 == NULL)
        DMINFO("node1 is null");
    
    if (node2 == NULL)
        DMINFO("node2 is null");

    entry1 = rb_entry(node1, struct memtable_rbnode, node);
    entry2 = rb_entry(node2, struct memtable_rbnode, node);

    return (int64_t)entry1->key - (int64_t)entry2->key;
}

void memtable_rbnode_destroy(struct memtable_rbnode* entry) {
    if (!IS_ERR_OR_NULL(entry)) {
        if (!IS_ERR_OR_NULL(entry->val) && !IS_ERR_OR_NULL(entry->dtr_fn)) 
            entry->dtr_fn(entry->val);
        kfree(entry);
    }
}


#define RBTREE_MEMTABLE_THIS_POINTER_DECLARE struct rbtree_memtable* this; \
        this = container_of(mt, struct rbtree_memtable, memtable);

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

void rbtree_memtable_put(struct memtable* mt, uint32_t key, void* val) {
    struct rb_node* node = NULL;
    struct memtable_rbnode *old = NULL, *new = NULL;
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    new = memtable_rbnode_create(key, val, record_destroy);
    if (!new)
        return;

next:
    node = rb_find_add(&new->node, &this->root, memtable_rbnode_cmp);
    if (node) {
        old = rb_entry(node, struct memtable_rbnode, node);
        rb_erase(node, &this->root);
        memtable_rbnode_destroy(old);
        goto next;
    }
}

int rbtree_memtable_get(struct memtable* mt, uint32_t key, void** p_val) {
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    *p_val = __rbtree_memtable_search(&this->root, key);
    if (*p_val) {
        return 0;
    }
        
    return -ENODATA;
}

bool rbtree_memtable_contains(struct memtable* mt, uint32_t key) {
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    return __rbtree_memtable_search(&this->root, key);
}

void rbtree_memtable_destroy(struct memtable* mt) {
    RBTREE_MEMTABLE_THIS_POINTER_DECLARE

    if (!IS_ERR_OR_NULL(this))
        kfree(this);
}

void rbtree_memtable_init(struct rbtree_memtable* this) {
    this->root = RB_ROOT;
    this->memtable.put = rbtree_memtable_put;
    this->memtable.get = rbtree_memtable_get;
    this->memtable.contains = rbtree_memtable_contains;
    this->memtable.destroy = rbtree_memtable_destroy;
}

struct memtable* rbtree_memtable_create(void) {
    struct rbtree_memtable* this;

    this = kmalloc(sizeof(struct rbtree_memtable), GFP_KERNEL);
    if (!this)
        return NULL;
    
    rbtree_memtable_init(this);

    return &this->memtable;
}