#include <linux/slab.h>
#include <linux/random.h>
#include <linux/sort.h>

#include "../include/dm_sworndisk.h"
#include "../include/memtable.h"
#include "../include/crypto.h"
#include "../include/hashtable.h"

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

    if (record)
        kfree(record);
}

struct memtable_entry* new_memtable_entry(memtable_key_t key, void* val, dtr_fn_t dtr_fn) {
    struct memtable_entry* entry = kmalloc(sizeof(struct memtable_entry), GFP_KERNEL);

    if (!entry)
        return NULL;
    entry->key = key;
    entry->val = val;
    entry->dtr_fn = dtr_fn;
    return entry;
}

void delete_memtable_entry(struct memtable_entry* entry) {
    if (!entry) return;
    if (entry->dtr_fn)
        entry->dtr_fn(entry->val);
    kfree(entry);
}

int memtable_entry_cmp(struct memtable_entry* entry1, struct memtable_entry* entry2) {
    return (int64_t)entry1->key - (int64_t)entry2->key;
}

int memtable_entry_cmp_rb(struct rb_node* node1, const struct rb_node* node2) {
    struct memtable_entry* entry1 = rb_entry(node1, struct memtable_entry, rb);
    struct memtable_entry* entry2 = rb_entry(node2, struct memtable_entry, rb);
    return memtable_entry_cmp(entry1, entry2);
}

int memtable_entry_cmp_rb_key(const void* key, const struct rb_node* node) {
    struct memtable_entry* entry = rb_entry(node, struct memtable_entry, rb);
    return (int64_t)(*(int*)key) - (int64_t)(entry->key);
}

int memtable_entry_cmp_pointer(const void* a, const void* b) {
    struct memtable_entry* entry1 = *(struct memtable_entry**)a;
    struct memtable_entry* entry2 = *(struct memtable_entry**)b;
    return memtable_entry_cmp(entry1, entry2);
}

// hash memtable definition
void* hash_memtable_put(struct memtable* memtable, memtable_key_t key, void* val, dtr_fn_t dtr_fn) {
    void* old_val = NULL;
    struct memtable_entry *old_entry, *new_entry;
    struct hash_memtable* this = container_of(memtable, struct hash_memtable, memtable);

    new_entry = new_memtable_entry(key, val, dtr_fn);
    if (!new_entry)
        return NULL;
    
    old_entry = this->hashtable->put(this->hashtable, key, new_entry);
    if (old_entry) {
        old_val = old_entry->val;
        kfree(old_entry);
    } 
    if (!old_val)
        memtable->size += 1;
    return old_val;
}

int hash_memtable_get(struct memtable* memtable, memtable_key_t key, void** p_val) {
    int err = 0;
    struct memtable_entry* entry;
    struct hash_memtable* this = container_of(memtable, struct hash_memtable, memtable);

    err = this->hashtable->get(this->hashtable, key, (void**)&entry);
    if (err)
        return err;
    *p_val = entry->val;
    return 0;
}

int hash_memtable_get_all_entry(struct memtable* memtable, struct list_head* entry_list) {
    size_t len = 0, i;
    struct iterator* iter;
    struct entry entry;
    struct memtable_entry** entry_array;
    struct hash_memtable* this = container_of(memtable, struct hash_memtable, memtable);

    entry_array = vmalloc(sizeof(struct memtable_entry*) * memtable->size);
    if (!entry_array)
        return -ENOMEM;

    iter = this->hashtable->iterator(this->hashtable);
    while (iter->has_next(iter)) {
        iter->next(iter, &entry);
        entry_array[len++] = entry.val;
    }
    iter->destroy(iter);

    sort(entry_array, len, sizeof(struct memtable_entry*), memtable_entry_cmp_pointer, NULL);
    INIT_LIST_HEAD(entry_list);
    for (i = 0; i < len; ++i) 
        list_add_tail(&entry_array[i]->list, entry_list);
    vfree(entry_array);
    return 0;
}

void* hash_memtable_remove(struct memtable* memtable, memtable_key_t key) {
    struct memtable_entry* entry;
    struct hash_memtable* this = container_of(memtable, struct hash_memtable, memtable);

    entry = this->hashtable->remove(this->hashtable, key);
    if (!entry)
        return NULL;
    memtable->size -= 1;
    return entry->val;
}

bool hash_memtable_contains(struct memtable* memtable, memtable_key_t key) {
    struct hash_memtable* this = container_of(memtable, struct hash_memtable, memtable);

    return this->hashtable->contains(this->hashtable, key);
}

void hash_memtable_clear(struct memtable* memtable) {
    struct iterator* iter;
    struct hash_memtable* this = container_of(memtable, struct hash_memtable, memtable);

    iter = this->hashtable->iterator(this->hashtable);
    while (iter->has_next(iter)) {
        struct entry entry;
        iter->next(iter, &entry);
        delete_memtable_entry(entry.val);
    }
    iter->destroy(iter);
    this->hashtable->clear(this->hashtable);
    memtable->size = 0;
}

void hash_memtable_destroy(struct memtable* memtable) {
    struct hash_memtable* this = container_of(memtable, struct hash_memtable, memtable);
    hash_memtable_clear(memtable);
    this->hashtable->destroy(this->hashtable);
    kfree(this);
}

int hash_memtable_init(struct hash_memtable* this) {
    int err = 0;

    this->hashtable = linked_hashtable_create();
    if (!this->hashtable) {
        err = -ENOMEM;
        goto bad;
    }

    this->memtable.size = 0;
    this->memtable.put = hash_memtable_put;
    this->memtable.get = hash_memtable_get;
    this->memtable.get_all_entry = hash_memtable_get_all_entry;
    this->memtable.remove = hash_memtable_remove;
    this->memtable.clear = hash_memtable_clear;
    this->memtable.destroy = hash_memtable_destroy;
    return 0;
bad:
    if (this->hashtable)
        this->hashtable->destroy(this->hashtable);
    return err;
}

struct memtable* hash_memtable_create(void) {
    int err = 0;
    struct hash_memtable* this = kmalloc(sizeof(struct hash_memtable), GFP_KERNEL);

    if (!this)
        goto bad;
    err = hash_memtable_init(this);
    if (err)
        goto bad;
    return &this->memtable;
bad:
    if (this)
        kfree(this);
    return NULL;
}

// rbtree memtable implementation
void* __rbtree_memtable_search(struct rb_root* root, memtable_key_t key) {
    struct memtable_entry* cur;
    struct rb_node *node = root->rb_node;  /* top of the tree */

    while (node)
	{
	    cur = rb_entry(node, struct memtable_entry, rb);

	    if (cur->key > key)
		    node = node->rb_left;
	    else if (cur->key < key)
		    node = node->rb_right;
	    else
		    return cur->val;  /* Found it */
  	}
	return NULL;
}

void* rbtree_memtable_put(struct memtable* memtable, memtable_key_t key, void* val, dtr_fn_t dtr_fn) {
    void* old_val = NULL;
    struct rb_node* node = NULL;
    struct memtable_entry *old_entry = NULL, *new_entry = NULL;
    struct rbtree_memtable* this = container_of(memtable, struct rbtree_memtable, memtable);

    new_entry = new_memtable_entry(key, val, dtr_fn);
    if (!new_entry)
        return NULL;

next:
    node = rb_find_add(&new_entry->rb, &this->root, memtable_entry_cmp_rb);
    if (node) {
        old_entry = rb_entry(node, struct memtable_entry, rb);
        rb_erase(node, &this->root);
        old_val = old_entry->val;
        kfree(old_entry);
        goto next;
    }
    if (!old_val)
        memtable->size += 1;
    return old_val;
}

int rbtree_memtable_get(struct memtable* memtable, memtable_key_t key, void** p_val) {
    struct rbtree_memtable* this = container_of(memtable, struct rbtree_memtable, memtable);

    *p_val = __rbtree_memtable_search(&this->root, key);
    if (*p_val) {
        return 0;
    }
        
    return -ENODATA;
}

void* rbtree_memtable_remove(struct memtable* memtable, memtable_key_t key) {
    void* val;
    struct memtable_entry* entry;
    struct rb_node* node;
    struct rbtree_memtable* this = container_of(memtable, struct rbtree_memtable, memtable);

    node = rb_find(&key, &this->root, memtable_entry_cmp_rb_key);
    if (!node)
        return NULL;
    
    memtable->size -= 1;
    rb_erase(node, &this->root);
    entry = rb_entry(node, struct memtable_entry, rb);
    val = entry->val;
    kfree(entry);

    return val;
}

bool rbtree_memtable_contains(struct memtable* memtable, memtable_key_t key) {
    struct rbtree_memtable* this = container_of(memtable, struct rbtree_memtable, memtable);

    return __rbtree_memtable_search(&this->root, key);
}

int rbtree_memtable_get_all_entry(struct memtable* memtable, struct list_head* entries) {
    struct rb_node* node;
    struct rbtree_memtable* this = container_of(memtable, struct rbtree_memtable, memtable);

    INIT_LIST_HEAD(entries);
    for (node = rb_first(&this->root); node; node = rb_next(node)) {
        struct memtable_entry* entry = rb_entry(node, struct memtable_entry, rb);
        list_add_tail(&entry->list, entries);
    }

    return 0;
}

void rbtree_memtable_clear(struct memtable* memtable) {
    struct memtable_entry* entry;
    struct rbtree_memtable* this = container_of(memtable, struct rbtree_memtable, memtable);

    while(!RB_EMPTY_ROOT(&this->root)) {
        entry = rb_entry(rb_first(&this->root), struct memtable_entry, rb);
        rb_erase(&entry->rb, &this->root);
        delete_memtable_entry(entry);
    }
    memtable->size = 0;
}

void rbtree_memtable_destroy(struct memtable* memtable) {
    struct rbtree_memtable* this = container_of(memtable, struct rbtree_memtable, memtable);

    rbtree_memtable_clear(memtable);
    kfree(this);
}


void rbtree_memtable_init(struct rbtree_memtable* this) {
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

struct memtable* rbtree_memtable_create(void) {
    struct rbtree_memtable* this;

    this = kmalloc(sizeof(struct rbtree_memtable), GFP_KERNEL);
    if (!this)
        return NULL;
    
    rbtree_memtable_init(this);
    return &this->memtable;
}