#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/log2.h>

#include "../include/hashtable.h"
#include "../include/dm_sworndisk.h"

#define hash(x, capacity) hash_64_generic((uint64_t)x, ilog2(capacity))

typedef uint64_t hashcode_t;

inline size_t rehash_threadhold(size_t capacity) {
    return capacity / 5 * 4;
} 

struct linked_node {
    hash_key_t key;
    void* val;
    struct hlist_node hlist;
};

struct linked_node* new_linked_node(hash_key_t key, void* val) {
    struct linked_node* node = kmalloc(sizeof(struct linked_node), GFP_KERNEL);
    if (!node)
        return NULL;
    node->key = key;
    node->val = val;
    INIT_HLIST_NODE(&node->hlist);
    return node;
}

void delete_linked_node(struct linked_node* node) {
    if (node)
        kfree(node);
}

struct linked_hashtable {
    size_t capacity;
    struct hlist_head* buckets;
    struct hashtable hashtable;
};

#define MAX_LINKED_HASHTABLE_CAPACITY (1 << 20)
#define DEFAULT_LINKED_HASHTABLE_CAPACITY 16

#define hash_for_each(buckets, slot, capacity, node, member) \
    for (slot = 0; slot < capacity; ++slot) \
        hlist_for_each_entry(node, &buckets[slot], member) 

#define hash_for_each_safe(buckets, slot, capacity, node, temp, member) \
    for (slot = 0; slot < capacity; ++slot) \
        hlist_for_each_entry_safe(node, temp, &buckets[slot], member) 

#define init_buckets(buckets, capacity) do { \
    size_t slot = 0; \
    for (slot = 0; slot < capacity; ++slot) \
        INIT_HLIST_HEAD(&buckets[slot]); \
} while(0)

void linked_hashtable_rehash(struct linked_hashtable* this) {
    size_t new_capacity, slot;
    struct linked_node* node;
    struct hlist_node* temp;
    struct hlist_head* new_buckets;

    if (this->capacity >= MAX_LINKED_HASHTABLE_CAPACITY)
        return;
    
    new_capacity = (this->capacity << 1);
    new_buckets = vmalloc(sizeof(struct hlist_head) * new_capacity);
    if (!new_buckets)
        goto bad;

    init_buckets(new_buckets, new_capacity);
    hash_for_each_safe(this->buckets, slot, this->capacity, node, temp, hlist) {
        size_t new_slot = hash(node->key, new_capacity);
        hlist_del_init(&node->hlist);
        hlist_add_head(&node->hlist, &new_buckets[new_slot]);
    }

    this->capacity = new_capacity;
    vfree(this->buckets);
    this->buckets = new_buckets;
    return;
bad:
    if (new_buckets)
        vfree(new_buckets);
}

struct linked_node* linked_hashtable_search_node(struct linked_hashtable* this, hash_key_t key) {
    size_t slot;
    struct linked_node* node;

    slot = hash(key, this->capacity);
    hlist_for_each_entry(node, &this->buckets[slot], hlist) {
        if (node->key == key) 
            return node;
    }

    return NULL;
}

void* linked_hashtable_put(struct hashtable* hashtable, hash_key_t key, void* val) {
    size_t slot;
    void* old_val = NULL;
    struct linked_node* node;
    struct linked_hashtable* this = container_of(hashtable, struct linked_hashtable, hashtable);
    
    if (hashtable->size >= rehash_threadhold(this->capacity))
        linked_hashtable_rehash(this);
    
    node = linked_hashtable_search_node(this, key);
    if (node) {
        old_val = node->val;
        node->val = val;
        return old_val;
    }

    slot = hash(key, this->capacity);
    node = new_linked_node(key, val);
    hlist_add_head(&node->hlist, &this->buckets[slot]);
    hashtable->size += 1;
    return old_val;
}

int linked_hashtable_get(struct hashtable* hashtable, hash_key_t key, void** val) {
    struct linked_node* node;
    struct linked_hashtable* this = container_of(hashtable, struct linked_hashtable, hashtable);

    node = linked_hashtable_search_node(this, key);
    if (!node)
        return -ENODATA;

    *val = node->val;
    return 0;
}

bool linked_hashtable_contains(struct hashtable* hashtable, hash_key_t key) {
    struct linked_hashtable* this = container_of(hashtable, struct linked_hashtable, hashtable);

    return linked_hashtable_search_node(this, key);
}

void* linked_hashtable_remove(struct hashtable* hashtable, hash_key_t key) {
    struct linked_hashtable* this = container_of(hashtable, struct linked_hashtable, hashtable);
    struct linked_node* node = linked_hashtable_search_node(this, key);

    if (!node)
        return NULL;
    hlist_del_init(&node->hlist);
    hashtable->size -= 1;
    return node->val;
}

void linked_hashtable_clear(struct hashtable* hashtable) {
    size_t slot;
    struct linked_node *node;
    struct hlist_node* temp;
    struct linked_hashtable* this = container_of(hashtable, struct linked_hashtable, hashtable);

    hash_for_each_safe(this->buckets, slot, this->capacity, node, temp, hlist) {
        hlist_del_init(&node->hlist);
        delete_linked_node(node);
    }

    init_buckets(this->buckets, this->capacity);
    hashtable->size = 0;
}

struct linked_hash_iter {
    size_t slot;
    struct hlist_node* hlist;
    struct linked_hashtable* hashtable;
    struct iterator iterator;
};

bool linked_hash_iter_has_next(struct iterator* iterator) {
    struct linked_hash_iter* this = container_of(iterator, struct linked_hash_iter, iterator);

    return this->hlist;
}

int linked_hash_iter_next(struct iterator* iterator, void* data) {
    struct linked_node* node;
    struct linked_hash_iter* this = container_of(iterator, struct linked_hash_iter, iterator);

    if (!linked_hash_iter_has_next(iterator))
        return -ENODATA;

    node = hlist_entry(this->hlist, struct linked_node, hlist);
    *(struct entry*)data = __entry(node->key, node->val);
    
    this->hlist = this->hlist->next;    
    while (this->slot < this->hashtable->capacity - 1 && !this->hlist) {
        this->slot += 1;
        this->hlist = this->hashtable->buckets[this->slot].first;
    }

    return 0;
}

void linked_hash_iter_destroy(struct iterator* iterator) {
    struct linked_hash_iter* this = container_of(iterator, struct linked_hash_iter, iterator);

    kfree(this);
}

int linked_hash_iter_init(struct linked_hash_iter* this, struct linked_hashtable* hashtable) {
    this->slot = 0;
    this->hashtable = hashtable;
    this->hlist = this->hashtable->buckets[0].first;
    while (this->slot < this->hashtable->capacity - 1 && !this->hlist) {
        this->slot += 1;
        this->hlist = this->hashtable->buckets[this->slot].first;
    }

    this->iterator.has_next = linked_hash_iter_has_next;
    this->iterator.next = linked_hash_iter_next;
    this->iterator.destroy = linked_hash_iter_destroy;
    return 0;
}

struct iterator* linked_hash_iter_create(struct linked_hashtable* hashtable) {
    int err = 0;
    struct linked_hash_iter* this = kmalloc(sizeof(struct linked_hash_iter), GFP_KERNEL);

    if (!this)
        goto bad;
    err = linked_hash_iter_init(this, hashtable);
    if (err)
        goto bad;
    return &this->iterator;
bad:
    if (this)
        kfree(this);
    return NULL;
}

struct iterator* linked_hashtable_iterator(struct hashtable* hashtable) {
    struct linked_hashtable* this = container_of(hashtable, struct linked_hashtable, hashtable);

    return linked_hash_iter_create(this);
}

void linked_hashtable_destroy(struct hashtable* hashtable) {
    struct linked_hashtable* this = container_of(hashtable, struct linked_hashtable, hashtable);
    linked_hashtable_clear(hashtable);
    kfree(this);
}

int linked_hashtable_init(struct linked_hashtable* this) {
    int err = 0;

    this->capacity = DEFAULT_LINKED_HASHTABLE_CAPACITY;
    this->buckets = vmalloc(sizeof(struct hlist_head) * this->capacity);
    if (!this->buckets) {
        err = -ENOMEM;
        goto bad;
    }

    init_buckets(this->buckets, this->capacity);
    this->hashtable.put = linked_hashtable_put;
    this->hashtable.get = linked_hashtable_get;
    this->hashtable.contains = linked_hashtable_contains;
    this->hashtable.remove = linked_hashtable_remove;
    this->hashtable.clear = linked_hashtable_clear;
    this->hashtable.iterator = linked_hashtable_iterator;
    this->hashtable.destroy = linked_hashtable_destroy;
    return 0;
bad:
    if (this->buckets)
        vfree(this->buckets);
    return err;
}

struct hashtable* linked_hashtable_create(void) {
    int err = 0;
    struct linked_hashtable* this = kmalloc(sizeof(struct linked_hashtable), GFP_KERNEL);

    if (!this)
        goto bad;
    
    err = linked_hashtable_init(this);
    if (err)
        goto bad;
    
    return &this->hashtable;
bad:
    if (this)
        kfree(this);
    return NULL;
}
