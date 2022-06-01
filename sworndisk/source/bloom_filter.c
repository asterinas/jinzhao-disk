#include <linux/list.h>
#include <linux/slab.h>
#include <linux/fs.h>

#include "../include/bloom_filter.h"
#include "../include/dm_sworndisk.h"

struct bloom_hash_t* bloom_hash_create(hash_func_t func) {
    struct bloom_hash_t* hash = kmalloc(sizeof(struct bloom_hash_t), GFP_KERNEL);

    if (!hash)
        return NULL;
    hash->func = func;
    INIT_LIST_HEAD(&hash->list);
    return hash;
}

void bloom_hash_destroy(struct bloom_hash_t* this) {
    kfree(this);
}

int bloom_filter_add_hash(struct bloom_filter* this, hash_func_t func) {
    struct bloom_hash_t* bloom_hash = bloom_hash_create(func);
    
    if (!bloom_hash)
        return -ENOMEM;
    list_add(&bloom_hash->list, &this->hash_funcs);
    return 0;
}

#define BITS_PER_BYTE 8
void bloom_filter_add(struct bloom_filter* this, void* ptr, size_t len) {
    struct bloom_hash_t* f;

    list_for_each_entry(f, &this->hash_funcs, list) {
        size_t offset = f->func(ptr, len) % (this->size * BITS_PER_BYTE);
        set_bit(offset, this->bits);
    }
}

bool bloom_filter_contains(struct bloom_filter* this, void* ptr, size_t len) {
    struct bloom_hash_t* f;

    list_for_each_entry(f, &this->hash_funcs, list) {
        size_t offset = f->func(ptr, len) % (this->size * BITS_PER_BYTE);
        if (!test_bit(offset, this->bits))
            return false;
    }

    return true;
}

void bloom_filter_destroy(struct bloom_filter* this) {
    struct bloom_hash_t *f, *next;

    if (!this)  return;

    if (this->bits)
        vfree(this->bits);
    list_for_each_entry_safe(f, next, &this->hash_funcs, list) {
        bloom_hash_destroy(f);
    }
    kfree(this);
}

void bloom_filter_load(struct bloom_filter* this, struct file* file, loff_t begin) {
    kernel_read(file, this->bits, this->size, &begin);
}

int bloom_filter_init(struct bloom_filter* this, size_t size) {
    int err = 0;

    INIT_LIST_HEAD(&this->hash_funcs);
    this->size = size;
    this->bits = vmalloc(size);
    if (!this->bits) {
        err = -ENOMEM;
        goto bad;
    }

    memset(this->bits, 0, this->size);
    return 0;
bad:
    if (this->bits)
        vfree(this->bits);
    return err;
}

struct bloom_filter* bloom_filter_create(size_t size) {
    int err = 0;
    struct bloom_filter* this = kzalloc(sizeof(struct bloom_filter), GFP_KERNEL);

    if (!this)  
        goto bad;
    err = bloom_filter_init(this, size);
    if (err)
        goto bad;
    
    return this;
bad:
    if (this)
        kfree(this);
    return NULL;
}

// unit test 
uint64_t djb2(const void *_str, size_t len) {
	const char *str = _str;
	uint64_t hash = 5381, i;

    for (i = 0; i < len; ++i) {
        hash = ((hash << 5) + hash) + str[i];
    }
	return hash;
}

uint64_t jenkins(const void *_key, size_t len) {
    const char* key = _key;
    uint32_t hash, i;
    for(hash = i = 0; i < len; ++i)
    {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

uint64_t shash(const void *_word, size_t len) {
    const unsigned char* word = _word;
    uint64_t hash = 0, i;

    for (i = 0 ; i < len ; ++i) {
        hash = 31 * hash + word[i];
    }
    return hash;
}

void bloom_filter_test() {
    size_t i;
    struct bloom_filter* filter = bloom_filter_create(32);

    bloom_filter_add_hash(filter, djb2);
    bloom_filter_add_hash(filter, jenkins);

    for (i = 0; i < 128; i += 2)
        bloom_filter_add(filter, &i, sizeof(size_t));
    
    for (i = 1; i < 128; i += 2) {
        if (bloom_filter_contains(filter, &i, sizeof(size_t)))
            DMINFO("should not contain this: %ld", i);
    }

    for (i = 0; i < 128; i += 2) {
        if (!bloom_filter_contains(filter, &i, sizeof(size_t)))
            DMINFO("it should be contained, but not!");
    }

    bloom_filter_destroy(filter);
}