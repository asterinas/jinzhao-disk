#ifndef __SWORNDISK_BLOOM_FILTER_H__
#define __SWORNDISK_BLOOM_FILTER_H__

uint64_t djb2(const void *_str, size_t len);
uint64_t jenkins(const void *_key, size_t len);
uint64_t shash(const void *_word, size_t len);

typedef uint64_t (*hash_func_t)(const void*, size_t);

struct bloom_hash_t {
    hash_func_t func;
    struct list_head list;
};

struct bloom_filter {
    struct list_head hash_funcs;
    void* bits;
    size_t size;
};

struct bloom_filter* bloom_filter_create(size_t size);
void bloom_filter_load(struct bloom_filter* this, struct file* file, loff_t begin);
void bloom_filter_add(struct bloom_filter* this, void* ptr, size_t len);
int bloom_filter_add_hash(struct bloom_filter* this, hash_func_t func);
bool bloom_filter_contains(struct bloom_filter* this, void* ptr, size_t len);
void bloom_filter_destroy(struct bloom_filter* this);
#endif