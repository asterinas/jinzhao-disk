#include <kunit/test.h>

#include "../include/bloom_filter.h"
#include "../include/memtable.h"
#include "../include/lsm_tree.h"
#include "../include/hashtable.h"

void bloom_filter_test(struct kunit* test) {
    size_t i;
    struct bloom_filter* filter = bloom_filter_create(32);

    bloom_filter_add_hash(filter, djb2);
    bloom_filter_add_hash(filter, jenkins);

    for (i = 0; i < 128; i += 2)
        bloom_filter_add(filter, &i, sizeof(size_t));

    for (i = 0; i < 128; i += 2) {
        bool result = bloom_filter_contains(filter, &i, sizeof(size_t));
        KUNIT_EXPECT_EQ(test, true, result);
    }

    bloom_filter_destroy(filter);
}

void hash_memtable_test(struct kunit* test) {
    int i;
    struct memtable_entry* entry;
    struct list_head entries;
    struct memtable* memtable = hash_memtable_create();

    // put entry
    for (i = 100; i >= 0; --i) {
        memtable->put(memtable, i, record_create(i, NULL, NULL, NULL), record_destroy);
    }

    // overwrite entry
    for (i = 100; i >= 0; --i) {
        memtable->put(memtable, i, record_create(100 - i, NULL, NULL, NULL), record_destroy);
    }

    memtable->get_all_entry(memtable, &entries);
    list_for_each_entry(entry, &entries, list) {
        KUNIT_EXPECT_EQ(test, 100 - entry->key, ((struct record*)(entry->val))->pba);
    }
}

void linked_hashtable_test(struct kunit* test) {
    size_t i;
    int *nums, *num;
    struct hashtable* hashtable = linked_hashtable_create();

    nums = kmalloc(sizeof(int) * 100, GFP_KERNEL);
    for (i = 0; i < 100; ++i) {
        nums[i] = 100 - i;
        hashtable->put(hashtable, i, &nums[i]);
    }
        
    
    for (i = 0; i < 100; ++i) {
        hashtable->get(hashtable, i, (void**)&num);
        KUNIT_EXPECT_EQ(test, 100 - i, *num);
    }

    hashtable->destroy(hashtable);
    kfree(nums);
}

static struct kunit_case sworndisk_test_cases[] = {
    KUNIT_CASE(bloom_filter_test),
    KUNIT_CASE(hash_memtable_test),
    KUNIT_CASE(linked_hashtable_test),
    {}
};

static struct kunit_suite sworndisk_test_suite = {
        .name = "dm-sworndisk",
        .test_cases = sworndisk_test_cases,
};
kunit_test_suite(sworndisk_test_suite);