/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include <kunit/test.h>

#include "../include/lsm_tree.h"
#include "../include/memtable.h"
#include "../include/metadata.h"

void rbtree_memtable_test(struct kunit *test)
{
	int i;
	struct memtable_entry *entry;
	struct list_head entries;
	struct memtable *memtable = rbtree_memtable_create();

	// put entry
	for (i = 100; i >= 0; --i) {
		memtable->put(memtable, i, record_create(i, NULL, NULL, NULL),
			      record_destroy);
	}

	// overwrite entry
	for (i = 100; i >= 0; --i) {
		memtable->put(memtable, i,
			      record_create(100 - i, NULL, NULL, NULL),
			      record_destroy);
	}

	memtable->get_all_entry(memtable, &entries);
	list_for_each_entry (entry, &entries, list) {
		KUNIT_EXPECT_EQ(test, 100 - entry->key,
				((struct record *)(entry->val))->pba);
	}
}

#define EXPECT_THRESHOLD(x, percent) ((x) / 100 * (percent))

static void calc_avail_sectors_test(struct kunit *test)
{
	// minimum input test: 0x0
	KUNIT_EXPECT_GE(test, calc_avail_sectors(0ull),
			EXPECT_THRESHOLD(0ull, 0));
	// maximum input test: 0xFFFFFFFFFFFFFFFF
	KUNIT_EXPECT_GE(test, calc_avail_sectors(0xFFFFFFFFFFFFFFFF),
			EXPECT_THRESHOLD(0xFFFFFFFFFFFFFFFF, 80));
}

static struct kunit_case jindisk_test_cases[] = {
	KUNIT_CASE(rbtree_memtable_test),
	KUNIT_CASE(calc_avail_sectors_test);
	{}
};

static struct kunit_suite jindisk_test_suite = {
	.name = "dm-jindisk",
	.test_cases = jindisk_test_cases,
};
kunit_test_suite(jindisk_test_suite);
