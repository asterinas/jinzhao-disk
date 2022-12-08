/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef __JINDISK_ITERATOR_H__
#define __JINDISK_ITERATOR_H__

#include <linux/types.h>

#include "memtable.h"

struct entry {
	memtable_key_t key;
	void *val;

	struct list_head node;
};

struct entry __entry(memtable_key_t key, void *val);

struct iterator {
	struct list_head node;
	void *private;

	bool (*has_next)(struct iterator *iterator);
	int (*next)(struct iterator *iterator, void *data);
	void (*destroy)(struct iterator *iterator);
};

#endif
