/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef DM_JINDISK_SEGMENT_ALLOCATOR_H
#define DM_JINDISK_SEGMENT_ALLOCATOR_H

#define NR_GC_PRESERVED 320
#define FOREGROUND_GC_THRESHOLD (NR_SEGMENT - NR_GC_PRESERVED)
#define BACKGROUND_GC_THRESHOLD (NR_SEGMENT - NR_GC_PRESERVED)
#define LEAST_CLEAN_SEGMENT_ONCE 5

struct segment_allocator {
	int (*alloc)(struct segment_allocator *al, size_t *seg);
	void (*foreground_gc)(struct segment_allocator *al);
	void (*destroy)(struct segment_allocator *al);
	size_t (*nr_valid_segment_get)(struct segment_allocator *al);
	void (*nr_valid_segment_set)(struct segment_allocator *al, size_t val);
};

struct default_segment_allocator {
	struct segment_allocator segment_allocator;
	size_t nr_segment;
	size_t nr_valid_segment;
	void *buffer;
	struct rw_semaphore gc_lock;
};

struct segment_allocator *sa_create(void);

#endif
