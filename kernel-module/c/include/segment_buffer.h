/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef DM_JINDISK_SEGMENT_BUFFER_H
#define DM_JINDISK_SEGMENT_BUFFER_H

#include <linux/bio.h>
#include <linux/completion.h>
#include <linux/dm-io.h>
#include <linux/rwsem.h>

#include "crypto.h"
#include "memtable.h"

#define SEGMENT_BUFFER_SIZE (SECTORS_PER_SEGMENT * SECTOR_SIZE)
#define POOL_SIZE 4

struct segment_block {
	dm_block_t lba;
	void *plain_block;
	struct rb_node node;
};

struct data_segment {
	int size;
	size_t cur_segment;
	char seg_key[AES_GCM_KEY_SIZE];
	void *cipher_segment;
	struct rb_root root;
};

struct segment_buffer {
	int (*push_bio)(struct segment_buffer *buf, struct bio *bio);
	void (*push_block)(struct segment_buffer *buf, dm_block_t lba,
			   void *buffer, bool rflag);
	int (*query_block)(struct segment_buffer *buf, uint32_t lba,
			   void *buffer);
	void (*flush_bios)(struct segment_buffer *buf, int index);
	void (*destroy)(struct segment_buffer *buf);
	void *(*implementer)(struct segment_buffer *buf);
};

struct default_segment_buffer {
	struct segment_buffer segment_buffer;

	int cur_buffer;
	struct data_segment buffer[POOL_SIZE];
	struct rw_semaphore rw_lock[POOL_SIZE];
	struct rw_semaphore lock;
};

struct segment_buffer *segbuf_create(void);

#endif
