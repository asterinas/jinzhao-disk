/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include <linux/dm-io.h>
#include <linux/timer.h>

#include "../include/dm_jindisk.h"
#include "../include/metadata.h"
#include "../include/segment_allocator.h"
#include "../include/segment_buffer.h"

#define GC_DELAY 1000 // milliseconds
struct timer_list gc_timer;
struct work_struct gc_work;
static struct workqueue_struct *gc_wq;

size_t sa_nr_valid_segment_get(struct segment_allocator *al)
{
	struct default_segment_allocator *this = container_of(
		al, struct default_segment_allocator, segment_allocator);

	return this->nr_valid_segment;
}

void sa_nr_valid_segment_set(struct segment_allocator *al, size_t val)
{
	struct default_segment_allocator *this = container_of(
		al, struct default_segment_allocator, segment_allocator);

	this->nr_valid_segment = val;
}

int sa_alloc(struct segment_allocator *al, size_t *seg)
{
	int r;
	struct default_segment_allocator *this = container_of(
		al, struct default_segment_allocator, segment_allocator);

	r = jindisk->meta->seg_validator->next(jindisk->meta->seg_validator,
					       seg);
	if (r) {
		DMDEBUG("sa_alloc next failed err:%d", r);
		return r;
	}

	r = jindisk->meta->seg_validator->take(jindisk->meta->seg_validator,
					       *seg);
	if (r) {
		DMERR("sa_alloc take failed err:%d", r);
		return r;
	}
	this->nr_valid_segment += 1;
	r = jindisk->meta->dst->take_segment(jindisk->meta->dst, *seg);
	if (r) {
		DMERR("sa_alloc take_segment failed segno:%lu", *seg);
		return r;
	}
	return 0;
}

int gc_one_segment(void)
{
	bool valid;
	void *buffer;
	struct victim *victim;
	dm_block_t lba, pba;
	int err, offset, count;
	struct record old;
	struct dst *dst = jindisk->meta->dst;
	struct seg_validator *svt = jindisk->meta->seg_validator;
	struct reverse_index_table *rit = jindisk->meta->rit;
	struct lsm_tree *lsm_tree = jindisk->lsm_tree;

	count = 0;
	offset = 0;
	buffer = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
	if (!buffer) {
		DMERR("gc_one_segment kzalloc buffer failed");
		return -ENOMEM;
	}
retry:
	victim = dst->pop_victim(dst);
	if (!victim) {
		DMDEBUG("gc_one_segment found no segment to gc");
		kfree(buffer);
		return -ENODATA;
	}
	if (victim->nr_valid_block == 0) {
		DMDEBUG("segment:%lu has no valid_block", victim->segno);
		goto out;
	}
	if (victim->segno == dst->logging_segno) {
		DMDEBUG("segment:%lu is threaded_logging, skip", victim->segno);
		victim_destroy(victim);
		goto retry;
	}

	DMDEBUG("gc segment:%lu", victim->segno);
	do {
		offset = find_next_bit(victim->block_validity_table,
				       BLOCKS_PER_SEGMENT, offset);
		if (offset == BLOCKS_PER_SEGMENT)
			break;

		pba = victim->segno * BLOCKS_PER_SEGMENT + offset;
		err = rit->reset(rit, pba, INF_ADDR, &lba);
		if (err)
			continue;

		lsm_tree->search(lsm_tree, lba, &old);
		if (pba != old.pba) {
			DMDEBUG("gc pba:%llu lba:%llu new:%llu out of date",
				pba, lba, old.pba);
			continue;
		}
		lsm_tree->put(lsm_tree, lba, NULL);

		jindisk_read_blocks(pba, 1, buffer, DM_IO_KMEM, NULL);
		err = jindisk->cipher->decrypt(jindisk->cipher, buffer,
					       DATA_BLOCK_SIZE, old.key, NULL,
					       old.mac, old.pba, buffer);
		if (!err) {
			jindisk->seg_buffer->push_block(jindisk->seg_buffer,
							lba, buffer, false);
			count++;
		}
	} while (++offset < BLOCKS_PER_SEGMENT);
out:
	err = dst->return_segment(dst, victim->segno);
	if (err)
		DMERR("clear DST failed segment:%lu", victim->segno);
	err = svt->test_and_return(svt, victim->segno, &valid);
	if (err)
		DMERR("clear SVT failed segment:%lu", victim->segno);

	victim_destroy(victim);
	kfree(buffer);
	return count;
}

void sa_foreground_gc(struct segment_allocator *al)
{
	int gc_count;
	size_t clean = 0;
	size_t target = LEAST_CLEAN_SEGMENT_ONCE * BLOCKS_PER_SEGMENT;
	struct default_segment_allocator *this = container_of(
		al, struct default_segment_allocator, segment_allocator);

	if (this->nr_valid_segment < FOREGROUND_GC_THRESHOLD)
		return;

	if (down_write_trylock(&this->gc_lock) == 0)
		return;

	DMDEBUG("sa_foreground_gc start");
	while (clean < target) {
		gc_count = gc_one_segment();
		if (gc_count < 0)
			break;

		clean += gc_count;
		this->nr_valid_segment -= 1;
	}
	DMDEBUG("sa_foreground_gc stop");
	up_write(&this->gc_lock);
}

void sa_background_gc(struct work_struct *ws)
{
	int gc_count;
	size_t clean = 0;
	size_t target = LEAST_CLEAN_SEGMENT_ONCE * BLOCKS_PER_SEGMENT;
	struct default_segment_allocator *this =
		container_of(jindisk->seg_allocator,
			     struct default_segment_allocator,
			     segment_allocator);

	if (this->nr_valid_segment < BACKGROUND_GC_THRESHOLD)
		return;

	if (down_write_trylock(&this->gc_lock) == 0)
		return;

	DMDEBUG("sa_background_gc start");
	while (clean < target) {
		gc_count = gc_one_segment();
		if (gc_count < 0)
			break;

		clean += gc_count;
		this->nr_valid_segment -= 1;
	}
	DMDEBUG("sa_background_gc stop");
	up_write(&this->gc_lock);
}

void gc_timer_callback(struct timer_list *gc_timer)
{
	queue_work(gc_wq, &gc_work);
	mod_timer(gc_timer, jiffies + msecs_to_jiffies(GC_DELAY));
}

void sa_destroy(struct segment_allocator *al)
{
	struct default_segment_allocator *this = container_of(
		al, struct default_segment_allocator, segment_allocator);

	del_timer(&gc_timer);
	if (gc_wq)
		destroy_workqueue(gc_wq);

	if (!IS_ERR_OR_NULL(this)) {
		kfree(this);
	}
}

int sa_init(struct default_segment_allocator *this)
{
	int err = 0;

	this->segment_allocator.alloc = sa_alloc;
	this->segment_allocator.foreground_gc = sa_foreground_gc;
	this->segment_allocator.destroy = sa_destroy;
	this->segment_allocator.nr_valid_segment_get = sa_nr_valid_segment_get;
	this->segment_allocator.nr_valid_segment_set = sa_nr_valid_segment_set;

	this->nr_segment = jindisk->meta->seg_validator->nr_segment;
	err = jindisk->meta->seg_validator->valid_segment_count(
		jindisk->meta->seg_validator, &this->nr_valid_segment);
	if (err)
		goto bad;

	gc_wq = alloc_workqueue("jindisk-gc", WQ_UNBOUND, 1);
	if (!gc_wq) {
		DMERR("alloc_workqueue gc_wq failed");
		err = -EAGAIN;
		goto bad;
	}
	init_rwsem(&this->gc_lock);
	INIT_WORK(&gc_work, sa_background_gc);
	timer_setup(&gc_timer, gc_timer_callback, 0);
	gc_timer.expires = jiffies + msecs_to_jiffies(GC_DELAY);
	add_timer(&gc_timer);
bad:
	return err;
}

struct segment_allocator *sa_create()
{
	int r;
	struct default_segment_allocator *sa;

	sa = kzalloc(sizeof(struct default_segment_allocator), GFP_KERNEL);
	if (!sa)
		return NULL;

	r = sa_init(sa);
	if (r)
		return NULL;

	return &sa->segment_allocator;
}
