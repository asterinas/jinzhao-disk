/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include <linux/bio.h>

#include "../include/crypto.h"
#include "../include/dm_jindisk.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"

struct bufferio_work {
	struct work_struct work;
	void *segbuf;
	int index;
};
static struct workqueue_struct *bufferio_wq;

struct segment_block *segment_block_new(uint32_t lba)
{
	struct segment_block *blk =
		kzalloc(sizeof(struct segment_block), GFP_KERNEL);
	if (!blk) {
		DMERR("segment_block_new kzalloc segment_block failed");
		return NULL;
	}
	blk->lba = lba;
	blk->plain_block = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
	if (!blk->plain_block) {
		DMERR("segment_block_new kzalloc plain_block failed");
		kfree(blk);
		return NULL;
	}
	return blk;
}

void segment_block_delete(struct segment_block *blk)
{
	if (blk) {
		kfree(blk->plain_block);
		kfree(blk);
	}
}
int segment_block_cmp_key(const void *key, const struct rb_node *node)
{
	struct segment_block *blk = rb_entry(node, struct segment_block, node);

	return (int64_t)(*(uint32_t *)key) - (int64_t)(blk->lba);
}

struct segment_block *data_segment_get(struct data_segment *ds, uint32_t lba)
{
	struct rb_node *node;

	node = rb_find(&lba, &ds->root, segment_block_cmp_key);
	if (node) {
		return rb_entry(node, struct segment_block, node);
	} else
		return NULL;
}

void data_segment_remove(struct data_segment *ds, struct segment_block *blk)
{
	rb_erase(&blk->node, &ds->root);
	ds->size -= 1;
	segment_block_delete(blk);
}

int segment_block_cmp_node(struct rb_node *node, const struct rb_node *parent)
{
	struct segment_block *nb = rb_entry(node, struct segment_block, node);
	struct segment_block *pb = rb_entry(parent, struct segment_block, node);

	return (int64_t)nb->lba - (int64_t)pb->lba;
}

void data_segment_add(struct data_segment *ds, struct segment_block *blk)
{
	struct rb_node *old;
	struct segment_block *old_blk;

	old = rb_find_add(&blk->node, &ds->root, segment_block_cmp_node);
	if (old) {
		old_blk = rb_entry(old, struct segment_block, node);
		rb_erase(old, &ds->root);
		segment_block_delete(old_blk);
	} else
		ds->size += 1;
}

int data_segment_init(struct data_segment *ds)
{
	ds->size = 0;
	ds->root = RB_ROOT;
	get_random_bytes(ds->seg_key, sizeof(ds->seg_key));
	ds->cipher_segment = vmalloc(SEGMENT_BUFFER_SIZE);
	if (!ds->cipher_segment) {
		DMERR("data_segment_init failed");
		return -ENOMEM;
	}
	return 0;
}

void data_segment_destroy(struct data_segment *ds)
{
	struct segment_block *blk;

	if (ds->cipher_segment)
		vfree(ds->cipher_segment);
	while (!RB_EMPTY_ROOT(&ds->root)) {
		blk = rb_entry(rb_first(&ds->root), struct segment_block, node);
		rb_erase(&blk->node, &ds->root);
		segment_block_delete(blk);
	}
}

int segbuf_push_bio(struct segment_buffer *buf, struct bio *bio)
{
#if defined(DEBUG)
	dm_block_t start = bio_to_lba(bio);
	int count = DIV_ROUND_UP(bio->bi_iter.bi_size, DATA_BLOCK_SIZE);

	DMDEBUG("segbuf_push_bio start:%llu count:%d", start, count);
#endif
	while (bio->bi_iter.bi_size) {
		struct bio_vec bv = bio_iter_iovec(bio, bio->bi_iter);
		dm_block_t lba = bio_to_lba(bio);
		void *data_in = page_address(bv.bv_page);

		disk_counter.write_req_blocks += 1;
		buf->push_block(buf, lba, data_in, true);
		if (bio->bi_iter.bi_size < DATA_BLOCK_SIZE) {
			DMERR("write < 4K lba:%llu offset:%d len:%d", lba,
			      bv.bv_offset, bv.bv_len);
			break;
		}
		bio_advance_iter(bio, &bio->bi_iter, DATA_BLOCK_SIZE);
	}
	return 0;
}

void bufferio_handler(struct work_struct *ws)
{
	struct bufferio_work *bw = container_of(ws, struct bufferio_work, work);
	struct segment_buffer *buf = bw->segbuf;
	struct default_segment_buffer *this = container_of(
		buf, struct default_segment_buffer, segment_buffer);

	DMDEBUG("bufferio start index:%u", bw->index);
	down_read(&this->rw_lock[bw->index]);
	buf->flush_bios(buf, bw->index);
	up_read(&this->rw_lock[bw->index]);
	DMDEBUG("bufferio stop index:%u", bw->index);
	kfree(bw);
}

void segbuf_push_block(struct segment_buffer *buf, dm_block_t lba, void *buffer,
		       bool rflag)
{
	struct default_segment_buffer *this = container_of(
		buf, struct default_segment_buffer, segment_buffer);
	struct bufferio_work *bw = NULL;
	struct segment_block *blk = NULL;
	int cur, i, j;

	down_write(&this->lock);
	cur = this->cur_buffer;
	if (rflag == false) {
		for (i = 0; i < POOL_SIZE; i++) {
			j = (cur + POOL_SIZE - i) % POOL_SIZE;
			blk = data_segment_get(&this->buffer[j], lba);
			if (blk) {
				DMDEBUG("segbuf_push_block from gc, lba:%llu "
					"has new data, skip",
					lba);
				up_write(&this->lock);
				return;
			}
		}
	} else {
		blk = data_segment_get(&this->buffer[cur], lba);
		if (blk)
			DMDEBUG("segbuf_push_block from bio, lba:%llu "
				"has old data, rewrite",
				lba);
	}

	if (!blk) {
		blk = segment_block_new(lba);
		data_segment_add(&this->buffer[cur], blk);
	}
	memcpy(blk->plain_block, buffer, DATA_BLOCK_SIZE);
	DMDEBUG("segbuf_push_block lba:%llu write to buffer", lba);
	if (this->buffer[cur].size >= BLOCKS_PER_SEGMENT) {
		bw = kzalloc(sizeof(struct bufferio_work), GFP_KERNEL);
		bw->segbuf = buf;
		bw->index = cur;
		INIT_WORK(&bw->work, bufferio_handler);
		queue_work(bufferio_wq, &bw->work);

		this->cur_buffer = (cur + 1) % POOL_SIZE;
		down_write(&this->rw_lock[this->cur_buffer]);
		if (this->buffer[this->cur_buffer].size > 0)
			data_segment_destroy(&this->buffer[this->cur_buffer]);
		data_segment_init(&this->buffer[this->cur_buffer]);
		up_write(&this->rw_lock[this->cur_buffer]);
	}
	up_write(&this->lock);
}

void segbuf_threaded_logging(struct data_segment *ds)
{
	int err = 0;
	struct dst *dst = jindisk->meta->dst;
	struct rb_node *node;
	void *buffer = NULL;

	buffer = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
	if (!buffer) {
		DMERR("threaded_logging buffer kzalloc failed");
		return;
	}
	for (node = rb_first(&ds->root); node; node = rb_next(node)) {
		struct segment_block *blk;
		dm_block_t pba;
		struct record *new;

		blk = rb_entry(node, struct segment_block, node);
		err = dst->find_logging_block(dst, &pba);
		if (err) {
			DMERR("find_logging_block failed lba:%llu", blk->lba);
			continue;
		}
		new = record_create(pba, ds->seg_key, NULL);
		jindisk->cipher->encrypt(jindisk->cipher,
					 (char *)blk->plain_block,
					 DATA_BLOCK_SIZE, new->key, NULL,
					 new->mac, new->pba, buffer);

		jindisk->lsm_tree->put(jindisk->lsm_tree, blk->lba, new);
		jindisk->meta->rit->set(jindisk->meta->rit, pba, blk->lba);
		jindisk_write_blocks(pba, 1, buffer, DM_IO_KMEM);
	}
	kfree(buffer);
}

void segbuf_flush_bios(struct segment_buffer *buf, int index)
{
	struct default_segment_buffer *this = container_of(
		buf, struct default_segment_buffer, segment_buffer);
	struct data_segment *ds = &this->buffer[index];
	size_t count = ds->size;
	struct record *new;
	struct segment_block *blk;
	struct rb_node *node;
	dm_block_t start, pba;
	int i = 0, err = 0;

	if (!count)
		return;

	err = jindisk->seg_allocator->alloc(jindisk->seg_allocator,
					    &ds->cur_segment);
	if (err) {
		DMDEBUG("threaded_logging index:%u", index);
		segbuf_threaded_logging(ds);
		return;
	}
	start = ds->cur_segment * BLOCKS_PER_SEGMENT;
	for (node = rb_first(&ds->root); node; node = rb_next(node), i++) {
		blk = rb_entry(node, struct segment_block, node);

		pba = start + i;
		new = record_create(pba, ds->seg_key, NULL);
		jindisk->cipher->encrypt(
			jindisk->cipher, (char *)blk->plain_block,
			DATA_BLOCK_SIZE, new->key, NULL, new->mac, new->pba,
			(char *)(ds->cipher_segment) + i * DATA_BLOCK_SIZE);
		jindisk->lsm_tree->put(jindisk->lsm_tree, blk->lba, new);
		jindisk->meta->rit->set(jindisk->meta->rit, pba, blk->lba);
	}
	jindisk_write_blocks(start, count, ds->cipher_segment, DM_IO_VMA);
}

int segbuf_query_block(struct segment_buffer *buf, uint32_t lba, void *data_out)
{
	struct default_segment_buffer *this = container_of(
		buf, struct default_segment_buffer, segment_buffer);
	struct segment_block *blk;
	int i, j, index;

	down_read(&this->lock);
	for (i = 0, j = this->cur_buffer + POOL_SIZE; i < POOL_SIZE; i++) {
		index = (j - i) % POOL_SIZE;

		blk = data_segment_get(&this->buffer[index], lba);
		if (blk) {
			memcpy(data_out, blk->plain_block, DATA_BLOCK_SIZE);
			up_read(&this->lock);
			return 0;
		}
	}
	up_read(&this->lock);
	return -ENODATA;
}

void *segbuf_implementer(struct segment_buffer *buf)
{
	struct default_segment_buffer *this = container_of(
		buf, struct default_segment_buffer, segment_buffer);
	return this;
}

void segbuf_destroy(struct segment_buffer *buf)
{
	int i;
	struct default_segment_buffer *this = container_of(
		buf, struct default_segment_buffer, segment_buffer);

	buf->flush_bios(buf, this->cur_buffer);

	if (bufferio_wq)
		destroy_workqueue(bufferio_wq);

	for (i = 0; i < POOL_SIZE; i++)
		data_segment_destroy(&this->buffer[i]);

	kfree(this);
}

int segbuf_init(struct default_segment_buffer *buf)
{
	int i, err;

	bufferio_wq = alloc_workqueue("jindisk-buf", WQ_UNBOUND, 1);
	if (!bufferio_wq) {
		DMERR("alloc_workqueue jindisk-buf failed");
		err = -EAGAIN;
		goto bad;
	}
	init_rwsem(&buf->lock);
	for (i = 0; i < POOL_SIZE; i++)
		init_rwsem(&buf->rw_lock[i]);

	buf->cur_buffer = 0;
	err = data_segment_init(&buf->buffer[0]);
	if (err)
		goto bad;

	buf->segment_buffer.push_bio = segbuf_push_bio;
	buf->segment_buffer.push_block = segbuf_push_block;
	buf->segment_buffer.query_block = segbuf_query_block;
	buf->segment_buffer.flush_bios = segbuf_flush_bios;
	buf->segment_buffer.implementer = segbuf_implementer;
	buf->segment_buffer.destroy = segbuf_destroy;
	return 0;
bad:
	if (bufferio_wq)
		destroy_workqueue(bufferio_wq);

	data_segment_destroy(&buf->buffer[0]);
	return err;
}

struct segment_buffer *segbuf_create()
{
	int r;
	struct default_segment_buffer *buf;

	buf = kzalloc(sizeof(struct default_segment_buffer), GFP_KERNEL);
	if (!buf)
		return NULL;

	r = segbuf_init(buf);
	if (r)
		return NULL;

	return &buf->segment_buffer;
}
