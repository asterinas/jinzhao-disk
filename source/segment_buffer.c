#include <linux/bio.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"
#include "../include/bio_operate.h"
#include "../include/crypto.h"

#define INF_SEGNO (~0ULL)

struct bufferio_work {
	struct work_struct work;
	void *segbuf;
	int index;
};
static struct workqueue_struct *bufferio_wq;

void btox(char *xp, const char *bb, int n)  {
    const char xx[]= "0123456789ABCDEF";
    while (--n >= 0) xp[n] = xx[(bb[n>>1] >> ((1 - (n&1)) << 2)) & 0xF];
}

struct segment_block *segment_block_new(uint32_t lba)
{
	struct segment_block *blk = kzalloc(sizeof(struct segment_block), GFP_KERNEL);

	if (!blk) {
		DMERR("segment_block_new kzalloc segment_block failed\n");
		return NULL;
	}
	blk->lba = lba;
	blk->plain_block = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
	if (!blk->plain_block) {
		DMERR("segment_block_new kzalloc plain_block failed\n");
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
	struct segment_block *node_blk = rb_entry(node, struct segment_block, node);
	struct segment_block *node_parent = rb_entry(parent, struct segment_block, node);

	return (int64_t)node_blk->lba - (int64_t)node_parent->lba;
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
	int err = 0;

	ds->size = 0;
	ds->root = RB_ROOT;
	get_random_bytes(ds->seg_key, sizeof(ds->seg_key));
	ds->cipher_segment = vmalloc(SEGMENT_BUFFER_SIZE);
	if (!ds->cipher_segment) {
		DMERR("data_segment_init failed\n");
		return -ENOMEM;
	}
	err = sworndisk->seg_allocator->alloc(sworndisk->seg_allocator,
					      &ds->cur_segment);
	return err;
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

int segbuf_push_bio(struct segment_buffer* buf, struct bio *bio)
{
	struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer,
							   segment_buffer);

	while (bio->bi_iter.bi_size) {
		struct bio_vec bv = bio_iter_iovec(bio, bio->bi_iter);
		dm_block_t lba = bio_get_block_address(bio);
		struct segment_block *blk = NULL;
		int cur = this->cur_buffer;
		void *data_in = page_address(bv.bv_page);

		down_write(&this->rw_lock[cur]);
		blk = data_segment_get(&this->buffer[cur], lba);
		if (blk) {
			memcpy(blk->plain_block, data_in, DATA_BLOCK_SIZE);
		} else {
			buf->push_block(buf, lba, data_in);
		}
		up_write(&this->rw_lock[cur]);

		bio_advance_iter(bio, &bio->bi_iter, DATA_BLOCK_SIZE);
	}

	sworndisk->seg_allocator->foreground_gc(sworndisk->seg_allocator);
	return 0;
}

void bufferio_handler(struct work_struct *ws)
{
	struct bufferio_work *bw = container_of(ws, struct bufferio_work, work);
	struct segment_buffer *buf = bw->segbuf;
	struct default_segment_buffer *this = container_of(buf, struct default_segment_buffer,
							   segment_buffer);
	down_read(&this->rw_lock[bw->index]);
	buf->flush_bios(buf, bw->index);
	up_read(&this->rw_lock[bw->index]);
	kfree(bw);
}

void segbuf_push_block(struct segment_buffer *buf, dm_block_t lba, void *buffer)
{
	struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer,
							   segment_buffer);
	struct bufferio_work *bw;
	struct segment_block *blk;
	int cur = this->cur_buffer;

	blk = segment_block_new(lba);
	if (!blk) {
		return;
	}
	memcpy(blk->plain_block, buffer, DATA_BLOCK_SIZE);
	data_segment_add(&this->buffer[cur], blk);
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
}

void segbuf_flush_bios(struct segment_buffer* buf, int index)
{
	struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer,
							   segment_buffer);
	struct data_segment *ds = &this->buffer[index];
	dm_block_t blkaddr = ds->cur_segment * BLOCKS_PER_SEGMENT;
	size_t count = ds->size;
	struct record *new, old;
	struct segment_block *blk;
	struct rb_node *node;
	dm_block_t pba;
	int err = 0, i = 0;

	if (!count)
		return;

	for (node = rb_first(&ds->root); node; node = rb_next(node), i++) {
		blk = rb_entry(node, struct segment_block, node);

		err = sworndisk->lsm_tree->search(sworndisk->lsm_tree, blk->lba, &old);
		if (!err)
			sworndisk->meta->dst->return_block(sworndisk->meta->dst, old.pba);

		pba = blkaddr + i;
		new = record_create(pba, ds->seg_key, NULL);
		sworndisk->cipher->encrypt(sworndisk->cipher, (char *)blk->plain_block,
					   DATA_BLOCK_SIZE, new->key, NULL, new->mac,
					   new->pba, (char *)(ds->cipher_segment) +
					   i * DATA_BLOCK_SIZE);
		sworndisk->lsm_tree->put(sworndisk->lsm_tree, blk->lba, new);
		sworndisk->meta->rit->set(sworndisk->meta->rit, pba, blk->lba);
	}
	sworndisk_write_blocks(blkaddr, count, ds->cipher_segment, DM_IO_VMA);
}

int segbuf_query_block(struct segment_buffer* buf, uint32_t lba, void *data_out)
{
	struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer,
							   segment_buffer);
	struct segment_block *blk;
	int i, j, index;

	for (i = 0, j = this->cur_buffer + POOL_SIZE; i < POOL_SIZE; i++) {
		index = (j - i) % POOL_SIZE;

		down_read(&this->rw_lock[index]);
		blk = data_segment_get(&this->buffer[index], lba);
		if (blk) {
			memcpy(data_out, blk->plain_block, DATA_BLOCK_SIZE);
			up_read(&this->rw_lock[index]);
			return 0;
		}
		up_read(&this->rw_lock[index]);
	}
	return -ENODATA;
}

void* segbuf_implementer(struct segment_buffer* buf) {
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);

    return this;
}

void segbuf_destroy(struct segment_buffer* buf) {
	int i;
	struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);

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

	bufferio_wq = alloc_workqueue("kxdisk-segbuf", WQ_UNBOUND, POOL_SIZE);
	if (!bufferio_wq) {
		DMERR("alloc_workqueue kxdisk-segbuf failed\n");
		err = -EAGAIN;
		goto bad;
	}
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

struct segment_buffer* segbuf_create() {
    int r;
    struct default_segment_buffer* buf;

    buf = kzalloc(sizeof(struct default_segment_buffer), GFP_KERNEL);
    if (!buf)
        return NULL;
    
    r = segbuf_init(buf);
    if (r)
        return NULL;
    return &buf->segment_buffer;
}
