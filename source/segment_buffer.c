#include <linux/bio.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"
#include "../include/bio_operate.h"
#include "../include/crypto.h"

#define INF_SEGNO (~0ULL)

void btox(char *xp, const char *bb, int n)  {
    const char xx[]= "0123456789ABCDEF";
    while (--n >= 0) xp[n] = xx[(bb[n>>1] >> ((1 - (n&1)) << 2)) & 0xF];
}

int pba_in_segbuf(struct default_segment_buffer* this, dm_block_t pba)
{
	int i;
	size_t segno = pba >> 10;

	for (i = 0; i < POOL_SIZE; i++) {
		if (this->cur_segment[i] == segno)
			return i;
	}
	return -ENODATA;
}

int segbuf_push_bio(struct segment_buffer* buf, struct bio *bio) {
    int err = 0, cur;
    void *buffer, *pipe;
    struct record record = {0};
    dm_block_t lba = bio_get_block_address(bio);
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);

    down_write(&this->rw_lock);
    cur = this->cur_buffer;

    err = sworndisk->lsm_tree->search(sworndisk->lsm_tree, lba, &record);
    if (!err && this->cur_segment[cur] == (record.pba >> 10)) {
        buffer = this->buffer[cur] + (record.pba % BLOCKS_PER_SEGMENT) * DATA_BLOCK_SIZE;
        pipe = this->pipe[cur] + (record.pba % BLOCKS_PER_SEGMENT) * DATA_BLOCK_SIZE;
        bio_get_data(bio, buffer + bio_block_sector_offset(bio) * SECTOR_SIZE, bio_get_data_len(bio));
        sworndisk->cipher->encrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE,
                record.key, record.iv, record.mac, record.pba, pipe);
        sworndisk->lsm_tree->put(sworndisk->lsm_tree, lba, record_copy(&record));
        up_write(&this->rw_lock);
        return MODIFY_IN_MEM_BUFFER;
    }
    if (!err)
	    sworndisk->meta->dst->return_block(sworndisk->meta->dst, record.pba);

    buffer = this->buffer[cur] + this->cur_sector[cur] * SECTOR_SIZE;
    bio_get_data(bio, buffer + bio_block_sector_offset(bio) * SECTOR_SIZE, bio_get_data_len(bio));
    buf->push_block(buf, lba, buffer);
    up_write(&this->rw_lock);
    if (cur != this->cur_buffer)
	    buf->flush_bios(buf, cur);

    sworndisk->seg_allocator->foreground_gc(sworndisk->seg_allocator);
    return PUSH_NEW_BLOCK;
}

dm_block_t next_block(struct default_segment_buffer* this, int index, bool threaded_logging)
{
    struct victim victim;
    size_t offset;
    dm_block_t blkaddr;

    if (!threaded_logging)
        return (this->cur_segment[index] * SECTOES_PER_SEGMENT + this->cur_sector[index]) / SECTORS_PER_BLOCK;
    
    victim = *sworndisk->meta->dst->peek_victim(sworndisk->meta->dst);
    offset = find_first_zero_bit(victim.block_validity_table, BLOCKS_PER_SEGMENT);
    blkaddr = victim.segno * BLOCKS_PER_SEGMENT + offset;
    sworndisk->meta->dst->take_block(sworndisk->meta->dst, blkaddr);
    return blkaddr;
} 

void segbuf_push_block(struct segment_buffer* buf, dm_block_t lba, void* buffer)
{
    dm_block_t pba;
    void *pipe = NULL, *block = NULL;
    struct record *record;
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);
    bool threaded_logging = sworndisk_should_threaded_logging();
    int cur = this->cur_buffer;

    pba = next_block(this, cur, threaded_logging);
    record = record_create(pba, NULL, NULL, NULL);
    block = this->buffer[cur] + this->cur_sector[cur] * SECTOR_SIZE;
    if (block != buffer)
	memmove(block, buffer, DATA_BLOCK_SIZE);

    pipe = this->pipe[cur] + this->cur_sector[cur] * SECTOR_SIZE;
    sworndisk->cipher->encrypt(sworndisk->cipher, block, DATA_BLOCK_SIZE, 
			record->key, record->iv, record->mac, record->pba, pipe);

    sworndisk->lsm_tree->put(sworndisk->lsm_tree, lba, record);
    sworndisk->meta->rit->set(sworndisk->meta->rit, pba, lba);

    if (threaded_logging) {
        sworndisk_write_blocks(pba, 1, pipe, DM_IO_VMA);
        return;
    }

    this->cur_sector[cur] += SECTORS_PER_BLOCK;
    if (this->cur_sector[cur] >= SECTOES_PER_SEGMENT) {
	this->cur_buffer = (cur + 1) % POOL_SIZE;
        sworndisk->seg_allocator->alloc(sworndisk->seg_allocator, &this->cur_segment[this->cur_buffer]);
	this->cur_sector[this->cur_buffer] = 0;
    }
}

void segbuf_flush_bios(struct segment_buffer* buf, int index) {
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);
    dm_block_t blkaddr = this->cur_segment[index] * BLOCKS_PER_SEGMENT;
    size_t count = (this->cur_sector[index] - 1) / SECTORS_PER_BLOCK + 1;

    if (this->cur_sector[index])
	    sworndisk_write_blocks(blkaddr, count, this->pipe[index], DM_IO_VMA);
}

int segbuf_query_bio(struct segment_buffer* buf, struct bio* bio, dm_block_t pba) {
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);
    int index;

    down_read(&this->rw_lock);
    index = pba_in_segbuf(this, pba);
    if (index < 0) {
	    up_read(&this->rw_lock);
	    return -ENODATA;
    }
    bio_set_data(bio, this->buffer[index] + (pba % BLOCKS_PER_SEGMENT) * DATA_BLOCK_SIZE, bio_get_data_len(bio));
    up_read(&this->rw_lock);
    return 0;
}

void* segbuf_implementer(struct segment_buffer* buf) {
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);

    return this;
}

void segbuf_destroy(struct segment_buffer* buf) {
	int i;
	struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);

	for (i = 0; i < POOL_SIZE; i++)
		buf->flush_bios(buf, i);

	for (i = 0; i < POOL_SIZE; i++) {
		vfree(this->buffer[i]);
		vfree(this->pipe[i]);
	}
	kfree(this);
}

int segbuf_init(struct default_segment_buffer *buf)
{
	int i, err;

	for (i = 0; i < POOL_SIZE; i++) {
		buf->cur_segment[i] = INF_SEGNO;
		buf->cur_sector[i] = 0;

		buf->buffer[i] = vmalloc(SEGMENT_BUFFER_SIZE);
		if (!buf->buffer[i]) {
			err = -ENOMEM;
			goto bad;
		}

		buf->pipe[i] = vmalloc(SEGMENT_BUFFER_SIZE);
		if (!buf->pipe[i]) {
			err = -ENOMEM;
			goto bad;
		}
	}
	buf->cur_buffer = 0;
	err = sworndisk->seg_allocator->alloc(sworndisk->seg_allocator,
					      &buf->cur_segment[0]);
	if (err)
		goto bad;

	init_rwsem(&buf->rw_lock);
	buf->segment_buffer.push_bio = segbuf_push_bio;
	buf->segment_buffer.push_block = segbuf_push_block;
	buf->segment_buffer.query_bio = segbuf_query_bio;
	buf->segment_buffer.flush_bios = segbuf_flush_bios;
	buf->segment_buffer.implementer = segbuf_implementer;
	buf->segment_buffer.destroy = segbuf_destroy;

	return 0;
bad:
	for (i = 0; i < POOL_SIZE; i++) {
		if (buf->buffer[i])
			vfree(buf->buffer[i]);
		if (buf->pipe[i])
			vfree(buf->pipe[i]);
	}
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
