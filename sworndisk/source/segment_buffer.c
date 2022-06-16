#include <linux/bio.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"
#include "../include/bio_operate.h"
#include "../include/crypto.h"

void btox(char *xp, const char *bb, int n)  {
    const char xx[]= "0123456789ABCDEF";
    while (--n >= 0) xp[n] = xx[(bb[n>>1] >> ((1 - (n&1)) << 2)) & 0xF];
}

int segbuf_push_bio(struct segment_buffer* buf, struct bio *bio) {
    int err = 0;
    void *buffer, *pipe;
    struct record record = {0};
    dm_block_t lba = bio_get_block_address(bio);
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);

    buffer = this->buffer + this->cur_sector * SECTOR_SIZE;
    pipe = this->pipe + this->cur_sector * SECTOR_SIZE;

    if (bio_sectors(bio) >= SECTORS_PER_BLOCK)
        goto fill_buffer;

    err = sworndisk->lsm_tree->search(sworndisk->lsm_tree, lba, &record);
    if (!err) {
        dm_block_t buf_begin, buf_end;

        buf_begin = this->cur_segment * BLOCKS_PER_SEGMENT;
        buf_end = buf_begin + this->cur_sector / SECTORS_PER_BLOCK;
        if (record.pba < buf_begin || record.pba >= buf_end) {
            sworndisk_read_blocks(record.pba, 1, buffer, DM_IO_VMA);
            sworndisk->cipher->decrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE, 
                record.key, record.iv, record.mac, record.pba, buffer);
        } else {
            buffer = this->buffer + (record.pba - buf_begin) * DATA_BLOCK_SIZE;
            pipe = this->pipe + (record.pba - buf_begin) * DATA_BLOCK_SIZE;
            bio_get_data(bio, buffer + bio_block_sector_offset(bio) * SECTOR_SIZE, bio_get_data_len(bio));
            sworndisk->cipher->encrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE, 
                record.key, record.iv, record.mac, record.pba, pipe);
            sworndisk->lsm_tree->put(sworndisk->lsm_tree, lba, record_copy(&record));
            return MODIFY_IN_MEM_BUFFER;
        }
    }

fill_buffer:
    bio_get_data(bio, buffer + bio_block_sector_offset(bio) * SECTOR_SIZE, bio_get_data_len(bio));
    buf->push_block(buf, lba, buffer);
    return PUSH_NEW_BLOCK;
}

dm_block_t next_block(struct default_segment_buffer* this, bool threaded_logging) {
    struct victim victim;
    size_t offset;
    dm_block_t blkaddr;

    if (!threaded_logging)
        return (this->cur_segment * SECTOES_PER_SEGMENT + this->cur_sector) / SECTORS_PER_BLOCK;
    
    victim = *sworndisk->meta->dst->peek_victim(sworndisk->meta->dst);
    offset = find_first_zero_bit(victim.block_validity_table, BLOCKS_PER_SEGMENT);
    blkaddr = victim.segno * BLOCKS_PER_SEGMENT + offset;
    sworndisk->meta->dst->take_block(sworndisk->meta->dst, blkaddr);
    return blkaddr;
} 

void segbuf_push_block(struct segment_buffer* buf, dm_block_t lba, void* buffer) {
    int err = 0;
    dm_block_t pba;
    void *pipe = NULL, *block = NULL;
    struct record *record, pre;
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);
    bool threaded_logging = sworndisk_should_threaded_logging();

    err = sworndisk->lsm_tree->search(sworndisk->lsm_tree, lba, &pre);
    if (!err)
        sworndisk->meta->dst->return_block(sworndisk->meta->dst, pre.pba);

    pba = next_block(this, threaded_logging);
    record = record_create(pba, NULL, NULL, NULL);
    block = this->buffer + this->cur_sector * SECTOR_SIZE;
    memmove(block, buffer, DATA_BLOCK_SIZE);
    pipe = this->pipe + this->cur_sector * SECTOR_SIZE;
    sworndisk->cipher->encrypt(sworndisk->cipher, block, DATA_BLOCK_SIZE, 
        record->key, record->iv, record->mac, record->pba, pipe);

    sworndisk->lsm_tree->put(sworndisk->lsm_tree, lba, record);
    sworndisk->meta->rit->set(sworndisk->meta->rit, pba, lba);

    if (threaded_logging) {
        sworndisk_write_blocks(pba, 1, pipe, DM_IO_VMA);
        return;
    }

    this->cur_sector += SECTORS_PER_BLOCK;
    if (this->cur_sector >= SECTOES_PER_SEGMENT) {
        buf->flush_bios(buf);
        this->cur_sector = 0;
        sworndisk->seg_allocator->alloc(sworndisk->seg_allocator, &this->cur_segment);
    }
}

void segbuf_flush_bios(struct segment_buffer* buf) {
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);
    dm_block_t blkaddr = this->cur_segment * BLOCKS_PER_SEGMENT;

    sworndisk_write_blocks(blkaddr, BLOCKS_PER_SEGMENT, this->pipe, DM_IO_VMA);
}

int segbuf_query_bio(struct segment_buffer* buf, struct bio* bio) {
    sector_t bi_sector, begin, end;
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);

    bi_sector = bio_get_sector(bio);
    begin = this->cur_segment * SECTOES_PER_SEGMENT;
    end = begin + this->cur_sector;

    if (bi_sector < begin || bi_sector + bio_sectors(bio) > end)
        return -ENODATA;

    bio_set_data(bio, this->buffer + (bi_sector - begin) * SECTOR_SIZE, bio_get_data_len(bio));
    return 0;
}

int segbuf_query_encrypted_block(struct segment_buffer* buf, dm_block_t blkaddr, void* buffer) {
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);
    dm_block_t begin = this->cur_segment * BLOCKS_PER_SEGMENT;
    dm_block_t end = begin + div_u64(this->cur_sector, SECTORS_PER_BLOCK);

    if (blkaddr < begin || blkaddr >= end)
        return -ENODATA;
    
    memcpy(buffer, this->pipe + (blkaddr - begin) * DATA_BLOCK_SIZE, DATA_BLOCK_SIZE);
    return 0;
}

int segbuf_query_encrypted_blocks(struct segment_buffer* buf, dm_block_t blkaddr, size_t count, void* buffer) {
    size_t i;

    for (i = 0; i < count; ++i) 
        segbuf_query_encrypted_block(buf, blkaddr + i, buffer + i * DATA_BLOCK_SIZE);
    return 0;
}

void* segbuf_implementer(struct segment_buffer* buf) {
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);

    return this;
}

void segbuf_destroy(struct segment_buffer* buf) {
    struct default_segment_buffer* this = container_of(buf, struct default_segment_buffer, segment_buffer);

    buf->flush_bios(buf);
    vfree(this->buffer);
    vfree(this->pipe);
    kfree(this);
}

int segbuf_init(struct default_segment_buffer *buf) {
    int err;

    err = sworndisk->seg_allocator->alloc(sworndisk->seg_allocator, &buf->cur_segment);
    if (err)
        return err;

    buf->cur_sector = 0;
    buf->buffer = vmalloc(SEGMENT_BUFFER_SIZE);
    if (!buf->buffer) {
        err = -ENOMEM;
        goto bad;
    }

    buf->pipe = vmalloc(SEGMENT_BUFFER_SIZE);
    if (!buf->pipe) {
        err = -ENOMEM;
        goto bad;
    }

    buf->segment_buffer.push_bio = segbuf_push_bio;
    buf->segment_buffer.push_block = segbuf_push_block;
    buf->segment_buffer.query_bio = segbuf_query_bio;
    buf->segment_buffer.flush_bios = segbuf_flush_bios;
    buf->segment_buffer.implementer = segbuf_implementer;
    buf->segment_buffer.destroy = segbuf_destroy;

    return 0;

bad:
    if (buf->buffer)
        vfree(buf->buffer);
    if (buf->pipe)
        vfree(buf->pipe);
    return err;
};

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