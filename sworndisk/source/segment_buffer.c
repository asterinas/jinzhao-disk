#include <linux/bio.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"
#include "../include/bio_operate.h"
#include "../include/crypto.h"

#define DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE struct default_segment_buffer* this; \
                struct dm_sworndisk_target* sworndisk; \
                  this = container_of(buf, struct default_segment_buffer, segment_buffer); \
                    sworndisk = this->sworndisk;

// assume bio has only one segment
void segbuf_push_bio(struct segment_buffer* buf, struct bio *bio) {
    dm_block_t lba;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE
    
    lba = bio_get_block_address(bio);
    bio_get_data(bio, this->buffer + (this->cur_sector + bio_block_sector_offset(bio)) * SECTOR_SIZE, bio_get_data_len(bio));
    buf->push_block(buf, lba, this->buffer + this->cur_sector * SECTOR_SIZE);
}

void segbuf_push_block(struct segment_buffer* buf, dm_block_t lba, void* buffer) {
    int r;
    dm_block_t pba;
    bool replaced;
    struct record* record, old;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    pba = (this->cur_segment * SECTOES_PER_SEGMENT + this->cur_sector) / SECTORS_PER_BLOCK;    
    record = record_create(pba, NULL, NULL, NULL);
    if (IS_ERR_OR_NULL(record))
        return;

    sworndisk->lsm_tree->put(sworndisk->lsm_tree, lba, record, sizeof(struct record), &replaced, &old);
    if (replaced) {
        sworndisk->metadata->data_segment_table->return_block(sworndisk->metadata->data_segment_table, old.pba);
    }

    if ((this->buffer + this->cur_sector * SECTOR_SIZE) != buffer) {
        memcpy(this->buffer + this->cur_sector * SECTOR_SIZE, buffer, DATA_BLOCK_SIZE);
    } 
    sworndisk->metadata->reverse_index_table->set(sworndisk->metadata->reverse_index_table, pba, lba);

    this->cur_sector += SECTORS_PER_BLOCK;
    if (this->cur_sector >= SECTOES_PER_SEGMENT) {
        buf->flush_bios(buf);
        this->cur_sector = 0;
        r = sworndisk->seg_allocator->get_next_free_segment(sworndisk->seg_allocator, &this->cur_segment);
        if (r)
            return;
    }
}

void segbuf_flush_bios(struct segment_buffer* buf) {
    unsigned long sync_error_bits;
    struct dm_io_request req;
    struct dm_io_region region;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE
    
    memcpy(this->pipe, this->buffer, SEGMENT_BUFFER_SIZE);

    req.bi_op = req.bi_op_flags = REQ_OP_WRITE;
    req.mem.type = DM_IO_KMEM;
    req.mem.offset = 0;
    req.mem.ptr.addr = this->pipe;
    req.notify.fn = NULL;
    req.client = this->io_client;

    region.bdev = sworndisk->data_dev->bdev;
    region.sector = this->cur_segment * SECTOES_PER_SEGMENT;
    region.count = SECTOES_PER_SEGMENT;

    dm_io(&req, 1, &region, &sync_error_bits);
    if (sync_error_bits) 
        DMERR("segment buffer flush error\n");
}

int segbuf_query_bio(struct segment_buffer* buf, struct bio* bio) {
    sector_t bi_sector;
    sector_t begin, end;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    bi_sector = bio_get_sector(bio);
    begin = this->cur_segment * SECTOES_PER_SEGMENT;
    end = begin + this->cur_sector;

    if (bi_sector < begin || bi_sector + bio_sectors(bio) > end)
        return -ENODATA;
    
    bio_set_data(bio, this->buffer + (bi_sector - begin)*SECTOR_SIZE, bio_get_data_len(bio));
    return 0;
}

void* segbuf_implementer(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    return this;
}

void segbuf_destroy(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    buf->flush_bios(buf);
    dm_io_client_destroy(this->io_client);
    kfree(this->buffer);
    kfree(this->pipe);
    kfree(this);
}

int segbuf_init(struct default_segment_buffer *buf, struct dm_sworndisk_target* sworndisk) {
    int err;

    err = sworndisk->seg_allocator->get_next_free_segment(sworndisk->seg_allocator, &buf->cur_segment);
    if (err)
        return err;

    buf->cur_sector = 0;
    buf->sworndisk = sworndisk;

    buf->buffer = kmalloc(SEGMENT_BUFFER_SIZE, GFP_KERNEL);
    if (!buf->buffer) {
        err = -ENOMEM;
        goto bad;
    }
       

    buf->pipe = kmalloc(SEGMENT_BUFFER_SIZE, GFP_KERNEL);
    if (!buf->pipe) {
        err = -ENOMEM;
        goto bad;
    }
        

    buf->io_client = dm_io_client_create();
    if (IS_ERR_OR_NULL(buf->io_client)) {
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
        kfree(buf->buffer);
    if (buf->pipe)
        kfree(buf->pipe);
    return err;
};

struct segment_buffer* segbuf_create(struct dm_sworndisk_target* sworndisk) {
    int r;
    struct default_segment_buffer* buf;

    buf = kzalloc(sizeof(struct default_segment_buffer), GFP_KERNEL);
    if (!buf)
        return NULL;
    
    r = segbuf_init(buf, sworndisk);
    if (r)
        return NULL;
    return &buf->segment_buffer;
}