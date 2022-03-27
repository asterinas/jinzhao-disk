#include <linux/bio.h>

#include "../include/dm_sworndisk.h"
#include "../include/segment_buffer.h"
#include "../include/bio_operate.h"
#include "../include/crypto.h"

#define DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE struct default_segment_buffer* this; \
                struct dm_sworndisk_target* sworndisk; \
                  this = container_of(buf, struct default_segment_buffer, segment_buffer); \
                    sworndisk = this->sworndisk;

// assume bio has only one segment
void segbuf_push_bio(struct segment_buffer* buf, struct bio *bio) {
    int r;
    struct record* record;
    sector_t lba, pba;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    if (this->cur_sector + bio_sectors(bio) >= SECTOES_PER_SEG) {
        buf->flush_bios(buf);
        r = sworndisk->seg_allocator->get_next_free_segment(sworndisk->seg_allocator, &this->cur_segment);
        if (r)
            return;
        this->cur_sector = 0;
    }
    
    lba = bio_get_sector(bio);
    pba = this->cur_segment * SECTOES_PER_SEG + this->cur_sector;

    record = record_create(pba, NULL, NULL, NULL);
    if (IS_ERR_OR_NULL(record))
        return;
    sworndisk->memtable->put(sworndisk->memtable, lba, record); 

    bio_get_data(bio, this->buffer + this->cur_sector * SECTOR_SIZE);
    this->cur_sector += 1;
}

void segbuf_flush_bios(struct segment_buffer* buf) {
    char* data;
    unsigned long sync_error_bits;
    struct dm_io_request req;
    struct dm_io_region region;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    data = kmalloc(SEGMENT_BUFFER_SIZE, GFP_KERNEL);
    if (!data) 
        return;
    
    memcpy(data, this->buffer, SEGMENT_BUFFER_SIZE);
    
    req.bi_op = req.bi_op_flags = REQ_OP_WRITE;
    req.mem.type = DM_IO_KMEM;
    req.mem.offset = 0;
    req.mem.ptr.addr = data;
    req.notify.fn = NULL;
    req.client = this->io_client;

    region.bdev = sworndisk->data_dev->bdev;
    region.sector = this->cur_segment * SECTOES_PER_SEG;
    region.count = SECTOES_PER_SEG;
    
    DMINFO("segment buffer flush: %ld", region.sector);
    dm_io(&req, 1, &region, &sync_error_bits);
    if (sync_error_bits) 
        DMERR("segment buffer flush error\n");
    
    kfree(data);
}

int segbuf_query_bio(struct segment_buffer* buf, struct bio* bio) {
    sector_t pba;
    sector_t begin, end;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    pba = bio_get_sector(bio);
    begin = this->cur_segment * SECTOES_PER_SEG;
    end = begin + this->cur_sector;

    if (pba < begin || pba >= end)
        return -ENODATA;
    
    bio_set_data(bio, this->buffer + (pba - begin)*SECTOR_SIZE, bio_get_data_len(bio));
    return 0;
}

void* segbuf_implementer(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    return this;
}

void segbuf_destroy(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    dm_io_client_destroy(this->io_client);
    kfree(this->buffer);
    kfree(this);
}

int segbuf_init(struct default_segment_buffer *buf, struct dm_sworndisk_target* sworndisk) {
    int r;

    r = sworndisk->seg_allocator->get_next_free_segment(sworndisk->seg_allocator, &buf->cur_segment);
    if (r)
        return r;

    buf->cur_sector = 0;
    buf->sworndisk = sworndisk;

    buf->buffer = kmalloc(SEGMENT_BUFFER_SIZE + SECTOR_SIZE, GFP_KERNEL);
    if (!buf->buffer)
        return -ENOMEM;
    buf->io_client = dm_io_client_create();
    buf->segment_buffer.push_bio = segbuf_push_bio;
    buf->segment_buffer.query_bio = segbuf_query_bio;
    buf->segment_buffer.flush_bios = segbuf_flush_bios;
    buf->segment_buffer.implementer = segbuf_implementer;
    buf->segment_buffer.destroy = segbuf_destroy;

    return 0;
};

struct segment_buffer* segbuf_create(struct dm_sworndisk_target* sworndisk) {
    int r;
    struct default_segment_buffer* buf;

    buf = kmalloc(sizeof(struct default_segment_allocator), GFP_KERNEL);
    if (!buf)
        return NULL;
    
    r = segbuf_init(buf, sworndisk);
    if (r)
        return NULL;
    return &buf->segment_buffer;
}