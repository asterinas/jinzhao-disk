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
    char* data;
    struct cache_entry* entry;
    struct mt_value* mv;
    sector_t lba, pba;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    if (this->cur_sector + bio_sectors(bio) >= SEC_PER_SEG) {
        // init_completion(&this->comp);
        // schedule_work(&this->flush_worker);
        // wait_for_completion(&this->comp);
        buf->flush_bios(buf);
        this->cur_segment += 1;
        this->cur_sector = 0;
    }
    
    lba = bio_get_sector(bio);
    pba = this->cur_segment * SEC_PER_SEG + this->cur_sector;

    data = bio_data_copy(bio);
    if (IS_ERR_OR_NULL(data))
        return;
    entry = cache_entry_create(pba, data, bio_get_data_len(bio), true);
    if (IS_ERR_OR_NULL(entry))
        return;
    sworndisk->cache->set(sworndisk->cache, pba, entry);

    mv = mt_value_create(pba, NULL, NULL, NULL);
    if (IS_ERR_OR_NULL(mv))
        return;
    sworndisk->memtable->put(sworndisk->memtable, lba, mv); 

    bio_get_data(bio, this->buffer + this->cur_sector * SECTOR_SIZE);
    this->cur_sector += 1;
}

void segbuf_flush_endio(struct bio* bio) {
    size_t shift;
    struct segbuf_flush_context* ctx;

    ctx = bio->bi_private;
    bio->bi_iter = ctx->bi_iter;
    for (shift=0; shift<SEC_PER_SEG; ++shift)
        ctx->sworndisk->cache->delete(ctx->sworndisk->cache, bio_get_sector(bio) + shift);
    bio_free_pages(bio);
    bio_put(bio);
    kfree(ctx);
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
    region.sector = this->cur_segment * SEC_PER_SEG;
    region.count = SEC_PER_SEG;
    
    dm_io(&req, 1, &region, &sync_error_bits);
    if (sync_error_bits) 
        DMERR("segment buffer flush error\n");
    
    kfree(data);
}

// void segbuf_flush_bios(struct segment_buffer* buf) {
//     size_t nr_segment;
//     struct page* pages;
//     struct bio* bio;
//     struct segbuf_flush_context* ctx;
//     DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

//     ctx = kmalloc(sizeof(struct segbuf_flush_context), GFP_KERNEL);
//     if (!ctx)
//         return;

//     nr_segment = SEGMENT_BUFFER_SIZE / PAGE_SIZE;
//     bio = bio_alloc(GFP_KERNEL, nr_segment);
//     if (IS_ERR_OR_NULL(bio))
//         return;

//     pages = alloc_pages(GFP_KERNEL, get_order(SEGMENT_BUFFER_SIZE));
//     if (IS_ERR_OR_NULL(pages))
//         return;

//     memcpy(page_address(pages), this->buffer, SEGMENT_BUFFER_SIZE);
//     bio_set_sector(bio, this->cur_segment * SEC_PER_SEG);

//     bio->bi_opf |= REQ_OP_WRITE;
//     bio_set_dev(bio, sworndisk->data_dev->bdev);
//     bio_fill_pages(bio, pages, nr_segment);
//     ctx->bi_iter = bio->bi_iter;
//     ctx->sworndisk = this->sworndisk;
//     bio->bi_private = ctx;
//     bio->bi_end_io = segbuf_flush_endio;
//     submit_bio_wait(bio);
// }

void segbuf_flush_work(struct work_struct* ws) {
    struct default_segment_buffer* this;

    this = container_of(ws, struct default_segment_buffer, flush_worker);
    this->segment_buffer.flush_bios(&this->segment_buffer);
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
    buf->cur_segment = 0;
    buf->cur_sector = 0;
    buf->sworndisk = sworndisk;

    buf->buffer = kmalloc(SEGMENT_BUFFER_SIZE + SECTOR_SIZE, GFP_KERNEL);
    if (!buf->buffer)
        return -ENOMEM;
    buf->io_client = dm_io_client_create();
    INIT_WORK(&buf->flush_worker, segbuf_flush_work);
    buf->segment_buffer.push_bio = segbuf_push_bio;
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