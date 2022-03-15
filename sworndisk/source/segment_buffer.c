#include <linux/bio.h>

#include "../include/dm_sworndisk.h"
#include "../include/segment_buffer.h"
#include "../include/bio_operate.h"
#include "../include/crypto.h"

#define DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE struct default_segment_buffer* this; \
                this = container_of(buf, struct default_segment_buffer, segment_buffer);

int segbuf_push_bio(struct segment_buffer* buf, struct bio *bio) {
    int r;
    sector_t pba;
    bool should_flush;
    struct bio_async_io_context* io_ctx;
    unsigned long flags;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    r = this->sa->alloc_sectors(this->sa, bio, &pba, &should_flush);
    if (r) {
        DMERR("alloc_sectors error");
        return r;
    }
        

    if (should_flush) 
        schedule_work(&this->flush_bio_work);


    // rediret bio
    bio_set_sector(bio, pba);
    io_ctx = bio->bi_private;
    io_ctx->pba = pba;
    // update reverse index table
    // this->sa->write_reverse_index_table(this->sa, pba, lba);
    spin_lock_irqsave(&this->lock, flags);
	bio_list_add(&this->bios, bio);
    spin_unlock_irqrestore(&this->lock, flags);
    // buf->flush_bios(buf);
    return 0;
}

void segbuf_flush_bio_endio(struct bio* bio) {
    struct bio* crypted;
    struct bio_list* bios;

    bios = bio->bi_private;
    while ((crypted = bio_list_pop(bios)))
        bio_endio(crypted);
    if (!IS_ERR_OR_NULL(bios))
        kfree(bios);
    bio_put(bio);
}

#define BIO_FLUSH_BATCH 300
void segbuf_flush_bios(struct segment_buffer* buf) {
    size_t i;
    int64_t nr_allocted_segment;
    int64_t nr_pending_segment;
    struct bio* bio;
    struct bio* merged_bio;
    struct bio_list bios;
    struct bio_list* crypted_bios;
    struct bio_async_io_context* io_ctx;
    unsigned long flags;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    if (bio_list_empty(&this->bios)) 
        return;

    bio_list_init(&bios);
    spin_lock_irqsave(&this->lock, flags);
	bio_list_merge(&bios, &this->bios);
    bio_list_init(&this->bios);
    spin_unlock_irqrestore(&this->lock, flags);

    nr_pending_segment = bio_list_size(&bios);
    while(nr_pending_segment > 0) {
        crypted_bios = kmalloc(sizeof(struct bio_list), GFP_KERNEL);
        if (!crypted_bios)
            goto bad;
        bio_list_init(crypted_bios);
        nr_allocted_segment = BIO_FLUSH_BATCH;
        if (nr_pending_segment < nr_allocted_segment)
            nr_allocted_segment = nr_pending_segment;
        merged_bio = bio_alloc_bioset(GFP_KERNEL, nr_allocted_segment, this->bio_set);
        if (IS_ERR_OR_NULL(merged_bio)) {
            // DMINFO("merged_bio bio_alloc error");
            goto bad;
        }
            
        i = 0;
        while (i < nr_allocted_segment && (bio = bio_list_pop(&bios))) {
            bio_crypt(bio);
            bio_list_add(crypted_bios, bio);
            bio_add_page(merged_bio, bio_page(bio), bio_get_data_len(bio), bio_offset(bio));
            ++i;
        }
        bio_set_dev(merged_bio, this->data_dev->bdev);
        bio_set_sector(merged_bio, bio_get_sector(bio_list_peek(crypted_bios)));
        merged_bio->bi_private = crypted_bios;
        merged_bio->bi_end_io = segbuf_flush_bio_endio;
        DMINFO("pba: %d, nr_sector: %d", bio_get_sector(merged_bio), bio_sectors(merged_bio));
        generic_make_request(merged_bio);

        nr_pending_segment -= nr_allocted_segment;
    }
    return;
bad:
    while ((bio = bio_list_pop(&bios))) {
        // DMINFO("flush bio, pba: %d", bio_get_sector(bio));
        // async write work schedule
        io_ctx = bio->bi_private;
        queue_work(io_ctx->wq, &io_ctx->work);
    }
}

void* segbuf_implementer(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    return this;
}

void segbuf_destroy(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    if (this->sa)
        this->sa->destroy(this->sa);
    kfree(this);
}

void segbuf_flush_bio_work(struct work_struct* ws) {
    struct default_segment_buffer* this;

    this = container_of(ws, struct default_segment_buffer, flush_bio_work);
    this->segment_buffer.flush_bios(&this->segment_buffer);
}

struct segment_buffer* segbuf_init(struct default_segment_buffer *buf,
  struct dm_dev* data_dev, struct dm_sworndisk_metadata *metadata, size_t nr_segment) {
    if (IS_ERR_OR_NULL(buf))
        return NULL;

    bio_list_init(&buf->bios);
    buf->data_dev = data_dev;
    buf->mt = hash_memtable_init(kmalloc(sizeof(struct hash_memtable), GFP_KERNEL));
    if (!buf->mt)
        return NULL;
    buf->cipher = aes_gcm_cipher_init(kmalloc(sizeof(struct aes_gcm_cipher), GFP_KERNEL));
    if (IS_ERR_OR_NULL(buf->cipher))
        return NULL; 
    buf->sa = sa_init(kmalloc(sizeof(struct default_segment_allocator), GFP_KERNEL), metadata, nr_segment);
    if (IS_ERR_OR_NULL(buf->sa))
        return NULL; 
    buf->bio_set = bioset_create(BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
    if (IS_ERR_OR_NULL(buf->bio_set))
        return NULL;

    spin_lock_init(&buf->lock);
    INIT_WORK(&buf->flush_bio_work, segbuf_flush_bio_work);
    buf->segment_buffer.push_bio = segbuf_push_bio;
    buf->segment_buffer.flush_bios = segbuf_flush_bios;
    buf->segment_buffer.implementer = segbuf_implementer;
    buf->segment_buffer.destroy = segbuf_destroy;
    return &buf->segment_buffer;
};
