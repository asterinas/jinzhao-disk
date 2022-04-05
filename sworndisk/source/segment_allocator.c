#include <linux/dm-io.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"
#include "../include/segment_allocator.h"

#define DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE struct default_segment_allocator* this; \
            struct dm_sworndisk_target* sworndisk; \
              this = container_of(al, struct default_segment_allocator, segment_allocator); \
                sworndisk = this->sworndisk;

int sa_get_next_free_segment(struct segment_allocator* al, size_t *seg) {
    int r;
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE 

    r = sworndisk->metadata->seg_validator->next(sworndisk->metadata->seg_validator, seg);
    if (r)
        return r;
    
    r = sworndisk->metadata->seg_validator->take(sworndisk->metadata->seg_validator, *seg);
    if (r)
        return r;

    this->nr_valid_segment += 1;
    r = sworndisk->metadata->data_segment_table->take_segment(sworndisk->metadata->data_segment_table, *seg);
    if (r)
        return r;

    if (this->nr_valid_segment > TRIGGER_SEGMENT_CLEANING_THREADHOLD && this->status != SEGMENT_CLEANING) 
        al->clean(al);

    return 0;
}

void sa_clean(struct segment_allocator* al) {
    int r;
    bool valid;
    dm_block_t lba, pba;
    size_t clean = 0, offset;
    struct victim* victim = NULL;
    unsigned long sync_error_bits;
    struct dm_io_request req;
    struct dm_io_region region;
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE

    this->status = SEGMENT_CLEANING;
    region.bdev = sworndisk->data_dev->bdev;
    req.bi_op = req.bi_op_flags = REQ_OP_READ;
    req.mem.type = DM_IO_KMEM;
    req.mem.offset = 0;
    req.mem.ptr.addr = this->buffer;
    req.notify.fn = NULL;
    req.client = this->io_client;
    while(clean < LEAST_CLEAN_SEGMENT_ONCE && 
      !sworndisk->metadata->data_segment_table->victim_empty(sworndisk->metadata->data_segment_table)) {
        victim = sworndisk->metadata->data_segment_table->pop_victim(sworndisk->metadata->data_segment_table);

        if (victim->nr_valid_block) {
            region.sector = victim->segment_id * SECTOES_PER_SEGMENT;
            region.count = SECTOES_PER_SEGMENT;
            dm_io(&req, 1, &region, &sync_error_bits);
            if (sync_error_bits) {
                DMERR("segment allocator read blocks error\n");
                goto exit;
            }

            offset = find_first_bit(victim->block_validity_table, BLOCKS_PER_SEGMENT);
            while(offset < BLOCKS_PER_SEGMENT) {
                pba = victim->segment_id * BLOCKS_PER_SEGMENT + offset;
                r = sworndisk->metadata->reverse_index_table->get(sworndisk->metadata->reverse_index_table, pba, &lba);
                if (r)
                    goto exit; 
                sworndisk->seg_buffer->push_block(sworndisk->seg_buffer, lba, this->buffer + offset * DATA_BLOCK_SIZE);
                offset = find_next_bit(victim->block_validity_table, BLOCKS_PER_SEGMENT, offset + 1);
            }
        }

        r = sworndisk->metadata->seg_validator->test_and_return(sworndisk->metadata->seg_validator, victim->segment_id, &valid);
        if (r)
            goto exit;

        if (valid) {
            clean += 1;
            this->nr_valid_segment -= 1;
        }

        victim_destroy(victim);
        victim = NULL;
    }

exit:
    if (victim)
        victim_destroy(victim);

    // sworndisk->metadata->seg_validator->cur_segment = 0;
    this->status = SEGMENT_ALLOCATING;
}

void sa_destroy(struct segment_allocator* al) {
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->io_client))
            dm_io_client_destroy(this->io_client);
        if (!IS_ERR_OR_NULL(this->buffer))
            kfree(this->buffer);
        kfree(this);
    }
}

int sa_init(struct default_segment_allocator* this, struct dm_sworndisk_target* sworndisk) {
    int err = 0;

    this->buffer = kmalloc(SEGMENT_BUFFER_SIZE, GFP_KERNEL);
    if (!this->buffer) {
        err = -ENOMEM;
        goto bad;
    }
    
    this->io_client = dm_io_client_create();
    if (IS_ERR_OR_NULL(this->io_client)) {
        err =  -ENOMEM;
        goto bad;
    }

    this->status = SEGMENT_ALLOCATING;
    this->sworndisk = sworndisk;
    this->segment_allocator.get_next_free_segment = sa_get_next_free_segment;
    this->segment_allocator.clean = sa_clean;
    this->segment_allocator.destroy = sa_destroy;

    err = sworndisk->metadata->seg_validator->valid_segment_count(sworndisk->metadata->seg_validator, &this->nr_valid_segment);
    if (err) 
        goto bad;

    return 0;
bad:
    if (this->buffer)
        kfree(this->buffer);
    if (this->io_client)
        dm_io_client_destroy(this->io_client);
    return err;
}

struct segment_allocator* sa_create(struct dm_sworndisk_target* sworndisk) {
    int r;
    struct default_segment_allocator* sa;

    sa = kzalloc(sizeof(struct default_segment_allocator), GFP_KERNEL);
    if (!sa)
        return NULL;
    
    r = sa_init(sa, sworndisk);
    if (r)
        return NULL;
    
    return &sa->segment_allocator;
}