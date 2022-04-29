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
    int err;
    size_t clean = 0;
    struct victim* victim = NULL;
    void* buffer = kmalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE

    this->status = SEGMENT_CLEANING;
    if (!buffer) goto exit;
    while(clean < LEAST_CLEAN_SEGMENT_ONCE && 
      !sworndisk->metadata->data_segment_table->victim_empty(sworndisk->metadata->data_segment_table)) {
        bool valid;

        victim = sworndisk->metadata->data_segment_table->pop_victim(sworndisk->metadata->data_segment_table);
        if (victim->nr_valid_block) {
            size_t offset;

            offset = find_first_bit(victim->block_validity_table, BLOCKS_PER_SEGMENT);
            while(offset < BLOCKS_PER_SEGMENT) {
                dm_block_t lba, pba;
                loff_t addr;
                struct record record;

                pba = victim->segment_id * BLOCKS_PER_SEGMENT + offset;
                addr = pba * DATA_BLOCK_SIZE;
                kernel_read(sworndisk->data_region, buffer, DATA_BLOCK_SIZE, &addr);
                sworndisk->metadata->reverse_index_table->get(sworndisk->metadata->reverse_index_table, pba, &lba);
                sworndisk->lsm_tree->search(sworndisk->lsm_tree, lba, &record);
                err = sworndisk->cipher->decrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE, 
                    record.key, AES_GCM_KEY_SIZE, record.iv, AES_GCM_IV_SIZE, record.mac, AES_GCM_AUTH_SIZE, record.pba);
                if (!err)
                    sworndisk->seg_buffer->push_block(sworndisk->seg_buffer, lba, buffer);
                offset = find_next_bit(victim->block_validity_table, BLOCKS_PER_SEGMENT, offset + 1);
            }
        }

        err = sworndisk->metadata->seg_validator->test_and_return(sworndisk->metadata->seg_validator, victim->segment_id, &valid);
        if (!err && valid) {
            clean += 1;
            this->nr_valid_segment -= 1;
        }

        victim_destroy(victim);
        victim = NULL;
    }

exit:
    if (victim)
        victim_destroy(victim);
    if (buffer)
        kfree(buffer);

    this->status = SEGMENT_ALLOCATING;
}

void sa_destroy(struct segment_allocator* al) {
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->io_client))
            dm_io_client_destroy(this->io_client);
        kfree(this);
    }
}

int sa_init(struct default_segment_allocator* this, struct dm_sworndisk_target* sworndisk) {
    int err = 0;
    
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