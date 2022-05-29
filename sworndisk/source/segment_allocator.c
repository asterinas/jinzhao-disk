#include <linux/dm-io.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"
#include "../include/segment_allocator.h"

int sa_get_next_free_segment(struct segment_allocator* al, size_t *seg) {
    int r;
    struct default_segment_allocator* this = container_of(al, struct default_segment_allocator, segment_allocator); 

    r = sworndisk->meta->seg_validator->next(sworndisk->meta->seg_validator, seg);
    if (r)
        return r;
    
    r = sworndisk->meta->seg_validator->take(sworndisk->meta->seg_validator, *seg);
    if (r)
        return r;

    this->nr_valid_segment += 1;
    r = sworndisk->meta->dst->take_segment(sworndisk->meta->dst, *seg);
    if (r)
        return r;

    if (this->nr_valid_segment > TRIGGER_SEGMENT_CLEANING_THREADHOLD && this->status != SEGMENT_CLEANING) 
        al->clean(al);

    return 0;
}

void sa_clean(struct segment_allocator* al) {
    int err;
    size_t clean = 0, target = LEAST_CLEAN_SEGMENT_ONCE * BLOCKS_PER_SEGMENT;
    struct victim victim, *p_victim = NULL;
    void* buffer = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
    void* plaintext = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
    struct default_segment_allocator* this = container_of(al, struct default_segment_allocator, segment_allocator); 

    this->status = SEGMENT_CLEANING;
    if (!buffer) goto exit;
    while(clean < target && !sworndisk->meta->dst->victim_empty(sworndisk->meta->dst)) {
        bool valid;

        victim = *(sworndisk->meta->dst->peek_victim(sworndisk->meta->dst));
        // TODO: don't GC current segment buffer
        if (victim.nr_valid_block) {
            size_t offset;

            offset = find_first_bit(victim.block_validity_table, BLOCKS_PER_SEGMENT);
            while(offset < BLOCKS_PER_SEGMENT) {
                dm_block_t lba, pba;
                // loff_t addr;
                struct record record;

                pba = victim.segment_id * BLOCKS_PER_SEGMENT + offset;
                // addr = pba * DATA_BLOCK_SIZE;
                // kernel_read(sworndisk->data_region, buffer, DATA_BLOCK_SIZE, &addr);
                sworndisk_read_blocks(pba, 1, buffer, DM_IO_KMEM);
                sworndisk->meta->rit->get(sworndisk->meta->rit, pba, &lba);
                sworndisk->lsm_tree->search(sworndisk->lsm_tree, lba, &record);
                err = sworndisk->cipher->decrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE, 
                    record.key, record.iv, record.mac, record.pba, plaintext);
                if (!err)
                    sworndisk->seg_buffer->push_block(sworndisk->seg_buffer, lba, plaintext);
                offset = find_next_bit(victim.block_validity_table, BLOCKS_PER_SEGMENT, offset + 1);
            }
        }

        err = sworndisk->meta->seg_validator->test_and_return(sworndisk->meta->seg_validator, victim.segment_id, &valid);
        if (!err && valid) {
            clean += (BLOCKS_PER_SEGMENT - victim.nr_valid_block);
            // DMINFO("clean: %ld, count: %ld", victim.segment_id, BLOCKS_PER_SEGMENT - victim.nr_valid_block);
            this->nr_valid_segment -= 1;
        }

        p_victim = sworndisk->meta->dst->remove_victim(sworndisk->meta->dst, victim.segment_id);
        victim_destroy(p_victim);
    }

exit:
    if (buffer)
        kfree(buffer);
    if (plaintext)
        kfree(plaintext);

    this->status = SEGMENT_ALLOCATING;
}

void sa_destroy(struct segment_allocator* al) {
    struct default_segment_allocator* this = container_of(al, struct default_segment_allocator, segment_allocator); 

    if (!IS_ERR_OR_NULL(this)) {
        kfree(this);
    }
}

int sa_init(struct default_segment_allocator* this) {
    int err = 0;

    this->status = SEGMENT_ALLOCATING;
    this->segment_allocator.get_next_free_segment = sa_get_next_free_segment;
    this->segment_allocator.clean = sa_clean;
    this->segment_allocator.destroy = sa_destroy;

    err = sworndisk->meta->seg_validator->valid_segment_count(sworndisk->meta->seg_validator, &this->nr_valid_segment);
    if (err) 
        goto bad;

    return 0;
bad:
    return err;
}

struct segment_allocator* sa_create() {
    int r;
    struct default_segment_allocator* sa;

    sa = kzalloc(sizeof(struct default_segment_allocator), GFP_KERNEL);
    if (!sa)
        return NULL;
    
    r = sa_init(sa);
    if (r)
        return NULL;
    
    return &sa->segment_allocator;
}