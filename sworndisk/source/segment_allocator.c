#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/segment_allocator.h"

#define DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE struct default_segment_allocator* this; \
              this = container_of(al, struct default_segment_allocator, segment_allocator); \

int sa_get_next_free_segment(struct segment_allocator* al, size_t *seg) {
    int r;
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE 

    r = this->sworndisk->metadata->seg_validator->next(this->sworndisk->metadata->seg_validator, seg);
    if (r)
        return r;
    
    r = this->sworndisk->metadata->seg_validator->take(this->sworndisk->metadata->seg_validator, *seg);
    if (r)
        return r;
        
    return 0;
}

// void sa_clean(struct segment_allocator* al) {
//     dm_block_t pba;
//     size_t clean = 0;
//     struct victim* victim;
//     DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE

//     while(clean < LEAST_CLEAN_SEGMENT_ONCE && 
//       !sworndisk->metadata->data_segment_table->victim_empty(sworndisk->metadata->data_segment_table)) {
//         victim = sworndisk->metadata->data_segment_table->pop_victim(sworndisk->metadata->data_segment_table);
//         pba = find_first_bit(victim->block_validity_table, BLOCKS_PER_SEGMENT);
//         while (pba < BLOCKS_PER_SEGMENT) {
            
//             pba = find_next_bit(victim->block_validity_table, BLOCKS_PER_SEGMENT, pba + 1);
//         }
//         victim_destroy(victim);
//     }
// }

void sa_destroy(struct segment_allocator* al) {
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE

    if (!IS_ERR_OR_NULL(this))
        kfree(this);
}

void sa_init(struct default_segment_allocator* this, struct dm_sworndisk_target* sworndisk) {
    this->sworndisk = sworndisk;
    this->segment_allocator.get_next_free_segment = sa_get_next_free_segment;
    this->segment_allocator.clean = NULL;
    this->segment_allocator.destroy = sa_destroy;
}

struct segment_allocator* sa_create(struct dm_sworndisk_target* sworndisk) {
    struct default_segment_allocator* sa;

    sa = kmalloc(sizeof(struct default_segment_allocator), GFP_KERNEL);
    if (!sa)
        return NULL;
    
    sa_init(sa, sworndisk);
    return &sa->segment_allocator;
}