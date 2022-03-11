#ifndef DM_SWORNDISK_SEGMENT_ALLOCATOR_H
#define DM_SWORNDISK_SEGMENT_ALLOCATOR_H

#include "../include/metadata.h"

#define NR_SEGMENT 4096
#define SEC_PER_BLK 32
#define BLK_PER_SEG 64
#define SEC_PER_SEG (SEC_PER_BLK*BLK_PER_SEG)

struct segment_allocator {
    int (*get_next_free_segment)(struct segment_allocator* al, size_t *seg, size_t next_seg);
    int (*alloc_sectors)(struct segment_allocator* al, struct bio* bio, sector_t *pba, bool *should_flush);
    int (*write_reverse_index_table)(struct segment_allocator* al, sector_t pba, sector_t lba);
    void (*clean)(struct segment_allocator* al);
    void (*destroy)(struct segment_allocator* al);
};

struct default_segment_allocator {
    struct segment_allocator segment_allocator;
    struct dm_sworndisk_metadata* metadata;
    size_t nr_segment;
    size_t cur_segment;
    size_t cur_sector;
};

struct segment_allocator* sa_init(struct default_segment_allocator* this, struct dm_sworndisk_metadata *metadata, size_t nr_segment);

#endif