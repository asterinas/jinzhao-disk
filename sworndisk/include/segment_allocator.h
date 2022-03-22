#ifndef DM_SWORNDISK_SEGMENT_ALLOCATOR_H
#define DM_SWORNDISK_SEGMENT_ALLOCATOR_H

#include "../include/metadata.h"

#define NR_SEGMENT 65536
#define SEC_PER_SEG 2048

struct segment_allocator {
    int (*get_next_free_segment)(struct segment_allocator* al, size_t *seg, size_t next_seg);
    int (*alloc_sectors)(struct segment_allocator* al, struct bio* bio, sector_t *pba);
    int (*write_reverse_index_table)(struct segment_allocator* al, sector_t pba, sector_t lba);
    void (*clean)(struct segment_allocator* al);
    void (*destroy)(struct segment_allocator* al);
};

struct default_segment_allocator {
    struct segment_allocator segment_allocator;
    struct dm_sworndisk_target* sworndisk;
    size_t nr_segment;
    size_t cur_segment;
    size_t cur_sector;
};

struct segment_allocator* sa_create(struct dm_sworndisk_target *sworndisk);

#endif