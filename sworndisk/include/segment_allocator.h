#ifndef DM_SWORNDISK_SEGMENT_ALLOCATOR_H
#define DM_SWORNDISK_SEGMENT_ALLOCATOR_H

#include "../include/metadata.h"

#define NR_SEGMENT 4096
#define SECTORS_PER_BLOCK 1
#define SECTOES_PER_SEG 2048

struct segment_allocator {
    int (*get_next_free_segment)(struct segment_allocator* al, size_t *seg);
    void (*clean)(struct segment_allocator* al);
    void (*destroy)(struct segment_allocator* al);
};

struct default_segment_allocator {
    struct segment_allocator segment_allocator;
    struct dm_sworndisk_target* sworndisk;
    size_t nr_segment;
};

struct segment_allocator* sa_create(struct dm_sworndisk_target *sworndisk);

#endif