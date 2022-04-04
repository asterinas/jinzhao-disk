#ifndef DM_SWORNDISK_SEGMENT_ALLOCATOR_H
#define DM_SWORNDISK_SEGMENT_ALLOCATOR_H

#define NR_SEGMENT 1280
#define SECTORS_PER_BLOCK 8
#define BLOCKS_PER_SEGMENT 1024
#define SECTOES_PER_SEGMENT (SECTORS_PER_BLOCK * BLOCKS_PER_SEGMENT)

#define DATA_BLOCK_SIZE (SECTORS_PER_BLOCK * SECTOR_SIZE)

#define TRIGGER_SEGMENT_CLEANING_THREADHOLD (0.7f);
#define LEAST_CLEAN_SEGMENT_ONCE (0.1f * NR_SEGMENT)

enum segment_allocator_status {
    SEGMENT_ALLOCATING,
    SEGMENT_CLEANING
};

struct segment_allocator {
    int (*get_next_free_segment)(struct segment_allocator* al, size_t *seg);
    void (*clean)(struct segment_allocator* al);
    void (*destroy)(struct segment_allocator* al);
};

struct default_segment_allocator {
    struct segment_allocator segment_allocator;
    const struct dm_sworndisk_target* sworndisk;
    size_t nr_segment;
    enum segment_allocator_status status;
};

struct segment_allocator* sa_create(struct dm_sworndisk_target *sworndisk);

#endif