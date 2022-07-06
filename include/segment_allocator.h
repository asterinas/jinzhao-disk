#ifndef DM_SWORNDISK_SEGMENT_ALLOCATOR_H
#define DM_SWORNDISK_SEGMENT_ALLOCATOR_H

extern size_t NR_SEGMENT;
#define SECTORS_PER_BLOCK 8
#define BLOCKS_PER_SEGMENT 1024
#define SECTOES_PER_SEGMENT (SECTORS_PER_BLOCK * BLOCKS_PER_SEGMENT)

#define DATA_BLOCK_SIZE (SECTORS_PER_BLOCK * SECTOR_SIZE)

#define GC_THREADHOLD (NR_SEGMENT - 16) 
#define LEAST_CLEAN_SEGMENT_ONCE 1

enum segment_allocator_status {
    SEGMENT_ALLOCATING,
    SEGMENT_CLEANING
};

struct segment_allocator {
    int (*alloc)(struct segment_allocator* al, size_t *seg);
    void (*foreground_gc)(struct segment_allocator* al);
    bool (*will_trigger_gc)(struct segment_allocator* al);
    void (*destroy)(struct segment_allocator* al);
};

struct default_segment_allocator {
    struct segment_allocator segment_allocator;
    size_t nr_segment;
    size_t nr_valid_segment;
    enum segment_allocator_status status;
    void* buffer;
};

struct segment_allocator* sa_create(void);

#endif