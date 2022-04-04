#ifndef DM_SWORNDISK_SEGMENT_BUFFER_H
#define DM_SWORNDISK_SEGMENT_BUFFER_H

#include <linux/bio.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/dm-io.h>

#include "segment_allocator.h"
#include "memtable.h"
#include "crypto.h"

#define SEGMENT_BUFFER_SIZE (SECTOES_PER_SEGMENT * SECTOR_SIZE)


struct segment_buffer {
    void (*push_bio)(struct segment_buffer* buf, struct bio* bio);
    void (*push_block)(struct segment_buffer* buf, dm_block_t lba, void* buffer);
    int (*query_bio)(struct segment_buffer* buf, struct bio* bio);
    void (*flush_bios)(struct segment_buffer* buf);
    void (*destroy)(struct segment_buffer* buf);
    void* (*implementer)(struct segment_buffer* buf);
};


struct default_segment_buffer {
    struct segment_buffer segment_buffer;

    void *buffer, *pipe;
    size_t cur_segment;
    sector_t cur_sector;
    struct dm_io_client* io_client;
    struct dm_sworndisk_target* sworndisk;
};

struct segment_buffer* segbuf_create(struct dm_sworndisk_target* sowrndisk);

#endif