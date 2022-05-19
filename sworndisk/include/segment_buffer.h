#ifndef DM_SWORNDISK_SEGMENT_BUFFER_H
#define DM_SWORNDISK_SEGMENT_BUFFER_H

#include <linux/bio.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/dm-io.h>

#include "segment_allocator.h"
#include "memtable.h"
#include "crypto.h"

// #define DEBUG_CRYPT

#define SEGMENT_BUFFER_SIZE (SECTOES_PER_SEGMENT * SECTOR_SIZE)

void btox(char *xp, const char *bb, int n);

#define MODIFY_IN_MEM_BUFFER 0
#define PUSH_NEW_BLOCK 1
struct segment_buffer {
    int (*push_bio)(struct segment_buffer* buf, struct bio* bio);
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
    struct dm_sworndisk_target* sworndisk;

#ifdef DEBUG_CRYPT
    loff_t crypt_info_pos;
    struct file* crypt_info;
#endif
};

struct segment_buffer* segbuf_create(struct dm_sworndisk_target* sowrndisk);

#endif