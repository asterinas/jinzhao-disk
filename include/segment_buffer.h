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
#define POOL_SIZE 4

void btox(char *xp, const char *bb, int n);

#define MODIFY_IN_MEM_BUFFER 0
#define PUSH_NEW_BLOCK 1
struct segment_buffer {
    int (*push_bio)(struct segment_buffer* buf, struct bio* bio);
    void (*push_block)(struct segment_buffer* buf, dm_block_t lba, void* buffer);
    int (*query_bio)(struct segment_buffer* buf, struct bio* bio, dm_block_t pba);
    void (*flush_bios)(struct segment_buffer* buf, int index);
    void (*destroy)(struct segment_buffer* buf);
    void* (*implementer)(struct segment_buffer* buf);
};

struct default_segment_buffer {
    struct segment_buffer segment_buffer;

    char seg_key[AES_GCM_KEY_SIZE];
    int cur_buffer;
    void *buffer[POOL_SIZE], *pipe[POOL_SIZE];
    size_t cur_segment[POOL_SIZE];
    sector_t cur_sector[POOL_SIZE];
    struct rw_semaphore rw_lock;
};

struct segment_buffer* segbuf_create(void);

#endif
