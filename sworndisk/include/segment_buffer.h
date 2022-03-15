#ifndef DM_SWORNDISK_SEGMENT_BUFFER_H
#define DM_SWORNDISK_SEGMENT_BUFFER_H

#include <linux/bio.h>

#include "segment_allocator.h"
#include "memtable.h"
#include "crypto.h"

struct segment_buffer {
    int (*push_bio)(struct segment_buffer* buf, struct bio* bio);
    void (*flush_bios)(struct segment_buffer* buf);
    int (*encrypt_bio)(struct segment_buffer* buf, struct bio* bio, struct memtable* mt, int lba, int pba);
    void (*destroy)(struct segment_buffer* buf);
    void* (*implementer)(struct segment_buffer* buf);
};


struct default_segment_buffer {
    struct segment_buffer segment_buffer;
    spinlock_t lock;
    struct dm_dev* data_dev;
    struct bio_list bios;
    struct segment_allocator* sa;
    struct memtable* mt;
    struct bio_set* bio_set;
    struct aead_cipher *cipher;
    struct work_struct flush_bio_work;
};

struct segment_buffer* segbuf_init(struct default_segment_buffer *buf, 
    struct dm_dev* data_dev, struct dm_sworndisk_metadata *metadata, size_t nr_segment);

#endif