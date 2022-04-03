#ifndef SWORNDISK_JOURNAL_H
#define SWORNDISK_JOURNAL_H

#include "disk_structs.h"

struct journal_replayer {
    int (*replay)(struct journal_replayer* journal_replayer, void** entry_list, size_t len);
};

struct journal {
    size_t capacity, entry_size;
    struct dm_block_manager* bm;
    dm_block_t start;
    struct disk_queue* entries;
    struct journal_replayer* replayer;

    int (*append)(struct journal* this, void* entry);
    int (*replay_all)(struct journal* this);
};

int journal_init(struct journal* this, struct dm_block_manager* bm, dm_block_t start, size_t capacity, size_t entry_size, struct journal_replayer* replayer);

#endif