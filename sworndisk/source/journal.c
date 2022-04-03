#include "../include/journal.h"

int journal_append(struct journal* this, void* entry) {
    int r;

    if (this->entries->full(this->entries)) {
        r = this->replay_all(this);
        if (r)
            return r;
    }
    
    r = this->entries->push(this->entries, entry);
    if (r)
        return r;

    return 0;
}


int journal_replay_all(struct journal* this) {
    int r;
    void** entry_list;

    entry_list = this->entries->peek(this->entries, this->entries->size);
    if (IS_ERR_OR_NULL(entry_list))
        return -ENODATA;
    
    r = this->replayer->replay(this->replayer, entry_list, this->entries->size);
    if (r)
        return r;
    
    r = this->entries->clear(this->entries);
    if (r)
        return r;

    return 0;
}

int journal_init(struct journal* this, struct dm_block_manager* bm, dm_block_t start, size_t capacity, size_t entry_size, struct journal_replayer* replayer) {
    this->entries = disk_queue_create(bm, start, capacity, entry_size);
    if (IS_ERR_OR_NULL(this->entries))
        return -ENOMEM;
    
    this->bm = bm;
    this->start = start;
    this->capacity = capacity;
    this->entry_size = entry_size;
    this->replayer = replayer;

    this->append = journal_append;
    this->replay_all = journal_replay_all;

    return 0;
}

struct journal* journal_create(struct dm_block_manager* bm, dm_block_t start, size_t capacity, size_t entry_size, struct journal_replayer* replayer) {
    int r;
    struct journal* this;

    this = kmalloc(sizeof(struct journal), GFP_KERNEL);
    if (!this)
        return NULL;
    
    r = journal_init(this, bm, start, capacity, entry_size, replayer);
    if (r)
        return NULL;
    
    return this;
}

void journal_destroy(struct journal* this) {
    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->entries))
            disk_queue_destroy(this->entries);
        kfree(this);
    }
}