#include <linux/slab.h>

#include "../include/dm_sworndisk.h"
#include "../include/bio_operate.h"

unsigned int bio_get_sector(struct bio *bio) {
    return bio->bi_iter.bi_sector;
}

void bio_set_sector(struct bio *bio, unsigned int sector) {
    bio->bi_iter.bi_sector = sector;
}

// in bytes
size_t bio_get_data_len(struct bio* bio) {
    return bio->bi_iter.bi_size;
}

void bio_set_data_len(struct bio* bio, unsigned int len) {
    bio->bi_iter.bi_size = len;
}

dm_block_t bio_get_block_address(struct bio* bio) {
    return bio_get_sector(bio) / SECTORS_PER_BLOCK;
}

sector_t bio_block_sector_offset(struct bio* bio) {
    return bio_get_sector(bio) % SECTORS_PER_BLOCK;
}

void __bio_data_transfer(struct bio* bio, char* buffer, size_t len) {
    bool has_next;
    char* kaddr;
    size_t offset;
    struct bio *total, *split;

    total = bio_clone_fast(bio, GFP_KERNEL, &fs_bio_set);
    if (IS_ERR_OR_NULL(total))
        return;
    
    offset = 0;
    has_next = true;
next:
    if (bio_sectors(total) > 1) {
        split = bio_split(total, 1, GFP_KERNEL, &fs_bio_set);
        if (IS_ERR_OR_NULL(split))
            return;
    } else {
        split = total;
        has_next = false;
    }

    if (offset + bio_get_data_len(split) > len)
        return;

    kaddr = kmap_atomic(bio_page(split));
    if (bio_op(bio) == REQ_OP_WRITE)
        memcpy(buffer + offset, kaddr + bio_offset(split), bio_get_data_len(split));
    else if(bio_op(bio) == REQ_OP_READ)
        memcpy(kaddr + bio_offset(split), buffer + offset, bio_get_data_len(split));
    kunmap_atomic(kaddr);

    offset += bio_get_data_len(split);
    bio_put(split);

    if (has_next)
        goto next;
}

void bio_get_data(struct bio* bio, char* buffer, size_t len) {
   __bio_data_transfer(bio, buffer, len);
}


void bio_set_data(struct bio* bio, char* buffer, size_t len) {
    __bio_data_transfer(bio, buffer, len);
}