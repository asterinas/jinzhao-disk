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
    char* kaddr;
    size_t offset = 0;
    struct bio *total = NULL, *split = NULL;

    total = bio_clone_fast(bio, GFP_KERNEL, &fs_bio_set);
    while (split != total) {
        split = (bio_sectors(total) > 1 ? bio_split(total, 1, GFP_KERNEL, &fs_bio_set) : total);
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
    }   
}

void bio_get_data(struct bio* bio, char* buffer, size_t len) {
   __bio_data_transfer(bio, buffer, len);
}


void bio_set_data(struct bio* bio, char* buffer, size_t len) {
    __bio_data_transfer(bio, buffer, len);
}