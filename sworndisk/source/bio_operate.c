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
unsigned int bio_get_data_len(struct bio* bio) {
    return bio->bi_iter.bi_size;
}

void bio_set_data_len(struct bio* bio, unsigned int len) {
    bio->bi_iter.bi_size = len;
}

// assume this bio has only one page
void bio_get_data(struct bio* bio, char* buffer) {
    char* kaddr;

    kaddr = kmap_atomic(bio_page(bio));
    memcpy(buffer, kaddr + bio_offset(bio), bio_get_data_len(bio));
    kunmap_atomic(kaddr);
}

void page_set_data(struct page* page, char* data, size_t len, size_t offset) {
    char* kaddr;

    kaddr = kmap_atomic(page);
    memcpy(kaddr + offset, data, len);
    kunmap_atomic(kaddr);
}


char* bio_data_copy(struct bio* bio) {
    size_t len;
    char* buffer;
    char* kaddr;
    size_t offset;
    struct bio_vec bvec;
    struct bvec_iter bi_iter;

    len = bio_get_data_len(bio);
    buffer = kmalloc(len, GFP_KERNEL);
    if (!buffer)
        return NULL;
    
    offset = 0;
    bio_for_each_segment(bvec, bio, bi_iter) {
        kaddr = kmap_atomic(bvec.bv_page);
        memcpy(buffer+offset, kaddr+bvec.bv_offset, bvec.bv_len);
        kunmap_atomic(kaddr);
        offset += bvec.bv_len;
    }

    return buffer;
}

int bio_set_data(struct bio* bio, char* buffer, size_t len) {
    char* kaddr;
    size_t offset;
    struct bio_vec bvec;
    struct bvec_iter bi_iter;

    offset = 0;
    bio_for_each_segment(bvec, bio, bi_iter) {
        if (offset + bvec.bv_len > len)
            return -EAGAIN;
        kaddr = kmap(bvec.bv_page);
        memcpy(kaddr+bvec.bv_offset, buffer+offset, bvec.bv_len);
        kunmap(bvec.bv_page);
        offset += bvec.bv_len;
    }

    return 0;
}