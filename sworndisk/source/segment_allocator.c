#include "../include/segment_allocator.h"

#define DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE struct default_segment_allocator* this; \
            struct dm_sworndisk_target* sworndisk; \
              this = container_of(al, struct default_segment_allocator, segment_allocator); \
                sworndisk = this->sworndisk;

#include "../include/dm_sworndisk.h"

int sa_get_next_free_segment(struct segment_allocator* al, size_t *seg, size_t next_seg) {
    int r;
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE 

    r = dm_sworndisk_get_first_free_segment(sworndisk->metadata, seg, next_seg);
    if (r) {
        DMERR("get_first_free_segment error\n");
        return r;
    }

    r = dm_sworndisk_set_svt(sworndisk->metadata, *seg, true);
    if (r) {
        DMERR("dm_sworndisk_set_svt error\n");
        return r;
    }
        
    return 0;
}

int sa_alloc_sectors(struct segment_allocator* al, struct bio* bio, sector_t *pba) {
    int r;
    size_t seg;
    size_t next_seg;
    size_t nr_sector;
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE

    next_seg = this->cur_segment + 1;
    nr_sector = bio_sectors(bio);
    if (this->cur_sector + nr_sector >= SEC_PER_SEG) {
try:
        r = al->get_next_free_segment(al, &seg, next_seg);
        if (r) {
            // return seg;
            // since there are no segment cleaning methods, a trick to provide sufficient disk space
            r = dm_sworndisk_reset_svt(sworndisk->metadata);
            if (r)
                return r;
            goto try;
        }
        this->cur_segment = seg;
        this->cur_sector = 0;
    }

    *pba = this->cur_segment*SEC_PER_SEG + this->cur_sector;
    this->cur_sector += nr_sector;
    return 0;
}

int sa_write_reverse_index_table(struct segment_allocator* al, sector_t lba, sector_t pba) {
    int r;
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE

    r = dm_sworndisk_rit_insert(sworndisk->metadata, pba, lba);
    if (r)
        return r;
    return 0;
}

void sa_destroy(struct segment_allocator* al) {
    DEFAULT_SEGMENT_ALLOCATOR_THIS_POINTER_DECLARE

    kfree(this);
}

int sa_init(struct default_segment_allocator* this, struct dm_sworndisk_target* sworndisk) {
    int r;

    this->cur_sector = 0;
    this->sworndisk = sworndisk;
    this->segment_allocator.get_next_free_segment = sa_get_next_free_segment;
    this->segment_allocator.alloc_sectors = sa_alloc_sectors;
    this->segment_allocator.write_reverse_index_table = sa_write_reverse_index_table;
    this->segment_allocator.clean = NULL;
    this->segment_allocator.destroy = sa_destroy;

    r = this->segment_allocator.get_next_free_segment(&this->segment_allocator, &this->cur_segment, 0);
    return r;
}

struct segment_allocator* sa_create(struct dm_sworndisk_target* sworndisk) {
    int r;
    struct default_segment_allocator* sa;

    sa = kmalloc(sizeof(struct default_segment_allocator), GFP_KERNEL);
    if (!sa)
        return NULL;
    
    r = sa_init(sa, sworndisk);
    if (r)
        return NULL;
    return &sa->segment_allocator;
}