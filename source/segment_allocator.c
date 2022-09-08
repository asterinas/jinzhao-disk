#include <linux/dm-io.h>
#include <linux/timer.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"
#include "../include/segment_allocator.h"

#define GC_DELAY 5000   // milliseconds
struct timer_list gc_timer;
struct work_struct gc_work;

int sa_alloc(struct segment_allocator* al, size_t *seg) {
    int r;
    struct default_segment_allocator* this = container_of(al, struct default_segment_allocator, segment_allocator); 

    r = sworndisk->meta->seg_validator->next(sworndisk->meta->seg_validator, seg);
    if (r)
        return r;
    
    r = sworndisk->meta->seg_validator->take(sworndisk->meta->seg_validator, *seg);
    if (r)
        return r;

    this->nr_valid_segment += 1;
    // TODO: don't take all blocks in a segment together, or some blocks may never be GC
    r = sworndisk->meta->dst->take_segment(sworndisk->meta->dst, *seg);
    if (r)
        return r;

    return 0;
}

bool offset_in_region(size_t offset, size_t region_begin, size_t region_end) {
    return (offset >= region_begin && offset < region_end);
}

void sa_foreground_gc(struct segment_allocator* al) {
    int err, cur;
    size_t clean = 0, target = LEAST_CLEAN_SEGMENT_ONCE * BLOCKS_PER_SEGMENT;
    struct victim victim, *p_victim = NULL;
    void *buffer, *plaintext;
    struct default_segment_allocator* this = container_of(al, struct default_segment_allocator, segment_allocator); 
    struct default_segment_buffer *segbuf = container_of(sworndisk->seg_buffer, struct default_segment_buffer, segment_buffer);

    if (this->nr_valid_segment < FOREGROUND_GC_THRESHOLD || this->status == SEGMENT_CLEANING)
	    return;

    this->status = SEGMENT_CLEANING;

    buffer = vmalloc(SEGMENT_BUFFER_SIZE);
    plaintext = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
    if (!buffer || !plaintext) goto exit;
    while(clean < target && !sworndisk->meta->dst->victim_empty(sworndisk->meta->dst)) {
        bool valid;

        victim = *(sworndisk->meta->dst->peek_victim(sworndisk->meta->dst));
        // TODO: don't GC current segment buffer
        if (victim.nr_valid_block) {
            size_t offset;
            unsigned int region_begin = 0, region_end = 0;

            offset = find_first_bit(victim.block_validity_table, BLOCKS_PER_SEGMENT);
            while(offset < BLOCKS_PER_SEGMENT) {
                dm_block_t lba, pba;
                struct record record;

                pba = victim.segno * BLOCKS_PER_SEGMENT + offset;
                if (!offset_in_region(offset, region_begin, region_end)) {
                    region_begin = offset;
                    region_end = find_next_zero_bit(victim.block_validity_table, BLOCKS_PER_SEGMENT, region_begin);
                    sworndisk_read_blocks(pba, region_end - region_begin, buffer + offset * DATA_BLOCK_SIZE, DM_IO_VMA);
                }
                
                sworndisk->meta->rit->get(sworndisk->meta->rit, pba, &lba);
		down_write(&segbuf->rw_lock);
		cur = segbuf->cur_buffer;
                sworndisk->lsm_tree->search(sworndisk->lsm_tree, lba, &record);
		if (record.pba != pba) {
			up_write(&segbuf->rw_lock);
			offset = find_next_bit(victim.block_validity_table, BLOCKS_PER_SEGMENT, offset + 1);
			continue;
		}
                err = sworndisk->cipher->decrypt(sworndisk->cipher, buffer + offset * DATA_BLOCK_SIZE, DATA_BLOCK_SIZE, 
                    record.key, record.iv, record.mac, record.pba, plaintext);
                if (!err)
                    sworndisk->seg_buffer->push_block(sworndisk->seg_buffer, lba, plaintext);
		up_write(&segbuf->rw_lock);
		if (cur != segbuf->cur_buffer)
		    sworndisk->seg_buffer->flush_bios(sworndisk->seg_buffer, cur);
                offset = find_next_bit(victim.block_validity_table, BLOCKS_PER_SEGMENT, offset + 1);
            }
        }

        err = sworndisk->meta->seg_validator->test_and_return(sworndisk->meta->seg_validator, victim.segno, &valid);
        if (!err && valid) {
            clean += (BLOCKS_PER_SEGMENT - victim.nr_valid_block);
            // DMINFO("clean: %ld, count: %ld", victim.segno, BLOCKS_PER_SEGMENT - victim.nr_valid_block);
            this->nr_valid_segment -= 1;
        }

        p_victim = sworndisk->meta->dst->remove_victim(sworndisk->meta->dst, victim.segno);
        victim_destroy(p_victim);
    }

exit:
    if (buffer)
        vfree(buffer);
    if (plaintext)
        kfree(plaintext);

    this->status = SEGMENT_ALLOCATING;
}

void sa_background_gc(struct work_struct *ws)
{
	int err, offset, cur;
	bool valid = false;
	void *buffer = NULL;
	dm_block_t lba, pba;
	struct record record;
	size_t clean = 0, target = LEAST_CLEAN_SEGMENT_ONCE * BLOCKS_PER_SEGMENT;
	struct victim victim, *p_victim = NULL;
	struct default_segment_allocator *this = container_of(sworndisk->seg_allocator, struct default_segment_allocator, segment_allocator);
	struct default_segment_buffer *segbuf = container_of(sworndisk->seg_buffer, struct default_segment_buffer, segment_buffer);

	if (this->nr_valid_segment < BACKGROUND_GC_THRESHOLD || this->status == SEGMENT_CLEANING)
		return;

	this->status = SEGMENT_CLEANING;

	buffer = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
	if (!buffer) {
		DMERR("sa_background_gc kzalloc buffer failed\n");
		return;
	}

	while (clean < target && !sworndisk->meta->dst->victim_empty(sworndisk->meta->dst)) {
		victim = *(sworndisk->meta->dst->peek_victim(sworndisk->meta->dst));
		if (victim.nr_valid_block) {
			offset = 0;
			do {
				offset = find_next_bit(victim.block_validity_table, BLOCKS_PER_SEGMENT, offset);
				pba = victim.segno * BLOCKS_PER_SEGMENT + offset;
				sworndisk->meta->rit->get(sworndisk->meta->rit, pba, &lba);
				down_write(&segbuf->rw_lock);
				cur = segbuf->cur_buffer;
				sworndisk->lsm_tree->search(sworndisk->lsm_tree, lba, &record);
				if (record.pba != pba) {
					up_write(&segbuf->rw_lock);
					continue;
				}
				sworndisk_read_blocks(pba, 1, buffer, DM_IO_KMEM);
				err = sworndisk->cipher->decrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE, record.key, record.iv, record.mac, record.pba, buffer);
				if (!err)
					sworndisk->seg_buffer->push_block(sworndisk->seg_buffer, lba, buffer);
				up_write(&segbuf->rw_lock);
				if (cur != segbuf->cur_buffer)
					sworndisk->seg_buffer->flush_bios(sworndisk->seg_buffer, cur);
			} while (++offset < BLOCKS_PER_SEGMENT);
		}
		err = sworndisk->meta->seg_validator->test_and_return(sworndisk->meta->seg_validator, victim.segno, &valid);
		if (!err && valid) {
			clean += (BLOCKS_PER_SEGMENT - victim.nr_valid_block);
			this->nr_valid_segment -= 1;
		}
		p_victim = sworndisk->meta->dst->remove_victim(sworndisk->meta->dst, victim.segno);
		victim_destroy(p_victim);
	}

	this->status = SEGMENT_ALLOCATING;
	kfree(buffer);
}

void gc_timer_callback(struct timer_list *gc_timer)
{
	schedule_work(&gc_work);
	mod_timer(gc_timer, jiffies + msecs_to_jiffies(GC_DELAY));
}

void sa_destroy(struct segment_allocator* al) {
    struct default_segment_allocator* this = container_of(al, struct default_segment_allocator, segment_allocator); 

    del_timer(&gc_timer);
    if (!IS_ERR_OR_NULL(this)) {
        kfree(this);
    }
}

int sa_init(struct default_segment_allocator* this) {
    int err = 0;

    this->status = SEGMENT_ALLOCATING;
    this->segment_allocator.alloc = sa_alloc;
    this->segment_allocator.foreground_gc = sa_foreground_gc;
    this->segment_allocator.destroy = sa_destroy;

    err = sworndisk->meta->seg_validator->valid_segment_count(sworndisk->meta->seg_validator, &this->nr_valid_segment);
    if (err) 
        goto bad;

    INIT_WORK(&gc_work, sa_background_gc);

    timer_setup(&gc_timer, gc_timer_callback, 0);
    gc_timer.expires = jiffies + msecs_to_jiffies(GC_DELAY);
    add_timer(&gc_timer);

    return 0;
bad:
    return err;
}

struct segment_allocator* sa_create() {
    int r;
    struct default_segment_allocator* sa;

    sa = kzalloc(sizeof(struct default_segment_allocator), GFP_KERNEL);
    if (!sa)
        return NULL;
    
    r = sa_init(sa);
    if (r)
        return NULL;
    
    return &sa->segment_allocator;
}
