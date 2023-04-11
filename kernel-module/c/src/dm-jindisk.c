/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include <linux/device-mapper.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>

#include "../include/async.h"
#include "../include/dm_jindisk.h"
#include "../include/metadata.h"
#include "../include/segment_allocator.h"
#include "../include/segment_buffer.h"

size_t NR_SEGMENT;
struct dm_jindisk *jindisk = NULL;
struct disk_statistics disk_counter = { 0 };

void bio_list_add_safe(struct dm_jindisk *jindisk, struct bio_list *list,
		       struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&jindisk->req_lock, flags);
	bio_list_add(list, bio);
	spin_unlock_irqrestore(&jindisk->req_lock, flags);
}

void bio_list_take_safe(struct dm_jindisk *jindisk, struct bio_list *dst,
			struct bio_list *src)
{
	unsigned long flags;

	bio_list_init(dst);
	spin_lock_irqsave(&jindisk->req_lock, flags);
	bio_list_merge(dst, src);
	bio_list_init(src);
	spin_unlock_irqrestore(&jindisk->req_lock, flags);
}

void defer_bio(struct dm_jindisk *jindisk, struct bio *bio)
{
	bio_list_add_safe(jindisk, &jindisk->deferred_bios, bio);
	schedule_work(&jindisk->deferred_bio_worker);
}

void jindisk_block_io(void *iocb, struct diskio_ctx *ctx)
{
	unsigned long sync_error_bits = 0;
	struct dm_io_request req = { .bi_op = req.bi_op_flags = ctx->bi_op,
				     .mem.type = ctx->mem_type,
				     .mem.offset = 0,
				     .mem.ptr.addr = ctx->io_buffer,
				     .notify.fn = iocb,
				     .notify.context = ctx,
				     .client = jindisk->io_client };
	struct dm_io_region region = {
		.bdev = jindisk->raw_dev->bdev,
		.sector = (jindisk->meta->superblock->data_start +
			   ctx->blk_start) *
			  SECTORS_PER_BLOCK,
		.count = (ctx->blk_count) * SECTORS_PER_BLOCK
	};

	dm_io(&req, 1, &region, &sync_error_bits);
	if (sync_error_bits)
		DMERR("segment buffer io error");
}

void decrypt_work(struct work_struct *ws)
{
	int i, err;
	struct diskio_ctx *ctx = container_of(ws, struct diskio_ctx, work);

	DMDEBUG("decrypt_work blk_count:%u", ctx->blk_count);
	for (i = 0; i < ctx->blk_count; ++i) {
		struct record *r = ctx->infos[i]->record;
		void *ciphertext = (char *)ctx->io_buffer + i * DATA_BLOCK_SIZE;
		void *data_out = ctx->infos[i]->page_addr;

		err = jindisk->cipher->decrypt(jindisk->cipher, ciphertext,
					       DATA_BLOCK_SIZE, r->key, NULL,
					       r->mac, r->pba, data_out);
		if (err)
			DMERR("decrypt data failed lba:%llu pba:%llu err:%d",
			      ctx->infos[i]->lba, r->pba, err);

		DMDEBUG("decrypt lba:%llu pba:%llu", ctx->infos[i]->lba,
			r->pba);
		record_destroy(r);
		kfree(ctx->infos[i]);
	}
	vfree(ctx->io_buffer);
	kfree(ctx->infos);

	if (ctx->wait && atomic_dec_and_test(ctx->cnt))
		complete(ctx->wait);

	kfree(ctx);
}

void read_iocb(unsigned long error, void *ctx)
{
	struct diskio_ctx *ictx = ctx;

	if (error) {
		DMERR("read_iocb io error");
		return;
	}

	INIT_WORK(&ictx->work, decrypt_work);
	schedule_work(&ictx->work);
}

void jindisk_read_blocks(dm_block_t pba, size_t count, void *buffer,
			 enum dm_io_mem_type mem_type, void *ctx)
{
	struct diskio_ctx *ictx = ctx;

	if (!ctx)
		ictx = kzalloc(sizeof(struct diskio_ctx), GFP_KERNEL);

	DMDEBUG("read_blocks dm-io start:%llu count:%lu", pba, count);
	ictx->bi_op = REQ_OP_READ;
	ictx->blk_start = pba;
	ictx->blk_count = count;
	ictx->io_buffer = buffer;
	ictx->mem_type = mem_type;

	disk_counter.read_io_blocks += count;
	disk_counter.read_io_count += 1;
	if (ctx)
		jindisk_block_io(read_iocb, ictx);
	else
		jindisk_block_io(NULL, ictx);

	if (!ctx)
		kfree(ictx);
}

void jindisk_write_blocks(dm_block_t pba, size_t count, void *buffer,
			  enum dm_io_mem_type mem_type)
{
	struct diskio_ctx ctx = {
		.bi_op = REQ_OP_WRITE,
		.blk_start = pba,
		.blk_count = count,
		.io_buffer = buffer,
		.mem_type = mem_type,
	};
#if ENABLE_JOURNAL
	uint64_t i, ts;
	dm_block_t lba, hba;
	struct record d_record;
	struct journal_region *journal;
	struct journal_record j_record;
#endif
	DMDEBUG("write_blocks dm-io start:%llu count:%lu", pba, count);
	jindisk_block_io(NULL, &ctx);
	disk_counter.write_io_blocks += count;
	disk_counter.write_io_count += 1;

#if ENABLE_JOURNAL
	hba = pba;
	journal = jindisk->meta->journal;
	ts = ktime_get_real_ns();
	for (i = 0; i < count; i++) {
		hba += i;
		jindisk->meta->rit->get(jindisk->meta->rit, hba, &lba);
		jindisk->lsm_tree->search(jindisk->lsm_tree, lba, &d_record);

		j_record.type = DATA_LOG;
		j_record.data_log.timestamp = ts;
		j_record.data_log.lba = lba;
		j_record.data_log.hba = hba;
		memcpy(j_record.data_log.key, d_record.key, AES_GCM_KEY_SIZE);
		memcpy(j_record.data_log.mac, d_record.mac, AES_GCM_AUTH_SIZE);

		journal->jops->add_record(journal, &j_record);
	}
#endif
}

void merge_read_io(struct blk_info **blks, int start, int end,
		   struct completion *wait, atomic_t *wait_cnt)
{
	struct diskio_ctx *ctx;
	void *buffer;
	int i, count;

	count = end - start + 1;
	ctx = kzalloc(sizeof(struct diskio_ctx), GFP_KERNEL);
	buffer = vmalloc(count * DATA_BLOCK_SIZE);
	if (!ctx || !buffer) {
		DMERR("malloc diskio_ctx or buffer failed lba:%llu count:%d",
		      blks[start]->lba, count);
		goto err;
	}
	ctx->infos = kzalloc(count * sizeof(struct blk_info *), GFP_KERNEL);
	if (!ctx->infos) {
		DMERR("kzalloc ctx->infos failed lba:%llu count:%d",
		      blks[start]->lba, count);
		goto err;
	}
	for (i = 0; i < count; ++i)
		ctx->infos[i] = blks[start + i];

	ctx->wait = wait;
	ctx->cnt = wait_cnt;

	atomic_inc(wait_cnt);
	jindisk_read_blocks(blks[start]->record->pba, count, buffer, DM_IO_VMA,
			    ctx);
	return;
err:
	if (ctx)
		kfree(ctx);
	if (buffer)
		vfree(buffer);
	for (i = start; i < count; ++i) {
		record_destroy(blks[i]->record);
		kfree(blks[i]);
	}
}

void read_small_block(uint32_t lba, struct memtable *results,
		      struct bio_vec *bv)
{
	int err = 0;
	void *buffer = NULL;
	void *data_out;
	struct record *old;

	if (!results || !bv)
		return;

	data_out = page_address(bv->bv_page);
	buffer = kzalloc(DATA_BLOCK_SIZE, GFP_KERNEL);
	if (!buffer) {
		DMERR("read_small_block kzalloc buffer failed");
		return;
	}

	err = jindisk->seg_buffer->query_block(jindisk->seg_buffer, lba,
					       buffer);
	if (!err) {
		DMDEBUG("read_small_block found in segment_buffer lba:%u", lba);
		goto copy_data;
	}

	err = results->get(results, lba, (void **)&old);
	if (err) {
		DMDEBUG("read_small_block found nodata lba:%u", lba);
		goto err;
	}
	DMDEBUG("read_small_block found lba:%u pba:%llu", lba, old->pba);
	jindisk_read_blocks(old->pba, 1, buffer, DM_IO_KMEM, NULL);
	jindisk->cipher->decrypt(jindisk->cipher, buffer, DATA_BLOCK_SIZE,
				 old->key, NULL, old->mac, old->pba, buffer);
copy_data:
	memcpy((char *)data_out + bv->bv_offset, (char *)buffer + bv->bv_offset,
	       bv->bv_len);
err:
	kfree(buffer);
	return;
}

void jindisk_do_read(struct bio *bio)
{
	int range_start, range_end;
	struct completion wait;
	atomic_t wait_cnt;
	struct memtable *results;
	dm_block_t start = bio_to_lba(bio);
	int count = DIV_ROUND_UP(bio->bi_iter.bi_size, DATA_BLOCK_SIZE);
	int io_count = 0;
	struct blk_info **blks =
		kzalloc(count * sizeof(struct blk_info *), GFP_KERNEL);

	DMDEBUG("jindisk read request start:%llu count:%d", start, count);
	disk_counter.read_req_blocks += count;
	if (!blks) {
		DMERR("jindisk_do_read kzalloc blk_info array failed");
		goto out;
	}

	results = jindisk->lsm_tree->range_search(jindisk->lsm_tree, start,
						  start + count - 1);
	while (bio->bi_iter.bi_size) {
		struct bio_vec bv = bio_iter_iovec(bio, bio->bi_iter);
		dm_block_t lba = bio_to_lba(bio);
		void *data_out = page_address(bv.bv_page);
		int err = 0;
		struct record *old;

		if (bio->bi_iter.bi_size < DATA_BLOCK_SIZE) {
			DMWARN("read < 4K lba:%llu offset:%d len:%d", lba,
			       bv.bv_offset, bv.bv_len);
			read_small_block(lba, results, &bv);
			break;
		}
		err = jindisk->seg_buffer->query_block(jindisk->seg_buffer, lba,
						       data_out);
		if (!err)
			goto next;

		if (results)
			err = results->get(results, lba, (void **)&old);
		if (!results || err || old->pba == INF_ADDR)
			goto next;

		blks[io_count] = kzalloc(sizeof(struct blk_info), GFP_KERNEL);
		if (!blks[io_count]) {
			DMERR("kzalloc blk_info failed lba:%llu", lba);
			goto next;
		}
		blks[io_count]->lba = lba;
		blks[io_count]->record = record_copy(old);
		blks[io_count]->page_addr = data_out;
		io_count += 1;
	next:
		bio_advance_iter(bio, &bio->bi_iter, DATA_BLOCK_SIZE);
	}
	if (results)
		results->destroy(results);

	init_completion(&wait);
	atomic_set(&wait_cnt, 0);

	for (range_start = 0, range_end = 0; range_end < io_count;
	     ++range_end) {
		if (range_end + 1 == io_count)
			goto merge_io;

		if (blks[range_end]->record->pba + 1 ==
		    blks[range_end + 1]->record->pba)
			continue;
	merge_io:
		merge_read_io(blks, range_start, range_end, &wait, &wait_cnt);
		range_start = range_end + 1;
	}
	kfree(blks);

	if (atomic_read(&wait_cnt))
		wait_for_completion_io(&wait);
out:
	bio_endio(bio);
}

void async_read(void *ctx)
{
	jindisk_do_read(ctx);
	up(&jindisk->max_reader);
}

void jindisk_do_write(struct bio *bio)
{
	down_read(&jindisk->meta->journal->valid_fields_lock);
	jindisk->seg_buffer->push_bio(jindisk->seg_buffer, bio);
	bio_endio(bio);
	up_read(&jindisk->meta->journal->valid_fields_lock);
}

void async_write(void *ctx)
{
	jindisk_do_write(ctx);
}

void process_deferred_bios(struct work_struct *ws)
{
	struct bio *bio;
	struct bio_list bios;
	bool timeout = false;

	bio_list_take_safe(jindisk, &bios, &jindisk->deferred_bios);
	while ((bio = bio_list_pop(&bios))) {
		switch (bio_op(bio)) {
		case REQ_OP_READ:
			timeout = down_timeout(&jindisk->max_reader,
					       msecs_to_jiffies(300));
			go(async_read, bio);
			break;
		case REQ_OP_WRITE:
			jindisk_do_write(bio);
			break;
		}
	}
}

void backup_metadata(struct block_device *bdev, dm_block_t dst, dm_block_t src,
		     int blk_count, void *buffer, struct dm_io_client *client)
{
	int i;
	unsigned long sync_error_bits;
	struct dm_io_request req = {
		.mem.type = DM_IO_KMEM,
		.mem.offset = 0,
		.mem.ptr.addr = buffer,
		.notify.fn = NULL,
		.client = client,
	};
	struct dm_io_region region = {
		.bdev = bdev,
		.count = SECTORS_PER_BLOCK,
	};

	for (i = 0; i < blk_count; i++) {
		// read from src
		req.bi_op = REQ_OP_READ;
		region.sector = (src + i) * SECTORS_PER_BLOCK;
		dm_io(&req, 1, &region, &sync_error_bits);
		if (sync_error_bits)
			DMERR("backup_metadata: dm_io read error");
		// write to dst
		sync_error_bits = 0;
		req.bi_op = REQ_OP_WRITE;
		region.sector = (dst + i) * SECTORS_PER_BLOCK;
		dm_io(&req, 1, &region, &sync_error_bits);
		if (sync_error_bits)
			DMERR("backup_metadata: dm_io write error");
	}
}

void add_checkpoint_pack_record(struct metadata *meta)
{
	int blk_count, i;
	uint64_t record_index;
	void *buffer = NULL;
	dm_block_t base, src, dst;
	struct dm_io_client *client = NULL;
	struct journal_region *journal = meta->journal;
	struct journal_record j_record;

	buffer = kmalloc(METADATA_BLOCK_SIZE, GFP_KERNEL);
	if (!buffer) {
		DMERR("add_checkpoint_pack_record: kmalloc failed");
		return;
	}
	client = dm_io_client_create();
	if (!client) {
		DMERR("add_checkpoint_pack_record: dm_io_client_create failed");
		kfree(buffer);
		return;
	}

	down_write(&journal->valid_fields_lock);
	// backup metadata: SVT/DST/RIT/BITC
	for (i = 0; i < NR_CHECKPOINT_FIELDS; i++) {
		switch (i) {
		case DATA_SVT:
			base = meta->superblock->seg_validity_table_start;
			blk_count = meta->seg_validator->blk_count;
			break;
		case DATA_DST:
			base = meta->superblock->data_seg_table_start;
			blk_count = meta->dst->blk_count;
			break;
		case DATA_RIT:
			base = meta->superblock->reverse_index_table_start;
			blk_count = meta->rit->blk_count;
			break;
		case INDEX_SVT:
			base = meta->superblock
				       ->block_index_table_catalogue_start;
			blk_count = meta->bit_catalogue->bit_validity_table
					    ->blk_count;
			break;
		case INDEX_BITC:
			base = meta->superblock
				       ->block_index_table_catalogue_start +
			       meta->bit_catalogue->bit_validity_table
					       ->blk_count *
				       NR_CHECKPOINT_PACKS;
			blk_count = meta->bit_catalogue->blk_count;
			break;
		default:
			break;
		}
		if (test_bit(i, journal->valid_fields)) {
			dst = base;
			src = dst + blk_count;
		} else {
			src = base;
			dst = src + blk_count;
		}
		backup_metadata(jindisk->raw_dev->bdev, dst, src, blk_count,
				buffer, client);
	}
	up_write(&journal->valid_fields_lock);
	// add journal_record
	j_record.type = CHECKPOINT_PACK;
	j_record.checkpoint_pack.record_start = journal->record_start;
	j_record.checkpoint_pack.record_end = journal->record_end;
	bitmap_complement(j_record.checkpoint_pack.valid_fields,
			  journal->valid_fields, NR_CHECKPOINT_FIELDS);
	j_record.checkpoint_pack.timestamp = ktime_get_real_ns();
	record_index = journal->jops->add_record(journal, &j_record);

	meta->superblock->last_checkpoint_pack = record_index;
	journal->record_start = record_index;

	dm_io_client_destroy(client);
	kfree(buffer);
}

void flush_and_commit(struct dm_jindisk *jindisk, struct bio *bio)
{
	int i;
	loff_t start, end;
	struct file *fp;
	struct journal_region *journal;
	struct journal_record j_record;

	DMDEBUG("flush_and_commit...");
	// flush data segment_buffer
	for (i = 0; i < POOL_SIZE; i++)
		jindisk->seg_buffer->flush_bios(jindisk->seg_buffer, i);
	// flush index region
	fp = jindisk->lsm_tree->file;
	start = jindisk->meta->superblock->index_region_start *
		METADATA_BLOCK_SIZE;
	end = jindisk->meta->superblock->journal_region_start *
	      METADATA_BLOCK_SIZE;
	vfs_fsync_range(fp, start, end, 0);
	// flush checkpoint region
	dm_bufio_write_dirty_buffers(jindisk->meta->bc);

	// add data_commit record
	journal = jindisk->meta->journal;
	j_record.type = DATA_COMMIT;
	j_record.data_commit.timestamp = ktime_get_real_ns();
	journal->jops->add_record(journal, &j_record);
	// add checkpoint_pack record
	add_checkpoint_pack_record(jindisk->meta);
	// flush journal_region
	journal->jops->synchronize(journal);
}

static void jindisk_map_bio(struct dm_target *ti, struct bio *bio)
{
	struct dm_jindisk *jindisk = ti->private;
	sector_t origin = bio->bi_iter.bi_sector;

	bio_set_dev(bio, jindisk->raw_dev->bdev);
	if (unlikely(ti->begin != 0))
		bio->bi_iter.bi_sector = dm_target_offset(ti, origin);
}

static int dm_jindisk_target_map(struct dm_target *target, struct bio *bio)
{
	struct dm_jindisk *jindisk = target->private;

	jindisk_map_bio(target, bio);

	if (unlikely(bio->bi_iter.bi_size > (MAX_NR_FETCH * DATA_BLOCK_SIZE)))
		dm_accept_partial_bio(bio, (MAX_NR_FETCH * SECTORS_PER_BLOCK));

	switch (bio_op(bio)) {
	case REQ_OP_READ:
	case REQ_OP_WRITE:
		defer_bio(jindisk, bio);
		break;
	case REQ_OP_FLUSH:
		flush_and_commit(jindisk, bio);
		fallthrough;
	default:
		return DM_MAPIO_REMAPPED;
	}
	return DM_MAPIO_SUBMITTED;
}

sector_t dm_devsize(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

void dm_jindisk_destroy(struct dm_target *ti, struct dm_jindisk *sd)
{
	if (sd->seg_buffer)
		sd->seg_buffer->destroy(sd->seg_buffer);
	if (sd->seg_allocator)
		sd->seg_allocator->destroy(sd->seg_allocator);
	if (sd->lsm_tree)
		sd->lsm_tree->destroy(sd->lsm_tree);
	if (sd->meta)
		sd->meta->destroy(sd->meta);
	if (sd->cipher)
		sd->cipher->destroy(sd->cipher);
	if (sd->io_client)
		dm_io_client_destroy(sd->io_client);

	dm_put_device(ti, sd->raw_dev);
	if (sd)
		kfree(sd);
}

/*
 * This is constructor function of target gets called when we create some device
 * of type 'dm_jindisk'. i.e on execution of command 'dmsetup create'. It gets
 * called per device.
 */
static int dm_jindisk_target_ctr(struct dm_target *target, unsigned int argc,
				 char **argv)
{
	char root_key[AES_GCM_KEY_SIZE];
	char root_iv[AES_GCM_IV_SIZE];
	uint64_t total_sector;
	unsigned long action_flag = 0;
	int ret;

	if (argc != 4) {
		DMERR("Invalid no. of arguments.");
		target->error = "Invalid argument count";
		ret = -EINVAL;
		goto bad;
	}

	jindisk = kzalloc(sizeof(struct dm_jindisk), GFP_KERNEL);
	if (!jindisk) {
		DMERR("Error in kmalloc");
		target->error = "Cannot allocate linear context";
		ret = -ENOMEM;
		goto bad;
	}

	if (hex2bin((u8 *)root_key, argv[0], AES_GCM_KEY_SIZE) != 0) {
		target->error = "Invalid key";
		ret = -EINVAL;
		goto bad;
	}

	if (hex2bin((u8 *)root_iv, argv[1], AES_GCM_IV_SIZE) != 0) {
		target->error = "Invalid iv";
		ret = -EINVAL;
		goto bad;
	}

	if (dm_get_device(target, argv[2], dm_table_get_mode(target->table),
			  &jindisk->raw_dev)) {
		target->error = "dm-basic_target: Device lookup failed";
		goto bad;
	}

	if (kstrtoul(argv[3], 10, &action_flag) != 0) {
		target->error = "Invalid action flag";
		goto bad;
	}

	NR_SEGMENT = div_u64(target->len, SECTORS_PER_SEGMENT);
	total_sector = calc_metadata_blocks(NR_SEGMENT + NR_GC_PRESERVED) *
			       SECTORS_PER_BLOCK +
		       target->len + NR_GC_PRESERVED * SECTORS_PER_SEGMENT;
	if (total_sector > dm_devsize(jindisk->raw_dev)) {
		target->error = "raw disk not big enough for target->len";
		ret = -EAGAIN;
		goto bad;
	}

	sema_init(&jindisk->max_reader, MAX_READER);
	jindisk->io_client = dm_io_client_create();
	if (!jindisk->io_client) {
		target->error = "could not create dm-io client for jindisk";
		ret = -EAGAIN;
		goto bad;
	}

	jindisk->cipher = aes_gcm_cipher_create();
	if (!jindisk->cipher) {
		target->error = "could not create jindisk cipher";
		ret = -EAGAIN;
		goto bad;
	}

	jindisk->meta = metadata_create(root_key, root_iv, action_flag,
					jindisk->raw_dev->bdev);
	if (!jindisk->meta) {
		target->error = "could not create jindisk metadata";
		ret = -EAGAIN;
		goto bad;
	}

	jindisk->lsm_tree =
		lsm_tree_create(argv[2],
				&jindisk->meta->bit_catalogue->lsm_catalogue,
				jindisk->cipher);
	if (!jindisk->lsm_tree) {
		target->error = "could not create jindisk lsm tree";
		ret = -EAGAIN;
		goto bad;
	}

	jindisk->seg_allocator = sa_create();
	if (!jindisk->seg_allocator) {
		target->error = "could not create jindisk segment allocator";
		ret = -EAGAIN;
		goto bad;
	}

	spin_lock_init(&jindisk->req_lock);
	bio_list_init(&jindisk->deferred_bios);
	jindisk->seg_buffer = segbuf_create();
	if (!jindisk->seg_buffer) {
		target->error = "could not create jindisk segment buffer";
		ret = -EAGAIN;
		goto bad;
	}

	INIT_WORK(&jindisk->deferred_bio_worker, process_deferred_bios);
	target->private = jindisk;
	return 0;
bad:
	dm_jindisk_destroy(target, jindisk);
	DMERR("Exit: %s with ERROR", __func__);
	return ret;
}

/*
 *  This is destruction function, gets called per device.
 *  It removes device and decrement device count.
 */
static void dm_jindisk_target_dtr(struct dm_target *ti)
{
	struct dm_jindisk *sd = (struct dm_jindisk *)ti->private;

	dm_jindisk_destroy(ti, sd);
}

/*  This structure is fops for dm_jindisk target */
static struct target_type dm_jindisk = {
	.name = "jindisk",
	.version = { 1, 0, 0 },
	.module = THIS_MODULE,
	.ctr = dm_jindisk_target_ctr,
	.dtr = dm_jindisk_target_dtr,
	.map = dm_jindisk_target_map,
};

/*---- sysfs interface ----*/

static ssize_t disk_stats_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	int size = 0;

	size += sysfs_emit_at(buf, size, "read_req_blocks:%llu\n",
			      disk_counter.read_req_blocks);
	size += sysfs_emit_at(buf, size, "read_io_blocks:%llu\n",
			      disk_counter.read_io_blocks);
	size += sysfs_emit_at(buf, size, "read_io_count:%llu\n\n",
			      disk_counter.read_io_count);

	size += sysfs_emit_at(buf, size, "write_req_blocks:%llu\n",
			      disk_counter.write_req_blocks);
	size += sysfs_emit_at(buf, size, "write_io_blocks:%llu\n",
			      disk_counter.write_io_blocks);
	size += sysfs_emit_at(buf, size, "write_io_count:%llu\n\n",
			      disk_counter.write_io_count);

	size += sysfs_emit_at(buf, size, "minor_compaction:%llu\n",
			      disk_counter.minor_compaction);
	size += sysfs_emit_at(buf, size, "major_compaction:%llu\n\n",
			      disk_counter.major_compaction);
	size += sysfs_emit_at(buf, size, "bit_created:%llu\n",
			      disk_counter.bit_created);
	size += sysfs_emit_at(buf, size, "bit_removed:%llu\n",
			      disk_counter.bit_removed);
	size += sysfs_emit_at(buf, size, "bit_node_cache_hit:%llu\n",
			      disk_counter.bit_node_cache_hit);
	size += sysfs_emit_at(buf, size, "bit_node_cache_miss:%llu\n",
			      disk_counter.bit_node_cache_miss);

	return size;
}
static const struct kobj_attribute disk_stats = __ATTR_RO(disk_stats);

static ssize_t clear_stats_store(struct kobject *kobj,
				 struct kobj_attribute *attr, const char *buf,
				 size_t n)
{
	int value = 0;

	if (kstrtouint(buf, 10, &value) < 0)
		return -EINVAL;

	if (value > 0)
		memset(&disk_counter, 0, sizeof(disk_counter));

	return n;
}
static const struct kobj_attribute clear_stats =
	__ATTR(clear_stats, 0200, NULL, clear_stats_store);

static const struct attribute *disk_attributes[] = { &disk_stats.attr,
						     &clear_stats.attr, NULL };

/*---- ioctl interface ----*/

#define JINDISK_IOC_MAGIC 'J'
#define NR_CALC_AVAIL_SECTORS 0
#define NR_GET_MEASUREMENT 1

#define JINDISK_CALC_AVAIL_SECTORS                                             \
	_IOWR(JINDISK_IOC_MAGIC, NR_CALC_AVAIL_SECTORS, struct calc_task)
#define JINDISK_GET_MEASUREMENT                                                \
	_IOR(JINDISK_IOC_MAGIC, NR_GET_MEASUREMENT, char[AES_GCM_AUTH_SIZE])

struct calc_task {
	uint64_t real_sectors;
	uint64_t avail_sectors;
};

static long ctl_calc_avail_sectors(unsigned long arg)
{
	long r = -EINVAL;
	struct calc_task ct;

	r = copy_from_user(&ct, (void __user *)arg, sizeof(struct calc_task));
	if (r)
		goto out;

	ct.avail_sectors = calc_avail_sectors(ct.real_sectors);

	r = copy_to_user((void __user *)arg, &ct, sizeof(struct calc_task));
out:
	return r;
}

static long ctl_get_measurement(unsigned long arg)
{
	long r = -EINVAL;
	char *mac = NULL;
	uint32_t size = 0;

	if (jindisk == NULL) {
		DMERR("jindisk target is missing");
		goto out;
	}
	mac = jindisk->meta->superblock->root_mac;
	size = _IOC_SIZE(JINDISK_GET_MEASUREMENT);
	r = copy_to_user((void __user *)arg, mac, size);
out:
	return r;
}

static long dev_jindisk_ioctl(struct file *filp, unsigned int ioctl,
			      unsigned long arg)
{
	long r = -EINVAL;

	switch (ioctl) {
	case JINDISK_CALC_AVAIL_SECTORS:
		r = ctl_calc_avail_sectors(arg);
		break;
	case JINDISK_GET_MEASUREMENT:
		r = ctl_get_measurement(arg);
		break;
	default:
		break;
	}
	return r;
}

static const struct file_operations dev_jindisk_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = dev_jindisk_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = dev_jindisk_ioctl,
#endif
};

static struct miscdevice dev_jindisk = {
	MISC_DYNAMIC_MINOR,
	"jindisk",
	&dev_jindisk_fops,
};

/*---------Module Functions -----------------*/
static int init_dm_jindisk_target(void)
{
	int r;
	struct kobject *mod_kobj = &(THIS_MODULE->mkobj.kobj);

	r = sysfs_create_files(mod_kobj, disk_attributes);
	if (r) {
		DMERR("sysfs_create_files failed err:%d", r);
		goto out;
	}

	r = misc_register(&dev_jindisk);
	if (r) {
		DMERR("misc_register failed err:%d", r);
		goto free_sysfs;
	}

	r = dm_register_target(&dm_jindisk);
	if (r) {
		DMERR("dm_register_target failed err:%d", r);
		goto free_misc;
	}

	DMINFO("target registered");
	return 0;
free_misc:
	misc_deregister(&dev_jindisk);
free_sysfs:
	sysfs_remove_files(mod_kobj, disk_attributes);
out:
	return r;
}

static void cleanup_dm_jindisk_target(void)
{
	struct kobject *mod_kobj = &(THIS_MODULE->mkobj.kobj);

	sysfs_remove_files(mod_kobj, disk_attributes);
	misc_deregister(&dev_jindisk);
	dm_unregister_target(&dm_jindisk);
	DMINFO("target unregistered");
}

module_init(init_dm_jindisk_target);
module_exit(cleanup_dm_jindisk_target);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Ant Group");
