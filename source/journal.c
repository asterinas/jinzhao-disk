#include "../include/metadata.h"

struct rw_semaphore seg_rwsem[NR_JOURNAL_SEGMENT];

struct journal_ctx {
	int bi_op;
	int segnum;
	struct dm_io_client *client;
	struct completion *wait;
};

void journal_iocb(unsigned long error, void *ctx)
{
	struct journal_ctx *jctx = ctx;

	if (error)
		DMERR("journal region io error\n");

	dm_io_client_destroy(jctx->client);
	if (jctx->wait)
		complete(jctx->wait);

	switch (jctx->bi_op) {
	case REQ_OP_READ:
		up_read(&seg_rwsem[jctx->segnum]);
		break;
	case REQ_OP_WRITE:
		up_write(&seg_rwsem[jctx->segnum]);
		break;
	default:
		DMERR("unsupported bi_op\n");
		break;
	}
	kfree(jctx);
}

void journal_region_io(struct block_device *bdev, dm_block_t blkaddr,
		       int count, void *buffer, struct journal_ctx *ctx)
{
	struct dm_io_request req = {
		.bi_op = ctx->bi_op,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buffer,
		.notify.fn = journal_iocb,
		.notify.context = ctx,
		.client = ctx->client,
	};
	struct dm_io_region region = {
		.bdev	= bdev,
		.sector = blkaddr * SECTORS_PER_BLOCK,
		.count	= SECTORS_PER_BLOCK * count,
	};

	dm_io(&req, 1, &region, 0);
}

// load journal_records from disk
void journal_load(struct journal_region *this)
{
	int i, j, segstart, segend, segcount;
	struct completion *wait_on;

	if (this->record_start == this->record_end)
		goto out;

	segstart = this->record_start / JOURNAL_PER_SEGMENT;
	segend = this->record_end / JOURNAL_PER_SEGMENT;
	if (this->record_start < this->record_end)
		segcount = segend - segstart + 1;
	else
		segcount = min(segend + NR_JOURNAL_SEGMENT - segstart + 1,
			       NR_JOURNAL_SEGMENT);

	wait_on = kmalloc(segcount * sizeof(struct completion), GFP_KERNEL);
	if (!wait_on) {
		DMERR("kmalloc failed for wait_on\n");
		goto err;
	}

	for (i = 0;i < segcount; i++) {
		int segnum = (segstart + i) % NR_JOURNAL_SEGMENT;
		uint64_t blkaddr = this->superblock->journal_region_start +
					segnum * BLOCKS_PER_SEGMENT;
		void *buffer = this->records[segnum];
		struct journal_ctx *ctx = kmalloc(sizeof(struct journal_ctx),
						  GFP_KERNEL);
		if (!ctx) {
			DMERR("kmalloc failed for journal_ctx\n");
			break;
		}

		ctx->bi_op = REQ_OP_READ;
		ctx->segnum = segnum;
		ctx->client = dm_io_client_create();
		init_completion(&wait_on[i]);
		ctx->wait = &wait_on[i];
		down_read(&seg_rwsem[segnum]);

		journal_region_io(sworndisk->metadata_dev->bdev, blkaddr,
				  BLOCKS_PER_SEGMENT, buffer, ctx);
	}

	for (j = 0; j < i; j++)
		wait_for_completion_io(&wait_on[j]);

	if (i != segcount)
		goto err;

	this->last_sync_segnum = segend;
out:
	this->status = JOURNAL_LOADED;
err:
	if (wait_on)
		kfree(wait_on);
}
// check hmacs of journal_records, recover if failed
bool journal_should_recover(struct journal_region *this)
{
	// check hmac chain, if failed
	//	this->status = JOURNAL_RECOVERING; return true;
	// else
	//	this->status = JOURNAL_READY; return false;
	this->status = JOURNAL_READY;
	return false;
}

void journal_recover(struct journal_region *this)
{
	this->status = JOURNAL_READY;
}
// write journal_records to disk, also update the
// superblock->record_start/end to disk
void journal_synchronize(struct journal_region *this, int segnum)
{
	uint64_t blkaddr = this->superblock->journal_region_start +
				segnum * BLOCKS_PER_SEGMENT;
	void *buffer = this->records[segnum];
	struct completion wait;
	struct journal_ctx *ctx = kmalloc(sizeof(struct journal_ctx), GFP_KERNEL);

	if (!ctx) {
		DMERR("kmalloc failed for journal_ctx\n");
		return;
	}

	ctx->bi_op = REQ_OP_WRITE;
	ctx->segnum = segnum;
	ctx->client = dm_io_client_create();
	init_completion(&wait);
	ctx->wait = &wait;
	down_write(&seg_rwsem[segnum]);

	journal_region_io(sworndisk->metadata_dev->bdev, blkaddr,
			  BLOCKS_PER_SEGMENT, buffer, ctx);

	wait_for_completion_io(&wait);

	this->superblock->record_start = this->record_start;
	this->superblock->record_end = this->record_end;
	this->superblock->write(this->superblock);
	this->status = JOURNAL_READY;
}

void journal_add_record(struct journal_region *this, struct journal_record *record)
{
	struct journal_record **records = this->records;
	int segnum = this->record_end / JOURNAL_PER_SEGMENT;
	int index = this->record_end % JOURNAL_PER_SEGMENT;

	records[segnum][index].type = record->type;
	switch (record->type) {
	case DATA_LOG:
		records[segnum][index].data_log = record->data_log;
		break;
	case DATA_COMMIT:
		records[segnum][index].data_commit = record->data_commit;
		break;
	case BIT_COMPACTION:
		records[segnum][index].bit_compaction = record->bit_compaction;
		break;
	case BIT_NODE:
		records[segnum][index].bit_node = record->bit_node;
		break;
	case CHECKPOINT_PACK:
		records[segnum][index].checkpoint_pack = record->checkpoint_pack;
		break;
	default:
		DMERR("undefined journal record type\n");
		break;
	}
	//TODO:
	//	records[segnum][index].hmac =
	this->record_end = (this->record_end + 1) % this->record_max;
	if (this->record_end == this->record_start)
		this->record_start = (this->record_start + 1) % this->record_max;

	if (this->last_sync_segnum != segnum) {
		this->status = JOURNAL_SYNCHRONIZING;
		this->jops->synchronize(this, this->last_sync_segnum);
		this->last_sync_segnum = segnum;
	}
}

struct journal_operations default_jops = {
	.load		= journal_load,
	.should_recover = journal_should_recover,
	.recover	= journal_recover,
	.synchronize	= journal_synchronize,
	.add_record	= journal_add_record,
};

int journal_region_init(struct journal_region *this, struct superblock *superblock)
{
	int i;

	this->status = JOURNAL_UNINITIALIZED;
	this->superblock = superblock;
	this->jops = &default_jops;
	this->record_start = superblock->record_start;
	this->record_end = superblock->record_end;
	this->record_max = superblock->nr_journal;
	this->records = kmalloc(NR_JOURNAL_SEGMENT * sizeof(struct journal_record *),
			       GFP_KERNEL);
	if (!this->records)
		return -ENOMEM;
	for (i = 0; i < NR_JOURNAL_SEGMENT; i++) {
		this->records[i] = kmalloc(SEGMENT_BUFFER_SIZE, GFP_KERNEL);
		if (!this->records[i])
			return -ENOMEM;
	}
	for (i = 0; i < NR_JOURNAL_SEGMENT; i++)
		init_rwsem(&seg_rwsem[i]);

	this->jops->load(this);
	if (this->status == JOURNAL_LOADED && this->jops->should_recover(this))
		this->jops->recover(this);

	if (this->status == JOURNAL_READY)
		return 0;

	return -EAGAIN;
}

struct journal_region *journal_region_create(struct superblock *superblock)
{
	int r;
	struct journal_region *this;

	this = kmalloc(sizeof(struct journal_region), GFP_KERNEL);
	if (!this)
		return NULL;

	r = journal_region_init(this, superblock);
	if (r)
		return NULL;

	return this;
}

void journal_region_destroy(struct journal_region *this)
{
	int i;

	if (this->records) {
		for (i = 0; i < NR_JOURNAL_SEGMENT; i++) {
			if (this->records[i])
				kfree(this->records[i]);
		}
		kfree(this->records);
	}
	if (this)
		kfree(this);
}
