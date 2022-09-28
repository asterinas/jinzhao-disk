#include "../include/metadata.h"

struct journal_ctx {
	int bi_op;
	int blk_num;
	struct journal_block *buffer;
	struct completion *wait;
	atomic64_t *cnt;
};

void journal_iocb(unsigned long error, void *ctx)
{
	struct journal_ctx *jctx = ctx;

	if (error)
		DMERR("journal region io error\n");

	if (jctx->wait && atomic64_dec_and_test(jctx->cnt))
		complete(jctx->wait);

	if (jctx->buffer)
		kfree(jctx->buffer);
	kfree(jctx);
}

void journal_region_io(struct dm_io_client *client, dm_block_t blk_pba,
		       int count, void *buffer, struct journal_ctx *ctx)
{
	struct dm_io_request req = {
		.bi_op = ctx->bi_op,
		.mem.type = DM_IO_KMEM,
		.mem.ptr.addr = buffer,
		.notify.fn = journal_iocb,
		.notify.context = ctx,
		.client = client,
	};
	struct dm_io_region region = {
		.bdev	= sworndisk->raw_dev->bdev,
		.sector = blk_pba * SECTORS_PER_BLOCK,
		.count	= count * SECTORS_PER_BLOCK,
	};

	dm_io(&req, 1, &region, 0);
}

struct journal_block *journal_get_block(struct journal_region *this,
					uint64_t blk_num)
{
	int segno = blk_num / BLOCKS_PER_SEGMENT;
	int offset = blk_num % BLOCKS_PER_SEGMENT;

	if (segno != this->buffer.segno)
		this->jops->load(this, blk_num * RECORDS_PER_BLOCK, this->record_end);

	return &this->buffer.blocks[offset];
}

static int journal_derive_key(char *master_key, uint64_t blk_num,
			      char *derived_key, int derived_keysize)
{
	int rc = 0;
	char src_key[AES_GCM_KEY_SIZE];
	uint32_t csum;
	struct skcipher_request *req = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist src_sg, dst_sg;
	struct crypto_skcipher *tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);

	if (IS_ERR(tfm)) {
		rc = PTR_ERR(tfm);
		tfm = NULL;
		goto out;
	}

	memcpy(src_key, &blk_num, 8);
	csum = crc32_be(blk_num, master_key, AES_GCM_KEY_SIZE);
	memcpy(src_key + 8, &csum, 4);
	csum = crc32_be(~blk_num, master_key, AES_GCM_KEY_SIZE);
	memcpy(src_key + 12, &csum, 4);

	crypto_skcipher_set_flags(tfm, CRYPTO_TFM_REQ_FORBID_WEAK_KEYS);
	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		rc = -ENOMEM;
		goto out;
	}
	skcipher_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &wait);
	rc = crypto_skcipher_setkey(tfm, master_key, AES_GCM_KEY_SIZE);
	if (rc < 0)
		goto out;

	sg_init_one(&src_sg, src_key, AES_GCM_KEY_SIZE);
	sg_init_one(&dst_sg, derived_key, derived_keysize);
	skcipher_request_set_crypt(req, &src_sg, &dst_sg, derived_keysize,
				   NULL);
	rc = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
out:
	skcipher_request_free(req);
	crypto_free_skcipher(tfm);
	return rc;
}

void journal_encrypt_block(struct journal_region *this, uint64_t blk_num,
			   struct journal_block *buffer)
{
	struct journal_block *pre_blk, *cur_blk;
	char blk_key[AES_GCM_KEY_SIZE];
	char *blk_mac, *blk_iv;
	int rc;

	cur_blk = this->jops->get_block(this, blk_num);
	if (blk_num % BLOCKS_PER_SEGMENT == 0)
		cur_blk->previous_blk = this->buffer.previous_blk;
	else {
		pre_blk = this->jops->get_block(this, blk_num - 1);
		cur_blk->previous_blk = pre_blk->current_blk;
	}

	rc = journal_derive_key(this->superblock->root_key, blk_num,
				blk_key, AES_GCM_KEY_SIZE);
	if (rc) {
		DMERR("journal derive encrypt_key failed\n");
		return;
	}
	blk_mac = cur_blk->current_blk.mac;
	blk_iv = cur_blk->current_blk.iv;
	get_random_bytes(blk_iv, AES_GCM_IV_SIZE);

	rc = this->cipher->encrypt(this->cipher, (char *)cur_blk, BLOCK_CRYPT_LEN,
				   blk_key, blk_iv, blk_mac, blk_num, (char *)buffer);
	if (rc)
		DMERR("journal_encrypt_block failed\n");

	buffer->current_blk = cur_blk->current_blk;
	if (blk_num % BLOCKS_PER_SEGMENT == BLOCKS_PER_SEGMENT - 1)
		this->buffer.previous_blk = cur_blk->current_blk;
}

void journal_decrypt_block(struct journal_region *this, uint64_t blk_num)
{
	struct journal_block *cur_blk;
	char blk_key[AES_GCM_KEY_SIZE];
	char *blk_mac, *blk_iv;
	int rc;

	rc = journal_derive_key(this->superblock->root_key, blk_num,
				blk_key, AES_GCM_KEY_SIZE);
	if (rc) {
		DMERR("journal derive decrypt_key failed\n");
		return;
	}
	cur_blk = this->jops->get_block(this, blk_num);
	blk_mac = cur_blk->current_blk.mac;
	blk_iv = cur_blk->current_blk.iv;

	rc = this->cipher->decrypt(this->cipher, (char *)cur_blk, BLOCK_CRYPT_LEN,
				   blk_key, blk_iv, blk_mac, blk_num, (char *)cur_blk);
	if (rc)
		DMERR("journal_decrypt_block failed\n");
}

void journal_buffer_load(struct journal_region *this, uint64_t record_start,
			 uint64_t record_end)
{
	int i, offset, segno;
	uint64_t blk_start, blk_end, blk_count, blk_pba;
	struct journal_ctx *ctx;
	struct journal_block *buffer;
	struct completion wait;
	atomic64_t read_cnt;
	struct dm_io_client *client;

	segno = record_start / RECORDS_PER_SEGMENT;
	if (segno >= NR_JOURNAL_SEGMENT) {
		DMERR("record_start out of the journal_region\n");
		return;
	}

	mutex_lock(&this->sync_lock);
	this->buffer.segno = segno;
	mutex_unlock(&this->sync_lock);
	if (record_start == record_end)
		return;

	blk_start = record_start / RECORDS_PER_BLOCK;
	offset = blk_start % BLOCKS_PER_SEGMENT;
	if (record_end > record_start && segno == (record_end / RECORDS_PER_SEGMENT)) {
		blk_end = (record_end - 1) / RECORDS_PER_BLOCK;
		blk_count = blk_end - blk_start + 1;
	} else {
		blk_count = BLOCKS_PER_SEGMENT - offset;
	}

	client = dm_io_client_create();
	init_completion(&wait);
	atomic64_set(&read_cnt, blk_count);

	for (i = 0;i < blk_count; i++) {
		blk_pba = this->superblock->journal_region_start + blk_start + i;
		buffer = &this->buffer.blocks[offset + i];

		ctx = kmalloc(sizeof(struct journal_ctx), GFP_KERNEL);
		if (!ctx) {
			DMERR("journal_load: kmalloc failed for journal_ctx\n");
			break;
		}

		ctx->bi_op = REQ_OP_READ;
		ctx->blk_num = blk_start + i;
		ctx->buffer = NULL;
		ctx->wait = &wait;
		ctx->cnt = &read_cnt;

		journal_region_io(client, blk_pba, 1, buffer, ctx);
	}

	if (!atomic64_sub_and_test(blk_count - i, &read_cnt))
		wait_for_completion_io(&wait);

	dm_io_client_destroy(client);
	if (i != blk_count) {
		DMERR("journal_buffer_load not completed\n");
		return;
	}

	for (i = 0;i < blk_count; i++)
		this->jops->decrypt_block(this, blk_start + i);

	this->status = JOURNAL_LOADED;
}

// check hmacs of journal_records, recover if failed
bool journal_should_recover(struct journal_region *this)
{
	if (this->record_end == (this->record_start + 1) % MAX_RECORDS) {
		this->status = JOURNAL_READY;
		return false;
	} else {
		this->status = JOURNAL_RECOVERING;
		return true;
	}
}

void journal_recover(struct journal_region *this)
{
	uint64_t i;
	struct journal_block *blk;
	struct journal_record *record;

	for (i = this->record_start; i != this->record_end;) {
		blk = this->jops->get_block(this, i / RECORDS_PER_BLOCK);
		record = &blk->records[i % RECORDS_PER_BLOCK];
		// TODO: recover data_log/bit_compaction
		i = (i + 1) % MAX_RECORDS;
	}

	this->last_sync_record = this->record_end;
	this->status = JOURNAL_READY;
}

bool journal_should_sync(struct journal_region *this)
{
	int segno = this->record_end / RECORDS_PER_SEGMENT;

	return segno != this->buffer.segno;
}
// write journal_records to disk, also update the
// superblock->record_start/end to disk
void journal_synchronize(struct journal_region *this)
{
	int i, blk_count;
	uint64_t blk_start, blk_end, blk_pba;
	struct journal_ctx *ctx;
	struct journal_block *buffer;
	struct completion wait;
	atomic64_t write_cnt;
	struct dm_io_client *client;

	if (this->last_sync_record == this->record_end)
		return;

	blk_start = this->last_sync_record / RECORDS_PER_BLOCK;
	if (this->record_end % RECORDS_PER_SEGMENT != 0) {
		blk_end = (this->record_end - 1) / RECORDS_PER_BLOCK;
		blk_count = blk_end - blk_start + 1;
	} else {
		blk_count = BLOCKS_PER_SEGMENT - (blk_start % BLOCKS_PER_SEGMENT);
	}

	client = dm_io_client_create();
	init_completion(&wait);
	atomic64_set(&write_cnt, blk_count);
	mutex_lock(&this->sync_lock);

	for (i = 0;i < blk_count; i++) {
		blk_pba = this->superblock->journal_region_start + blk_start + i;

		buffer = kmalloc(sizeof(struct journal_block), GFP_KERNEL);
		if (!buffer) {
			DMERR("journal_sync: kmalloc failed for write buffer\n");
			break;
		}
		ctx = kmalloc(sizeof(struct journal_ctx), GFP_KERNEL);
		if (!ctx) {
			DMERR("journal_sync: kmalloc failed for journal_ctx\n");
			kfree(buffer);
			break;
		}

		this->jops->encrypt_block(this, blk_start + i, buffer);

		ctx->bi_op = REQ_OP_WRITE;
		ctx->blk_num = blk_start + i;
		ctx->buffer = buffer;
		ctx->wait = &wait;
		ctx->cnt = &write_cnt;

		journal_region_io(client, blk_pba, 1, buffer, ctx);
	}
	if (!atomic64_sub_and_test(blk_count - i, &write_cnt))
		wait_for_completion_io(&wait);

	if (i != blk_count) {
		DMERR("journal_sync not completed\n");
		this->last_sync_record = (blk_start + i) * RECORDS_PER_BLOCK;
	} else {
		this->last_sync_record = this->record_end;
	}
	mutex_unlock(&this->sync_lock);
	dm_io_client_destroy(client);

	if (this->last_sync_record == this->record_end) {
		this->superblock->record_start = this->record_start;
		this->superblock->record_end = this->record_end;
		this->superblock->write(this->superblock);
	}
	this->status = JOURNAL_READY;
}

uint64_t journal_add_record(struct journal_region *this, struct journal_record *record)
{
	uint64_t ret;
	struct journal_block *blk;
	struct journal_record *buffer;

	blk = this->jops->get_block(this, this->record_end / RECORDS_PER_BLOCK);
	buffer = &blk->records[this->record_end % RECORDS_PER_BLOCK];
	buffer->type = record->type;
	switch (record->type) {
	case DATA_LOG:
		buffer->data_log = record->data_log;
		break;
	case DATA_COMMIT:
		buffer->data_commit = record->data_commit;
		break;
	case BIT_COMPACTION:
		buffer->bit_compaction = record->bit_compaction;
		break;
	case BIT_NODE:
		buffer->bit_node = record->bit_node;
		break;
	case CHECKPOINT_PACK:
		buffer->checkpoint_pack = record->checkpoint_pack;
		break;
	default:
		DMERR("undefined journal record type\n");
		break;
	}

	ret = this->record_end;
	this->record_end = (this->record_end + 1) % MAX_RECORDS;
	if (this->record_end == this->record_start)
		this->record_start = (this->record_start + 1) % MAX_RECORDS;

	if (this->jops->should_sync(this)) {
		this->status = JOURNAL_SYNCHRONIZING;
		this->jops->synchronize(this);
	}
	return ret;
}

struct journal_operations default_jops = {
	.load		= journal_buffer_load,
	.should_recover = journal_should_recover,
	.recover	= journal_recover,
	.should_sync	= journal_should_sync,
	.synchronize	= journal_synchronize,
	.add_record	= journal_add_record,
	.get_block	= journal_get_block,
	.encrypt_block	= journal_encrypt_block,
	.decrypt_block	= journal_decrypt_block,
};

void nop_buffer_load(struct journal_region *this, uint64_t record_start,
		     uint64_t record_end)
{
}
bool nop_should_recover(struct journal_region *this)
{
	return false;
}
void nop_recover(struct journal_region *this)
{
}
bool nop_should_sync(struct journal_region *this)
{
	return false;
}
void nop_synchronize(struct journal_region *this)
{
}
uint64_t nop_add_record(struct journal_region *this, struct journal_record *record)
{
	return 0;
}
struct journal_block * nop_get_block(struct journal_region *this, uint64_t blk_num)
{
	return NULL;
}
void nop_encrypt_block(struct journal_region *this, uint64_t blk_num,
		       struct journal_block *buffer)
{
}
void nop_decrypt_block(struct journal_region *this, uint64_t blk_num)
{
}

struct journal_operations nop_jops = {
	.load		= nop_buffer_load,
	.should_recover = nop_should_recover,
	.recover	= nop_recover,
	.should_sync	= nop_should_sync,
	.synchronize	= nop_synchronize,
	.add_record	= nop_add_record,
	.get_block	= nop_get_block,
	.encrypt_block	= nop_encrypt_block,
	.decrypt_block	= nop_decrypt_block,
};

int journal_region_init(struct journal_region *this, struct superblock *superblock)
{
#if ENABLE_JOURNAL
	struct journal_record j_record;
	this->status = JOURNAL_UNINITIALIZED;
	this->superblock = superblock;
	this->jops = &default_jops;
	this->record_start = superblock->record_start;
	this->record_end = superblock->record_end;
	mutex_init(&this->sync_lock);
	init_rwsem(&this->valid_fields_lock);
	this->cipher = aes_gcm_cipher_create();
	if (!this->cipher) {
		DMERR("journal_region could not create cipher\n");
		return -EAGAIN;
	}

	this->buffer.blocks = kzalloc(BLOCKS_PER_SEGMENT * sizeof(struct journal_block),
				      GFP_KERNEL);
	if (!this->buffer.blocks) {
		DMERR("journal_region kzalloc buffer failed\n");
		return -ENOMEM;
	}

	if (this->record_start != this->record_end)
		this->jops->load(this, this->record_start, this->record_end);
	else {
		this->buffer.segno = this->record_start / RECORDS_PER_SEGMENT;

		j_record.type = CHECKPOINT_PACK;
		this->jops->add_record(this, &j_record);
		this->last_sync_record = this->record_start;
		this->status = JOURNAL_LOADED;
	}

	if (this->status == JOURNAL_LOADED && this->jops->should_recover(this))
		this->jops->recover(this);

	if (this->status == JOURNAL_READY)
		return 0;

	return -EAGAIN;
#else
	this->jops = &nop_jops;
	return 0;
#endif
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
	if (!this)
		return;
#if ENABLE_JOURNAL
	this->jops->synchronize(this);
	mutex_destroy(&this->sync_lock);
	if (this->cipher)
		this->cipher->destroy(this->cipher);

	if (this->buffer.blocks)
		kfree(this->buffer.blocks);
#endif
	kfree(this);
}
