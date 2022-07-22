#ifndef DM_SWORNDISK_JOURNAL_H
#define DM_SWORNDISK_JOURNAL_H

#include <crypto/skcipher.h>
#include <linux/crc32.h>
#include "segment_buffer.h"
#include "metadata.h"

#define JOURNAL_BLOCK_SIZE 4096
#define RECORDS_PER_BLOCK ((JOURNAL_BLOCK_SIZE - 2 * sizeof(struct crypto_info)) \
				/ sizeof(struct journal_record))
#define RECORDS_PER_SEGMENT (RECORDS_PER_BLOCK * BLOCKS_PER_SEGMENT)
#define NR_JOURNAL_SEGMENT 16
#define MAX_BLOCKS (BLOCKS_PER_SEGMENT * NR_JOURNAL_SEGMENT)
#define MAX_RECORDS (MAX_BLOCKS * RECORDS_PER_BLOCK)
#define BLOCK_CRYPT_LEN (sizeof(struct crypto_info) + RECORDS_PER_BLOCK \
			 * sizeof(struct journal_record))
#define SYNC_BLKNUM_THRESHOLD BLOCKS_PER_SEGMENT

enum record_type {
	DATA_LOG,
	DATA_COMMIT,
	BIT_COMPACTION,
	BIT_NODE,
	CHECKPOINT_PACK,
};

enum journal_status {
	JOURNAL_UNINITIALIZED,
	JOURNAL_LOADED,
	JOURNAL_RECOVERING,
	JOURNAL_READY,
	JOURNAL_SYNCHRONIZING,
};

struct data_log_record {
	uint64_t timestamp;
	uint64_t lba,hba;
	char key[AES_GCM_KEY_SIZE];
	char mac[AES_GCM_AUTH_SIZE];
	char iv[AES_GCM_IV_SIZE];
};

struct data_commit_record {
	uint64_t timestamp;
};

struct bit_compaction_record {};

struct bit_node_record {};

struct checkpoint_pack_record {};

struct journal_record {
	enum record_type	type;
	union {
		struct data_log_record		data_log;
		struct data_commit_record	data_commit;
		struct bit_compaction_record	bit_compaction;
		struct bit_node_record		bit_node;
		struct checkpoint_pack_record	checkpoint_pack;
	};
}__attribute__((aligned(64)));

struct crypto_info {
	char mac[AES_GCM_AUTH_SIZE];
	char iv[AES_GCM_IV_SIZE];
}__attribute__((aligned(32)));

struct journal_block {
	struct crypto_info previous_blk;
	struct journal_record records[RECORDS_PER_BLOCK];
	struct crypto_info current_blk;
}__attribute__((aligned(JOURNAL_BLOCK_SIZE)));

struct journal_operations;

struct journal_region {
	struct journal_block **blocks;
	struct superblock *superblock;
	struct journal_operations *jops;
	struct aead_cipher *cipher;
	uint64_t record_start;
	uint64_t record_end;
	// sync_lock protects last_sync_blk
	struct mutex sync_lock;
	uint64_t last_sync_blk;
	enum journal_status status;
};

struct journal_operations {
	void (*load)(struct journal_region *this);
	bool (*should_recover)(struct journal_region *this);
	void (*recover)(struct journal_region *this);
	bool (*should_sync)(struct journal_region *this);
	void (*synchronize)(struct journal_region *this);
	void (*add_record)(struct journal_region *this, struct journal_record *record);
	struct journal_block *(*get_block)(struct journal_region *this,
					   uint64_t blk_num);
	void (*encrypt_block)(struct journal_region *this, uint64_t blk_num,
			      struct journal_block *buffer);
	void (*decrypt_block)(struct journal_region *this, uint64_t blk_num,
			      struct journal_block *buffer);
};

#endif
