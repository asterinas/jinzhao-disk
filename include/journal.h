#ifndef DM_SWORNDISK_JOURNAL_H
#define DM_SWORNDISK_JOURNAL_H

#include "segment_buffer.h"
#include "metadata.h"

#define JOURNAL_PER_SEGMENT (SEGMENT_BUFFER_SIZE / sizeof(struct journal_record))
#define NR_JOURNAL_SEGMENT 16

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
	uint64_t data_seg_id;
	uint64_t timestamp;
	uint64_t lba,hba;
	char key[AES_GCM_KEY_SIZE];
	char mac[AES_GCM_AUTH_SIZE];
	char iv[AES_GCM_IV_SIZE];
};

struct data_commit_record {};

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
	uint64_t		hmac;
}__attribute__((aligned(64)));

struct journal_operations;

struct journal_region {
	struct journal_record **records;
	struct superblock *superblock;
	struct journal_operations *jops;
	uint64_t record_start;
	uint64_t record_end;
	uint64_t record_max;
	int last_sync_segnum;
	enum journal_status status;
};

struct journal_operations {
	void (*load)(struct journal_region *this);
	bool (*should_recover)(struct journal_region *this);
	void (*recover)(struct journal_region *this);
	void (*synchronize)(struct journal_region *this, int segnum);
	void (*add_record)(struct journal_region *this, struct journal_record *record);
};

#endif
