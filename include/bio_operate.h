#ifndef DM_SWORNDISK_BIO_OPERATE_H
#define DM_SWORNDISK_BIO_OPERATE_H

#include <linux/bio.h>

#include "../include/crypto.h"
#include "../include/memtable.h"
#include "../include/segment_allocator.h"

struct bio_crypt_context {
	sector_t lba;
	char* key;
	char* iv;
	char* mac;
	struct aead_cipher* cipher;
};

unsigned int bio_get_sector(struct bio *bio);
void bio_set_sector(struct bio *bio, unsigned int sector);
size_t bio_get_data_len(struct bio* bio);
void bio_set_data_len(struct bio* bio, unsigned int len);
dm_block_t bio_get_block_address(struct bio* bio);
sector_t bio_block_sector_offset(struct bio* bio);
void bio_get_data(struct bio* bio, char* buffer, size_t len);
void bio_set_data(struct bio* bio, char* buffer, size_t len);

#endif