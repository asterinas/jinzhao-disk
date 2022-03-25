#ifndef DM_SWORNDISK_BIO_OPERATE_H
#define DM_SWORNDISK_BIO_OPERATE_H

#include <linux/bio.h>

#include "../include/crypto.h"
#include "../include/memtable.h"
#include "../include/generic_cache.h"

#define BIO_CRYPT_SECTOR_LIMIT 1


struct bio_crypt_context {
	sector_t lba;
	char* key;
	char* iv;
	char* mac;
	struct aead_cipher* cipher;
};

unsigned int bio_get_sector(struct bio *bio);
void bio_set_sector(struct bio *bio, unsigned int sector);
unsigned int bio_get_data_len(struct bio* bio);
void bio_set_data_len(struct bio* bio, unsigned int len);
void bio_get_data(struct bio* bio, char* buffer);
int bio_set_data(struct bio* bio, char* buffer, size_t len);
char* bio_data_copy(struct bio* bio);
int bio_fill_pages(struct bio* bio, struct page* pages, size_t nr_segment);

#endif