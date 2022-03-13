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

struct bio_async_io_context {
	sector_t pba;
	struct bio* bio;
	struct bio* origin;
	struct memtable* mt;
	struct bvec_iter bi_iter;
	struct work_struct work;
	struct work_struct complete;
	struct workqueue_struct* wq;
	struct generic_cache* cache;
	struct bio_crypt_context* crypt_ctx;
};

unsigned int bio_get_sector(struct bio *bio);
void bio_set_sector(struct bio *bio, unsigned int sector);
unsigned int bio_get_data_len(struct bio* bio);
void bio_set_data_len(struct bio* bio, unsigned int len);
void crypt_bio_endio(struct bio* bio);
struct bio* bio_deepcopy(struct bio* src, struct bio_set* bs);
struct bio_crypt_context* bio_crypt_context_create(sector_t lba, char* key, 
  char* iv, char* mac, struct aead_cipher* cipher);
struct bio_async_io_context* bio_async_io_context_create(struct bio* bio, 
  struct bio* origin, struct memtable* mt, struct generic_cache* cache, struct bio_crypt_context* crypt_ctx);
struct bio* bio_copy(struct bio* src, gfp_t mask, struct bio_set* bs);
char* bio_data_buffer_copy(struct bio* bio);
int bio_fill_data_buffer(struct bio* bio, char* buffer, size_t len);
void bio_async_io_context_destroy(struct bio_async_io_context* ctx);
void bio_crypt_context_destroy(struct bio_crypt_context* ctx);

#endif