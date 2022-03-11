#ifndef DM_SWORNDISK_BIO_OPERATE_H
#define DM_SWORNDISK_BIO_OPERATE_H

#include <linux/bio.h>

#include "../include/crypto.h"

#define BIO_CRYPT_SECTOR_LIMIT 1


struct bio_crypt_context {
    sector_t lba;
    char* key;
    char* iv;
    char* mac;
    struct bio* origin;
    struct bvec_iter bi_iter;
    struct aead_cipher* cipher;
};

typedef struct bio_crypt_context async_bio_write_context; 

unsigned int bio_get_sector(struct bio *bio);
void bio_set_sector(struct bio *bio, unsigned int sector);
unsigned int bio_get_data_len(struct bio* bio);
void bio_set_data_len(struct bio* bio, unsigned int len);
void crypt_bio_endio(struct bio* bio);
struct bio* bio_deepcopy(struct bio* src, struct bio_set* bs);
void bio_crypt_context_init(struct bio_crypt_context* ctx, sector_t lba, char* key, 
    char* iv, char* mac, struct bio* origin, struct aead_cipher* cipher);
struct bio_crypt_context* bio_crypt_context_create(sector_t lba, char* key, 
  char* iv, char* mac, struct bio* origin, struct aead_cipher* cipher);
struct bio* bio_copy(struct bio* src, gfp_t mask, struct bio_set* bs);

#endif