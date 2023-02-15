/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef DM_JINDISK_CRYPTO_H
#define DM_JINDISK_CRYPTO_H

#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <linux/crc32.h>
#include <linux/scatterlist.h>

// in bytes
#define AES_GCM_KEY_SIZE 16
#define AES_GCM_BLOCK_SIZE 1
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16

#define RFC_AES_GCM_KEY_SIZE 20
#define RFC_AES_GCM_IV_SIZE 8
#define RFC_AES_GCM_BLOCK_SIZE 1
#define RFC_AES_GCM_AUTH_SIZE 16

#define AEAD_MSG_NR_PART 4

struct aead_cipher {
	int (*encrypt)(struct aead_cipher *ac, char *data, int len, char *key,
		       char *iv, char *mac, uint64_t seq, char *out);
	int (*decrypt)(struct aead_cipher *ac, char *data, int len, char *key,
		       char *iv, char *mac, uint64_t seq, char *out);
	void (*destroy)(struct aead_cipher *ac);
};

/*
	name         : gcm(aes)
	driver       : generic-gcm-aesni
	module       : aesni_intel
	priority     : 400
	refcnt       : 1
	selftest     : passed
	internal     : no
	type         : aead
	async        : yes
	blocksize    : 1
	ivsize       : 12
	maxauthsize  : 16
	geniv        : <none>
*/
/* AEAD request:
 *  |----- AAD -------|------ DATA -------|-- AUTH TAG --|
 *  | (authenticated) | (auth+encryption) |              |
 *  | sector_LE |  IV |  sector in/out    |  tag in/out  |
 */

struct aes_gcm_cipher {
	struct aead_cipher aead_cipher;
	struct crypto_aead *tfm;
	size_t key_size;
	size_t block_size;
	size_t auth_size;
	size_t iv_size;
	struct mutex lock;
};

/*
 * name         : cbc(aes)
 * driver       : cbc-aes-aesni
 * module       : aesni_intel
 * priority     : 400
 * refcnt       : 1
 * selftest     : passed
 * internal     : no
 * type         : skcipher
 * async        : yes
 * blocksize    : 16
 * min keysize  : 16
 * max keysize  : 32
 * ivsize       : 16
 * chunksize    : 16
 * walksize     : 16
 */

#define AES_CBC_ENCRYPT 0
#define AES_CBC_DECRYPT 1
#define AES_CBC_BLOCK_SIZE 16
#define AES_CBC_BLOCK_MASK (AES_CBC_BLOCK_SIZE - 1)
#define AES_CBC_KEY_SIZE 16
#define AES_CBC_IV_SIZE 16

struct skcipher {
	int (*encrypt)(struct skcipher *sc, char *data, int len, char *key,
		       char *iv, uint64_t seq, char *out);
	int (*decrypt)(struct skcipher *sc, char *data, int len, char *key,
		       char *iv, uint64_t seq, char *out);
	void (*destroy)(struct skcipher *sc);
};

struct aes_cbc_cipher {
	struct skcipher skcipher;
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	size_t block_size;
	size_t key_size;
	size_t iv_size;
	struct mutex lock;
};

struct aead_cipher *aes_gcm_cipher_create(void);
struct skcipher *aes_cbc_cipher_create(void);

#endif
