/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include <linux/random.h>
#include <linux/rwsem.h>

#include "../include/crypto.h"
#include "../include/dm_jindisk.h"

void btox(char *xp, const char *bb, int n)
{
	const char xx[] = "0123456789ABCDEF";

	while (--n >= 0)
		xp[n] = xx[(bb[n >> 1] >> ((1 - (n & 1)) << 2)) & 0xF];
}

int aes_gcm_cipher_encrypt(struct aead_cipher *ac, char *data, int len,
			   char *key, char *iv, char *mac, uint64_t seq,
			   char *out)
{
	int r;
	char *riv;
	struct aead_request *req;
	char zero_iv[AES_GCM_IV_SIZE] = { 0 };
	struct scatterlist sg_in[AEAD_MSG_NR_PART], sg_out[AEAD_MSG_NR_PART];
	DECLARE_CRYPTO_WAIT(wait);
	struct aes_gcm_cipher *this =
		container_of(ac, struct aes_gcm_cipher, aead_cipher);
#if defined(DEBUG)
	char mac_hex[(AES_GCM_AUTH_SIZE << 1) + 1] = { 0 };
	char key_hex[(AES_GCM_KEY_SIZE << 1) + 1] = { 0 };
	char iv_hex[(AES_GCM_IV_SIZE << 1) + 1] = { 0 };
#endif
	if (iv)
		riv = iv;
	else
		riv = zero_iv;

	sg_init_table(sg_in, AEAD_MSG_NR_PART);
	sg_set_buf(&sg_in[0], &seq, sizeof(uint64_t));
	sg_set_buf(&sg_in[1], riv, this->iv_size);
	sg_set_buf(&sg_in[2], data, len);
	sg_set_buf(&sg_in[3], mac, this->auth_size);

	sg_init_table(sg_out, AEAD_MSG_NR_PART);
	sg_set_buf(&sg_out[0], &seq, sizeof(uint64_t));
	sg_set_buf(&sg_out[1], riv, this->iv_size);
	sg_set_buf(&sg_out[2], out, len);
	sg_set_buf(&sg_out[3], mac, this->auth_size);

	r = mutex_lock_interruptible(&this->lock);
	if (r)
		goto exit;

	crypto_aead_setauthsize(this->tfm, this->auth_size);
	req = aead_request_alloc(this->tfm, GFP_KERNEL);
	if (!req) {
		DMERR("could not allocate aead request");
		goto exit;
	}

	aead_request_set_crypt(req, sg_in, sg_out, len, riv);
	aead_request_set_ad(req, sizeof(uint64_t) + this->iv_size);

	r = crypto_aead_setkey(this->tfm, key, this->key_size);
	if (r) {
		DMERR("gcm(aes) key could not be set");
		goto exit;
	}

	aead_request_set_callback(
		req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);
	r = crypto_wait_req(crypto_aead_encrypt(req), &wait);
	if (r) {
		DMERR("gcm(aes) encrypt error");
		goto exit;
	}
exit:
	if (req)
		aead_request_free(req);
#if defined(DEBUG)
	btox(key_hex, key, AES_GCM_KEY_SIZE << 1);
	btox(iv_hex, riv, AES_GCM_IV_SIZE << 1);
	btox(mac_hex, mac, AES_GCM_AUTH_SIZE << 1);
	DMDEBUG("gcm(aes) encrypted, key:%s, iv:%s, mac:%s, seq:%llu, len:%u",
		key_hex, iv_hex, mac_hex, seq, len);
#endif
	mutex_unlock(&this->lock);
	return r;
}

int aes_gcm_cipher_decrypt(struct aead_cipher *ac, char *data, int len,
			   char *key, char *iv, char *mac, uint64_t seq,
			   char *out)
{
	int r = 0;
	char *riv;
	struct aead_request *req;
	char zero_iv[AES_GCM_IV_SIZE] = { 0 };
	char mac_hex[(AES_GCM_AUTH_SIZE << 1) + 1] = { 0 };
	char key_hex[(AES_GCM_KEY_SIZE << 1) + 1] = { 0 };
	char iv_hex[(AES_GCM_IV_SIZE << 1) + 1] = { 0 };
	struct scatterlist sg_in[AEAD_MSG_NR_PART], sg_out[AEAD_MSG_NR_PART];
	DECLARE_CRYPTO_WAIT(wait);
	struct aes_gcm_cipher *this =
		container_of(ac, struct aes_gcm_cipher, aead_cipher);
	if (iv)
		riv = iv;
	else
		riv = zero_iv;

	sg_init_table(sg_in, AEAD_MSG_NR_PART);
	sg_set_buf(&sg_in[0], &seq, sizeof(uint64_t));
	sg_set_buf(&sg_in[1], riv, this->iv_size);
	sg_set_buf(&sg_in[2], data, len);
	sg_set_buf(&sg_in[3], mac, this->auth_size);

	sg_init_table(sg_out, AEAD_MSG_NR_PART);
	sg_set_buf(&sg_out[0], &seq, sizeof(uint64_t));
	sg_set_buf(&sg_out[1], riv, this->iv_size);
	sg_set_buf(&sg_out[2], out, len);
	sg_set_buf(&sg_out[3], mac, this->auth_size);

	r = mutex_lock_interruptible(&this->lock);
	if (r)
		goto exit;

	crypto_aead_setauthsize(this->tfm, this->auth_size);
	req = aead_request_alloc(this->tfm, GFP_KERNEL);
	if (!req) {
		DMERR("could not allocate aead request");
		goto exit;
	}

	aead_request_set_crypt(req, sg_in, sg_out, len + this->auth_size, riv);
	aead_request_set_ad(req, sizeof(uint64_t) + this->iv_size);

	r = crypto_aead_setkey(this->tfm, key, this->key_size);
	if (r) {
		DMERR("gcm(aes) key could not be set");
		goto exit;
	}

	aead_request_set_callback(
		req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
		crypto_req_done, &wait);
	r = crypto_wait_req(crypto_aead_decrypt(req), &wait);
	if (r == -EBADMSG) {
		btox(key_hex, key, AES_GCM_KEY_SIZE << 1);
		btox(iv_hex, riv, AES_GCM_IV_SIZE << 1);
		btox(mac_hex, mac, AES_GCM_AUTH_SIZE << 1);
		DMWARN("gcm(aes) authentication failed, key:%s, iv:%s, mac:%s, "
		       "seq:%llu",
		       key_hex, iv_hex, mac_hex, seq);
		goto exit;
	} else if (r) {
		DMERR("gcm(aes) decryption error");
		goto exit;
	}
#if defined(DEBUG)
	btox(key_hex, key, AES_GCM_KEY_SIZE << 1);
	btox(iv_hex, riv, AES_GCM_IV_SIZE << 1);
	btox(mac_hex, mac, AES_GCM_AUTH_SIZE << 1);
	DMDEBUG("gcm(aes) decrypted, key:%s, iv:%s, mac:%s, seq:%llu, len:%u",
		key_hex, iv_hex, mac_hex, seq, len);
#endif
exit:
	if (req)
		aead_request_free(req);

	mutex_unlock(&this->lock);
	return r;
}

void aes_gcm_cipher_destroy(struct aead_cipher *ac)
{
	struct aes_gcm_cipher *this =
		container_of(ac, struct aes_gcm_cipher, aead_cipher);
	crypto_free_aead(this->tfm);
	kfree(this);
}

int aes_gcm_cipher_init(struct aes_gcm_cipher *this)
{
	this->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(this->tfm)) {
		DMERR("could not allocate aead handler");
		return -ENOMEM;
	}

	mutex_init(&this->lock);
	this->block_size = crypto_aead_blocksize(this->tfm);
	this->auth_size = crypto_aead_authsize(this->tfm);
	this->iv_size = crypto_aead_ivsize(this->tfm);
	this->key_size = AES_GCM_KEY_SIZE;

	this->aead_cipher.encrypt = aes_gcm_cipher_encrypt;
	this->aead_cipher.decrypt = aes_gcm_cipher_decrypt;
	this->aead_cipher.destroy = aes_gcm_cipher_destroy;
	return 0;
}

struct aead_cipher *aes_gcm_cipher_create()
{
	int err = 0;
	struct aes_gcm_cipher *this;

	this = kmalloc(sizeof(struct aes_gcm_cipher), GFP_KERNEL);
	if (!this)
		goto bad;

	err = aes_gcm_cipher_init(this);
	if (err)
		goto bad;

	return &this->aead_cipher;
bad:
	if (this)
		kfree(this);
	return NULL;
}

/*
 * This function could be strengthened by some keyed
 * cryptographic hash function.
 */
static int generate_iv(uint64_t seed, char *iv, int len)
{
	u32 *p = (u32 *)iv;
	int round = len / sizeof(u32);

	memset(iv, 0, len);
	while (round--)
		*(p++) = crc32_be(seed, iv, len);

	return 0;
}

/*
 * __aes_cbc_cipher_helper - perform cbc(aes) encrypt/decrypt operation
 * @sc: the pointer of skcipher object
 * @op: operation code, e.g., AES_CBC_ENCRYPT/AES_CBC_DECRYPT
 * @src: source buffer
 * @len: length of the src in bytes, no more than 4096
 * @key: symmetric key for the operation
 * @iv: IV for the cipher operation, if NULL, use generate_iv() to obtain
 *  an IV according to the seq parameter
 * @seq: seed for IV generation, maybe unuse
 * @dst: destination buffer
 *
 * This function assumes that all the pointer is valid, and will not cause
 * illegal memory access.
 *
 * Return: 0 if the operation successed; < 0 if failed
 */
int __aes_cbc_cipher_helper(struct skcipher *sc, int op, char *src, int len,
			    char *key, char *iv, uint64_t seq, char *dst)
{
	struct aes_cbc_cipher *this =
		container_of(sc, struct aes_cbc_cipher, skcipher);
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist src_sg, dst_sg;
	char riv[AES_CBC_IV_SIZE] = { 0 };
	int r = 0;

	if (len <= 0 || len > BLOCK_SIZE)
		return -EINVAL;

	/* Align len to AES_CBC_BLOCK_SIZE */
	if ((len & AES_CBC_BLOCK_MASK) != 0)
		len = ((len | AES_CBC_BLOCK_MASK) ^ AES_CBC_BLOCK_MASK) + 1;

	if (iv == NULL) {
		r = generate_iv(seq, riv, AES_CBC_IV_SIZE);
		if (r < 0)
			goto exit;
	} else {
		/* The cbc(aes) will modify iv in-place, so copy it */
		memcpy(riv, iv, AES_CBC_IV_SIZE);
	}

	r = mutex_lock_interruptible(&this->lock);
	if (r < 0)
		goto exit;

	r = crypto_skcipher_setkey(this->tfm, key, AES_CBC_KEY_SIZE);
	if (r < 0)
		goto unlock_exit;

	sg_init_one(&src_sg, src, len);
	sg_init_one(&dst_sg, dst, len);
	skcipher_request_set_callback(this->req,
				      CRYPTO_TFM_REQ_MAY_BACKLOG |
					      CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(this->req, &src_sg, &dst_sg, len, riv);

	switch (op) {
	case AES_CBC_ENCRYPT:
		r = crypto_wait_req(crypto_skcipher_encrypt(this->req), &wait);
		if (r < 0)
			DMERR("cbc(aes) encryption failed");
		break;
	case AES_CBC_DECRYPT:
		r = crypto_wait_req(crypto_skcipher_decrypt(this->req), &wait);
		if (r < 0)
			DMERR("cbc(aes) decryption failed");
		break;
	default:
		DMERR("cbc(aes) handler: unsupported operation");
		break;
	}
unlock_exit:
	mutex_unlock(&this->lock);
exit:
	return r;
}

int aes_cbc_cipher_encrypt(struct skcipher *sc, char *data, int len, char *key,
			   char *iv, uint64_t seq, char *out)
{
	return __aes_cbc_cipher_helper(sc, AES_CBC_ENCRYPT, data, len, key, iv,
				       seq, out);
}

int aes_cbc_cipher_decrypt(struct skcipher *sc, char *data, int len, char *key,
			   char *iv, uint64_t seq, char *out)
{
	return __aes_cbc_cipher_helper(sc, AES_CBC_DECRYPT, data, len, key, iv,
				       seq, out);
}

void aes_cbc_cipher_destroy(struct skcipher *sc)
{
	struct aes_cbc_cipher *this =
		container_of(sc, struct aes_cbc_cipher, skcipher);

	crypto_free_skcipher(this->tfm);
	skcipher_request_free(this->req);
	kfree(this);
}

int aes_cbc_cipher_init(struct aes_cbc_cipher *this)
{
	int r = 0;

	this->tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(this->tfm)) {
		DMERR("could not allocate cbc(aes) handler");
		r = -EAGAIN;
		goto err;
	}
	this->req = skcipher_request_alloc(this->tfm, GFP_KERNEL);
	if (!this->req) {
		DMERR("could not allocate request for cbc(aes)");
		r = -ENOMEM;
		goto err;
	}

	mutex_init(&this->lock);
	this->block_size = crypto_skcipher_blocksize(this->tfm);
	this->iv_size = crypto_skcipher_ivsize(this->tfm);
	this->key_size = AES_CBC_KEY_SIZE;

	this->skcipher.encrypt = aes_cbc_cipher_encrypt;
	this->skcipher.decrypt = aes_cbc_cipher_decrypt;
	this->skcipher.destroy = aes_cbc_cipher_destroy;
	return 0;
err:
	crypto_free_skcipher(this->tfm);
	return r;
}

struct skcipher *aes_cbc_cipher_create(void)
{
	int r = 0;
	struct aes_cbc_cipher *this;

	this = kmalloc(sizeof(struct aes_cbc_cipher), GFP_KERNEL);
	if (!this)
		goto err;

	r = aes_cbc_cipher_init(this);
	if (r)
		goto err;

	return &this->skcipher;
err:
	if (this)
		kfree(this);
	return NULL;
}
