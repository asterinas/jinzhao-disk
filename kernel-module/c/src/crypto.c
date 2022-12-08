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
