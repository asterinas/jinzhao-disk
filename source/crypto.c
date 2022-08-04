#include <linux/random.h>
#include <linux/delay.h>
#include <linux/semaphore.h>

#include "../include/dm_sworndisk.h"
#include "../include/crypto.h"
#include "../include/segment_buffer.h"

int __get_random_bytes(char** p_data, unsigned int len) {
    *p_data = kzalloc(len+1, GFP_KERNEL);
    if (!(*p_data)) {
        DMERR("get random bytes alloc mem error\n");
        return -ENOMEM;
    }
    get_random_bytes(*p_data, len);
    return 0;
}

int aes_gcm_get_random_key(char** p_key, int key_len) {
    return __get_random_bytes(p_key, key_len);
}

int aes_gcm_get_random_iv(char** p_iv, int iv_len) {
    return __get_random_bytes(p_iv, iv_len);
}

int aes_gcm_cipher_encrypt(struct aead_cipher *ac, char* data, int len, char* key, char* iv, char* mac, uint64_t seq, char* out) {
    int r;
    struct aead_request* req;
    struct scatterlist sg_in[AEAD_MSG_NR_PART], sg_out[AEAD_MSG_NR_PART];
    DECLARE_CRYPTO_WAIT(wait);
    struct aes_gcm_cipher* this = container_of(ac, struct aes_gcm_cipher, aead_cipher);

    sg_init_table(sg_in, AEAD_MSG_NR_PART);
    sg_set_buf(&sg_in[0], &seq, sizeof(uint64_t));
    sg_set_buf(&sg_in[1], iv, this->iv_size);
    sg_set_buf(&sg_in[2], data, len);
    sg_set_buf(&sg_in[3], mac, this->auth_size);

    sg_init_table(sg_out, AEAD_MSG_NR_PART);
    sg_set_buf(&sg_out[0], &seq, sizeof(uint64_t));
    sg_set_buf(&sg_out[1], iv, this->iv_size);
    sg_set_buf(&sg_out[2], out, len);
    sg_set_buf(&sg_out[3], mac, this->auth_size);

    r = mutex_lock_interruptible(&this->lock);
    if (r)
        goto exit;
    
    crypto_aead_setauthsize(this->tfm, this->auth_size);
    req = aead_request_alloc(this->tfm, GFP_KERNEL);
    if (!req) {
        DMERR("could not allocate aead request\n");
        goto exit;
    }
    
    aead_request_set_crypt(req, sg_in, sg_out, len, iv);
    aead_request_set_ad(req, sizeof(uint64_t) + this->iv_size);

    r = crypto_aead_setkey(this->tfm, key, this->key_size);
    if (r) {
        DMERR("gcm(aes) key could not be set\n");
        goto exit;
    }

    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
    r = crypto_wait_req(crypto_aead_encrypt(req), &wait);
    if (r)  {
        DMERR("gcm(aes) encrypt error");
        goto exit;
    }

exit:
    if (req)
        aead_request_free(req);
    mutex_unlock(&this->lock);
    return r;
}

int aes_gcm_cipher_decrypt(struct aead_cipher *ac, char* data, int len, char* key, char* iv, char* mac, uint64_t seq, char* out) {
    int r = 0;
    uint32_t checksum = 0;
    struct aead_request* req;
    struct scatterlist sg_in[AEAD_MSG_NR_PART], sg_out[AEAD_MSG_NR_PART];
    DECLARE_CRYPTO_WAIT(wait);
    struct aes_gcm_cipher* this = container_of(ac, struct aes_gcm_cipher, aead_cipher);

#ifdef DEBUG_CRYPT
    checksum = dm_bm_checksum(data, len, 0);
#endif

    sg_init_table(sg_in, AEAD_MSG_NR_PART);
    sg_set_buf(&sg_in[0], &seq, sizeof(uint64_t));
    sg_set_buf(&sg_in[1], iv, this->iv_size);
    sg_set_buf(&sg_in[2], data, len);
    sg_set_buf(&sg_in[3], mac, this->auth_size);

    sg_init_table(sg_out, AEAD_MSG_NR_PART);
    sg_set_buf(&sg_out[0], &seq, sizeof(uint64_t));
    sg_set_buf(&sg_out[1], iv, this->iv_size);
    sg_set_buf(&sg_out[2], out, len);
    sg_set_buf(&sg_out[3], mac, this->auth_size);

    r = mutex_lock_interruptible(&this->lock);
    if (r)
        goto exit;

    crypto_aead_setauthsize(this->tfm, this->auth_size);
    req = aead_request_alloc(this->tfm, GFP_KERNEL);
    if (!req) {
        DMERR("could not allocate aead request\n");
        goto exit;
    }

    aead_request_set_crypt(req, sg_in, sg_out, len + this->auth_size, iv);
    aead_request_set_ad(req, sizeof(uint64_t) + this->iv_size);

    r = crypto_aead_setkey(this->tfm, key, this->key_size);
    if (r) {
        DMERR("gcm(aes) key could not be set\n");
        goto exit;
    }

    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
    r = crypto_wait_req(crypto_aead_decrypt(req), &wait);
    if (r == -EBADMSG) {
        char mac_hex[(AES_GCM_AUTH_SIZE << 1) + 1] = {0};
        char key_hex[(AES_GCM_KEY_SIZE << 1) + 1] = {0};
        char iv_hex[(AES_GCM_IV_SIZE << 1) + 1] = {0};

        btox(key_hex, key, AES_GCM_KEY_SIZE << 1);
        btox(iv_hex, iv, AES_GCM_IV_SIZE << 1);
        btox(mac_hex, mac, AES_GCM_AUTH_SIZE << 1);
        DMWARN("gcm(aes) authentication failed, key: %s, iv: %s, mac: %s, seq: %llu, checksum: %u", 
            key_hex, iv_hex, mac_hex, seq, checksum);
        goto exit;
    } else if (r) {
        DMERR("gcm(aes) decryption error\n");
        goto exit;
	}

exit:
    if (req)
        aead_request_free(req);
    mutex_unlock(&this->lock);
    return r;
}

void aes_gcm_cipher_destroy(struct aead_cipher* ac) {
    struct aes_gcm_cipher* this = container_of(ac, struct aes_gcm_cipher, aead_cipher);
    
    crypto_free_aead(this->tfm);
    kfree(this);
}

int aes_gcm_cipher_init(struct aes_gcm_cipher *this) {
    this->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(this->tfm)) {
        DMERR("could not allocate aead handler\n");
        return -ENOMEM;
    }

    mutex_init(&this->lock);
    this->block_size = crypto_aead_blocksize(this->tfm);
    this->auth_size = crypto_aead_authsize(this->tfm);
    this->iv_size = crypto_aead_ivsize(this->tfm);
    this->key_size = AES_GCM_KEY_SIZE;

    this->aead_cipher.get_random_key = aes_gcm_get_random_key;
    this->aead_cipher.get_random_iv = aes_gcm_get_random_iv;
    this->aead_cipher.encrypt = aes_gcm_cipher_encrypt;
    this->aead_cipher.decrypt = aes_gcm_cipher_decrypt;
    this->aead_cipher.destroy = aes_gcm_cipher_destroy;
    return 0;
}

struct aead_cipher* aes_gcm_cipher_create() {
    int err = 0;
    struct aes_gcm_cipher* this;

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
