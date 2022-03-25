#include <linux/random.h>

#include "../include/dm_sworndisk.h"
#include "../include/crypto.h"

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

int aes_gcm_cipher_encrypt(struct aead_cipher *ac, char* data, int len, char* key, int key_len, char* iv, char* mac, int mac_len, uint64_t seq) {
    int r;
    struct aead_request* req;
    struct scatterlist sg[AEAD_MSG_NR_PART];
    struct aes_gcm_cipher* ag = container_of(ac, struct aes_gcm_cipher, interface);

    req = aead_request_alloc(ag->tfm, GFP_KERNEL);
    if (!req) {
        DMERR("could not allocate aead request\n");
        goto exit;
    }
    sg_init_table(sg, AEAD_MSG_NR_PART);
    sg_set_buf(&sg[0], &seq, sizeof(uint64_t));
    sg_set_buf(&sg[1], iv, AES_GCM_IV_SIZE);
    sg_set_buf(&sg[2], data, len);
    sg_set_buf(&sg[3], mac, mac_len);
    
    aead_request_set_crypt(req, sg, sg, len, iv);
    aead_request_set_ad(req, sizeof(uint64_t)+AES_GCM_IV_SIZE);

    r = crypto_aead_setkey(ag->tfm, key, key_len);
    if (r) {
        DMERR("gcm(aes) key could not be set\n");
        goto exit;
    }
    r = crypto_aead_encrypt(req);
    if (r)  {
        DMERR("gcm(aes) encrypt error");
        goto exit;
    }
exit:
    if (req)
        aead_request_free(req);
    return r;
}

int aes_gcm_cipher_decrypt(struct aead_cipher *ac, char* data, int len, char* key, int key_len, char* iv, char* mac, int mac_len, uint64_t seq) {
    int r;
    struct aead_request* req;
    struct scatterlist sg[AEAD_MSG_NR_PART];
    struct aes_gcm_cipher* ag = container_of(ac, struct aes_gcm_cipher, interface);

    req = aead_request_alloc(ag->tfm, GFP_KERNEL);
    if (!req) {
        DMERR("could not allocate aead request\n");
        goto exit;
    }
    sg_init_table(sg, AEAD_MSG_NR_PART);
    sg_set_buf(&sg[0], &seq, sizeof(uint64_t));
    sg_set_buf(&sg[1], iv, AES_GCM_IV_SIZE);
    sg_set_buf(&sg[2], data, len);
    sg_set_buf(&sg[3], mac, mac_len);

    aead_request_set_crypt(req, sg, sg, len+mac_len, iv);
    aead_request_set_ad(req, sizeof(uint64_t)+AES_GCM_IV_SIZE);

    r = crypto_aead_setkey(ag->tfm, key, key_len);
    if (r) {
        DMERR("gcm(aes) key could not be set\n");
        goto exit;
    }
    r = crypto_aead_decrypt(req);
    if (r == -EBADMSG) {
        DMERR("gcm(aes) authentication failed");
        goto exit;
    } else if (r) {
        DMERR("gcm(aes) decryption error\n");
        goto exit;
	}
exit:
    if (req)
        aead_request_free(req);
    return r;
}

struct aead_cipher* aes_gcm_cipher_init(struct aes_gcm_cipher *ag) {
    ag->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(ag->tfm)) {
        DMERR("could not allocate aead handler\n");
        return NULL;
    }
    ag->block_size = AES_GCM_BLOCK_SIZE;
    ag->auth_size = AES_GCM_AUTH_SIZE;
    ag->iv_size = AES_GCM_IV_SIZE;
    ag->key_size = AES_GCM_KEY_SIZE;

    ag->interface.get_random_key = aes_gcm_get_random_key;
    ag->interface.get_random_iv = aes_gcm_get_random_iv;
    ag->interface.encrypt = aes_gcm_cipher_encrypt;
    ag->interface.decrypt = aes_gcm_cipher_decrypt;
    return &ag->interface;
}
