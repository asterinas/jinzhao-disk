#ifndef DM_SWORNDISK_CRYPTO_H
#define DM_SWORNDISK_CRYPTO_H

#include <linux/scatterlist.h> 
#include <crypto/aead.h> 

// in bytes
#define AES_GCM_KEY_SIZE 16
#define AES_GCM_BLOCK_SIZE 1 
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16

#define RFC_AES_GCM_KEY_SIZE 20
#define RFC_AES_GCM_IV_SIZE 8
#define RFC_AES_GCM_BLOCK_SIZE 1 
#define RFC_AES_GCM_AUTH_SIZE 16

struct aead_cipher {
    int (*encrypt)(struct aead_cipher* ac, char* data, int len, char* key, char* iv, char* mac, uint64_t seq, char* out);
    int (*decrypt)(struct aead_cipher* ac, char* data, int len, char* key, char* iv, char* mac, uint64_t seq, char* out);
    int (*get_random_key)(char** p_key, int key_len);
    int (*get_random_iv)(char** p_iv, int iv_len);
    void (*destroy)(struct aead_cipher* ac);
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
     
#define AEAD_MSG_NR_PART 4
struct aes_gcm_cipher {
    struct aead_cipher aead_cipher;
    struct crypto_aead *tfm;
    size_t key_size;
    size_t block_size;
    size_t auth_size;
    size_t iv_size;
    struct mutex lock;
};


struct aead_cipher* aes_gcm_cipher_create(void);
int __get_random_bytes(char** p_data, unsigned int len);

#endif