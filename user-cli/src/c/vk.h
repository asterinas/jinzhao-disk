#ifndef VK_H
#define VK_H

#define SHA512_KEYSIZE 128

struct volume_key *crypt_alloc_volume_key(size_t keylength, const char *key);

#endif
