#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>

#include "internal.h"
#include "vk.h"

struct volume_key *crypt_alloc_volume_key(size_t keylength, const char *key)
{
	struct volume_key *vk;

	if (keylength > (SIZE_MAX - sizeof(*vk)))
		return NULL;

	vk = malloc(sizeof(*vk) + keylength);
	if (!vk)
		return NULL;

	vk->keylength = keylength;

	/* keylength 0 is valid => no key */
	if (vk->keylength) {
		if (key)
			memcpy(&vk->key, key, keylength);
		else
			bzero(&vk->key, keylength);
	}

	return vk;
}
