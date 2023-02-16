/*
 * libdm_jindisk - device-mapper backend for jindisksetup CLI
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <libdevmapper.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <linux/fs.h>

#include "internal.h"
#include "vk.h"
#include "utils_hex.h"
#include "device.h"
#include "dm.h"
#include "libdm_jindisk.h"

int create_or_open_device(const char *name, struct dm_target *tgt)
{
	int r;

	// WL: calculate size and put it into &(tgt->size)
	r = device_block_adjust(tgt->data_device, tgt->offset, &(tgt->size));

	if (!r) {
		r = dm_create_device(name, tgt);
	}

	return r;
}

crypt_status_info crypt_status(const char *name)
{
	int r;

	if (!name)
		return CRYPT_INVALID;

	r = dm_status_device(name);

	if (r < 0 && r != -ENODEV)
		return CRYPT_INVALID;

	if (r == 0)
		return CRYPT_ACTIVE;

	if (r > 0)
		return CRYPT_BUSY;

	return CRYPT_INACTIVE;
}

int jindisk_activate(const char *device_name, const char *target_name,
		     const char *keyset, size_t key_size,
		     unsigned long action_flag)
{
	// WL: set vk as NULL so password won't affect it
	struct device *jindiskdevice = NULL;
	struct volume_key *vk = NULL;
	int r;

	if (!dm_check_versions()) {
		if (getuid() || geteuid())
			printf("Cannot initialize device-mapper, running as non-root user.\n");
		else
			printf("Cannot initialize device-mapper. Is dm_mod kernel module loaded?\n");
		return -ENOTSUP;
	}

	printf("Allocating context for jindisk device %s.\n",
	       device_name ?: "(none)");
	jindiskdevice = device_alloc(device_name);
	if (jindiskdevice == NULL) {
		printf("Device init failed!\n");
		return -ENOMEM;
	}

	// WL: now we only support SHA512 (key_size == 128) as the PBKDF hash algorithm
	if (!keyset || !key_size || key_size != SHA512_KEYSIZE) {
		printf("Incorrect volume key specified for jindisk device.\n");
		return -EINVAL;
	}

	vk = crypt_alloc_volume_key(key_size, keyset);
	if (!vk)
		return -ENOMEM;

	printf("Setting jindisk target...\n");
	struct dm_target tgt = { .data_device = jindiskdevice,
				 .vk = vk,
				 .offset = 0,
				 .action_flag = action_flag };

	r = create_or_open_device(target_name, &tgt);

	memset(&tgt, 0, sizeof(struct dm_target));

	bzero(vk->key, vk->keylength);
	vk->keylength = 0;
	free(vk);

	device_free(jindiskdevice);

	memset(&tgt, 0, sizeof(struct dm_target));

	return r;
}

int jindisk_deactivate(const char *name)
{
	struct dm_target tgt = {};
	int r;

	if (!dm_check_versions()) {
		if (getuid() || geteuid())
			printf("Cannot initialize device-mapper, running as non-root user.\n");
		else
			printf("Cannot initialize device-mapper. Is dm_mod kernel module loaded?\n");
		return -ENOTSUP;
	}

	switch (crypt_status(name)) {
	case CRYPT_ACTIVE:
	case CRYPT_BUSY:
		r = dm_query_device(name, &tgt);
		if (r >= 0) {
			if (tgt.holders) {
				printf("Device %s is still active and scheduled for deferred removal.\n",
				       name);
				r = -EBUSY;
				break;
			}
		}

		r = dm_remove_device(name);
		if (r < 0) {
			printf("Device %s cannot be removed.\n", name);
			r = -EBUSY;
		}
		break;
	case CRYPT_INACTIVE:
		printf("Device %s is not active.\n", name);
		r = -ENODEV;
		break;
	default:
		printf("Invalid device %s.\n", name);
		r = -EINVAL;
	}

	memset(&tgt, 0, sizeof(struct dm_target));

	return r;
}