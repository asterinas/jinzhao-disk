#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include <libdevmapper.h>

#include <linux/fs.h>

#include "internal.h"
#include "dm.h"
#include "device.h"
#include "utils_hex.h"
#include "vk.h"

static bool _dm_ioctl_checked = false;
static int _dm_use_count = 0;

int dm_check_versions(void)
{
	struct dm_task *dmt;
	struct dm_versions *target, *last_target;
	char dm_version[16];
	unsigned dm_maj, dm_min, dm_patch;

	if (!(dmt = dm_task_create(DM_DEVICE_LIST_VERSIONS)))
		goto out;

	if (!dm_task_run(dmt))
		goto out;

	if (!dm_task_get_driver_version(dmt, dm_version, sizeof(dm_version)))
		goto out;

	if (!_dm_ioctl_checked) {
		if (sscanf(dm_version, "%u.%u.%u", &dm_maj, &dm_min,
			   &dm_patch) != 3)
			goto out;
		printf("Detected dm-ioctl version %u.%u.%u.\n", dm_maj, dm_min,
		       dm_patch);
	}

	target = dm_task_get_versions(dmt);

	_dm_ioctl_checked = true;
out:
	if (dmt)
		dm_task_destroy(dmt);

	return (_dm_ioctl_checked ? 1 : 0);
}

// WL: the most important function
static char *get_dm_jindisk_params(struct dm_target *tgt)
{
	// WL: currently we use a 32 chars key hex string and 24 chars iv hex string
	int r, max_size, null_cipher = 0, num_options = 0, keystr_len = 32,
			 ivstr_len = 24;
	char *params = NULL;
	char *hexkeystr = NULL;
	char key[keystr_len + 1];
	char iv[ivstr_len + 1];

	if (!tgt)
		return NULL;

	hexkeystr = malloc(keystr_len + ivstr_len);
	hexkeystr = crypt_bytes_to_hex(keystr_len + ivstr_len, tgt->vk->key);
	if (!hexkeystr)
		goto out;

	max_size =
		strlen(hexkeystr) + strlen(device_path(tgt->data_device)) + 64;

	params = malloc(max_size);
	if (!params)
		goto out;

	memcpy(key, hexkeystr, keystr_len);
	key[keystr_len] = '\0';
	memcpy(iv, hexkeystr + keystr_len, ivstr_len);
	iv[ivstr_len] = '\0';

	// WL: params format: key, iv, dev_path, action_flag
	r = snprintf(params, max_size, "%s %s %s %lu", key, iv,
		     device_path(tgt->data_device), tgt->action_flag);
	printf("Getting jindisk params: %s\n", params);

	if (r < 0 || r >= max_size) {
		free(params);
		params = NULL;
	}
out:
	free(hexkeystr);
	return params;
}

/* DM helpers */
// WL: no udev support
static int _dm_remove(const char *name)
{
	int r = 0;
	struct dm_task *dmt;

	if (!(dmt = dm_task_create(DM_DEVICE_REMOVE)))
		return 0;

	if (!dm_task_set_name(dmt, name))
		goto out;

	r = dm_task_run(dmt);

out:
	dm_task_destroy(dmt);
	return r;
}

static int dm_status_dmi(const char *name, struct dm_info *dmi,
			 const char *target, char **status_line)
{
	struct dm_task *dmt;
	uint64_t start, length;
	int r = -EINVAL;

	if (!(dmt = dm_task_create(DM_DEVICE_STATUS)))
		return r;

	if (!dm_task_no_flush(dmt))
		goto out;

	if (!dm_task_set_name(dmt, name))
		goto out;

	if (!dm_task_run(dmt))
		goto out;

	if (!dm_task_get_info(dmt, dmi))
		goto out;

	if (!dmi->exists) {
		r = -ENODEV;
		goto out;
	}

	r = 0;

out:

	dm_task_destroy(dmt);
	return r;
}

int dm_status_device(const char *name)
{
	int r;
	struct dm_info dmi;
	struct stat st;

	// WL: libdevmapper is too clever and handles path argument differently with error. Fail early here if parameter is non-existent path.
	if (strchr(name, '/') && stat(name, &st) < 0)
		return -ENODEV;

	r = dm_status_dmi(name, &dmi, NULL, NULL);

	if (r < 0)
		return r;

	return (dmi.open_count > 0) ? 1 : 0;
}

// WL: core function when doing dm create
static int _dm_create_device(const char *name, struct dm_target *tgt)
{
	struct dm_task *dmt = NULL;
	struct dm_info dmi;
	int r = -EINVAL;

	if (!(dmt = dm_task_create(DM_DEVICE_CREATE)))
		goto out;

	if (!dm_task_set_name(dmt, name))
		goto out;

	if (!dm_task_secure_data(dmt))
		goto out;

	tgt->params = get_dm_jindisk_params(tgt);
	if (!tgt->params) {
		r = -EINVAL;
		goto out;
	}

	if (!dm_task_add_target(dmt, tgt->offset, tgt->size, "jindisk",
				tgt->params))
		goto out;

	r = -EINVAL;

	printf("Running the IOCTL...\n");
	if (!dm_task_run(dmt)) {
		r = dm_status_device(name);
		;
		if (r >= 0)
			r = -EEXIST;
		if (r != -EEXIST && r != -ENODEV)
			r = -EINVAL;
		goto out;
	}

	if (dm_task_get_info(dmt, &dmi))
		r = 0;

	if (r < 0)
		_dm_remove(name);

out:
	if (dmt)
		dm_task_destroy(dmt);

	dm_task_update_nodes();

	free(tgt->params);
	tgt->params = NULL;

	return r;
}

int dm_create_device(const char *name, struct dm_target *tgt)
{
	int r = -EINVAL;

	if (!tgt)
		return -EINVAL;

	r = _dm_create_device(name, tgt);

	return r;
}

int dm_query_device(const char *name, struct dm_target *tgt)
{
	if (!tgt)
		return -EINVAL;

	memset(tgt, 0, sizeof(*tgt));

	struct dm_task *dmt;
	struct dm_info dmi;
	uint64_t start, length;
	char *target_type, *params;
	int r = -EINVAL;

	if (!(dmt = dm_task_create(DM_DEVICE_TABLE)))
		return r;

	if (!dm_task_secure_data(dmt))
		goto out;

	if (!dm_task_set_name(dmt, name))
		goto out;

	r = -ENODEV;

	if (!dm_task_run(dmt))
		goto out;

	r = -EINVAL;
	if (!dm_task_get_info(dmt, &dmi))
		goto out;

	if (!dmi.exists) {
		r = -ENODEV;
		goto out;
	}

	if (dmi.target_count <= 0) {
		r = -EINVAL;
		goto out;
	}

	/* Never allow one to return empty key */
	if (dmi.suspended) {
		printf("Cannot read volume key while suspended.\n");
		r = -EINVAL;
		goto out;
	}

	tgt->holders = 0;

	r = (dmi.open_count > 0);

out:
	dm_task_destroy(dmt);

	if (r < 0)
		memset(tgt, 0, sizeof(*tgt));

	return r;
}

int dm_remove_device(const char *name)
{
	int r = -EINVAL;
	int retries = 1;

	if (!name)
		return -EINVAL;

	r = _dm_remove(name) ? 0 : -EINVAL;
	if (r) {
		printf("WARNING: other process locked internal device %s, %s.\n",
		       name, retries ? "retrying remove" : "giving up");
		sleep(1);
	}

	dm_task_update_nodes();

	return r;
}
