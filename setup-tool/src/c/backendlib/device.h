#ifndef DEVICE_H
#define DEVICE_H

/**
 * Device status
 */
typedef enum {
	CRYPT_INVALID, /**< device mapping is invalid in this context */
	CRYPT_INACTIVE, /**< no such mapped device */
	CRYPT_ACTIVE, /**< device is active */
	CRYPT_BUSY /**< device is active and has open count > 0 */
} crypt_status_info;

struct device *device_alloc(const char *path);
void device_free(struct device *device);
size_t device_block_size(struct device *device);
int device_block_adjust(struct device *device, uint64_t device_offset,
			uint64_t *size);
const char *device_block_path(const struct device *device);

char *device_path(struct device *device);

#endif