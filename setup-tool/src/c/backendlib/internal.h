#ifndef INTERNAL_H
#define INTERNAL_H

#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>

#define SECTOR_SHIFT 9
#define MISALIGNED(a, b) ((a) & ((b)-1))
#define DEFAULT_MEM_ALIGNMENT 4096

// WL: no locking support
struct device {
	char *path;
	char *file_path; /* WL: device could be a loop file */
	int dev_fd;

	// unsigned int o_direct : 1;
	size_t block_size; /* WL: device could be a loop file */
};

struct volume_key {
	size_t keylength;
	char key[]; /* this key consists of both key and iv */
};

struct dm_target {
	struct device *data_device;
	struct volume_key *vk;
	uint64_t offset; /* offset in sectors */
	uint64_t size;
	unsigned long action_flag;
	char *params;
	unsigned holders : 1; /* device flag detected (on query only) */
};

#endif /* INTERNAL_H */
