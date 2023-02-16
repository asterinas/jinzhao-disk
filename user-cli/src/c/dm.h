#ifndef DM_UTIL_H
#define DM_UTIL_H

#include <stdint.h>
#include "internal.h"

int dm_check_versions(void);
int dm_status_device(const char *name);
int dm_create_device(const char *name, struct dm_target *tgt);
int dm_remove_device(const char *name);
int dm_query_device(const char *name, struct dm_target *tgt);

#endif