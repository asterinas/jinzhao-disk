#ifndef LIBDM_jindisk_H
#define LIBDM_jindisk_H

int jindisk_activate(const char *device_path, const char *name, const char *key,
		     size_t key_size, unsigned long action_flag);
int jindisk_deactivate(const char *name);

#endif
