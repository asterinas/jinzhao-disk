/*
 * cryptsetup volume key implementation
 *
 * Copyright (C) 2004-2006 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2010-2022 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


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
