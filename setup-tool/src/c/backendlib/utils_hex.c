#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "utils_hex.h"

static char hex2asc(unsigned char c)
{
	return c + '0' + ((unsigned)(9 - c) >> 4 & 0x27);
}

char *crypt_bytes_to_hex(size_t size, const char *bytes)
{
	unsigned i;
	char *hex;

	if (size && !bytes)
		return NULL;

	/* Alloc adds trailing \0 */
	if (size == 0)
		hex = malloc(2);
	else
		hex = malloc(size * 2 + 1);
	if (!hex)
		return NULL;

	if (size == 0)
		hex[0] = '-';
	else
		for (i = 0; i < size; i++) {
			hex[i * 2] =
				hex2asc((const unsigned char)bytes[i] >> 4);
			hex[i * 2 + 1] =
				hex2asc((const unsigned char)bytes[i] & 0xf);
		}

	return hex;
}
