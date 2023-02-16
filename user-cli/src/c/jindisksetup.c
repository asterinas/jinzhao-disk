#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <openssl/evp.h>

#include <linux/limits.h>

#include "internal.h"
#include "libdm_jindisk.h"

void PBKDF2_HMAC_SHA_512(const char *pass, int passlen,
			 const unsigned char *salt, int saltlen,
			 int32_t iterations, uint32_t outputBytes,
			 char *hexResult, uint8_t *binResult)
{
	unsigned int i;
	unsigned char digest[outputBytes];

	PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iterations,
			  EVP_sha512(), outputBytes, digest);
	for (i = 0; i < sizeof(digest); i++) {
		sprintf(hexResult + (i * 2), "%02x", 255 & digest[i]);
		binResult[i] = digest[i];
	};
}

int action_create(const char *password, const char *dev_path,
		  const char *dm_name)
{
	int key_size = 128; /* SHA512 output has 128 chars */
	// WL: generate keyset using Pbkdf2
	int r = 0;
	// WL: using default salt, round (131072) to generate key, iv
	int passlen = strlen(password);
	const unsigned char *salt = "salt";
	int saltlen = strlen(salt);
	int32_t iterations = 131072;

	uint32_t outputBytes = 64;
	char hexResult[2 * outputBytes + 1];
	memset(hexResult, 0, sizeof(hexResult));
	uint8_t binResult[outputBytes];
	memset(binResult, 0, sizeof(binResult));
	char *keyset = NULL;

	printf("Computing PBKDF2(HMAC-SHA512, '%s', '%s', %d, %d) ...\n",
	       password, salt, iterations, outputBytes);
	PBKDF2_HMAC_SHA_512(password, passlen, salt, saltlen, iterations,
			    outputBytes, hexResult, binResult);

	keyset = (char *)binResult;

	if (dm_name)
		r = jindisk_activate(dev_path, dm_name, keyset, key_size, 1);
	else
		printf("No activated device!\n");

	return r;
}

int action_open(const char *password, const char *dev_path, const char *dm_name)
{
	int key_size = 128; /* SHA512 output has 128 chars */
	int r = 0;
	// WL: using default salt, round (131072) to generate key, iv
	int passlen = strlen(password);
	const unsigned char *salt = "salt";
	int saltlen = strlen(salt);
	int32_t iterations = 131072;

	uint32_t outputBytes = 64;
	char hexResult[2 * outputBytes + 1];
	memset(hexResult, 0, sizeof(hexResult));
	uint8_t binResult[outputBytes];
	memset(binResult, 0, sizeof(binResult));
	char *keyset = NULL;

	printf("Computing PBKDF2(HMAC-SHA512, '%s', '%s', %d, %d) ...\n",
	       password, salt, iterations, outputBytes);
	PBKDF2_HMAC_SHA_512(password, passlen, salt, saltlen, iterations,
			    outputBytes, hexResult, binResult);

	keyset = (char *)binResult;

	if (dm_name)
		r = jindisk_activate(dev_path, dm_name, keyset, key_size, 0);
	else
		printf("No activated device!\n");

	return r;
}

int action_close(const char *activated_name)
{
	int r = 0;

	if (activated_name) {
		r = jindisk_deactivate(activated_name);
	} else
		printf("No activated device!\n");

	return r;
}

int main(int argc, const char **argv)
{
	const char *password = NULL;
	const char *dev_path = NULL;
	const char *dm_name = NULL;
	int r = 0;
	uint8_t need_help = 0;

	if (argc <= 1) {
		printf("Too few arguments!\n");
		need_help = 1;
		goto help;
	}
	if (argc >= 6) {
		printf("Too many arguments!\n");
		need_help = 1;
		goto err;
	}

	if (!strcmp(argv[1], "create")) {
		if (argc == 5) {
			password = argv[2];
			dev_path = argv[3];
			dm_name = argv[4];
			r = action_create(password, dev_path, dm_name);
			if (r != 0)
				goto err;
			else
				goto out;
		} else {
			need_help = 1;
			goto help;
		}
	}
	if (!strcmp(argv[1], "open")) {
		if (argc == 5) {
			password = argv[2];
			dev_path = argv[3];
			dm_name = argv[4];
			r = action_open(password, dev_path, dm_name);
			if (r != 0)
				goto err;
			else
				goto out;
		} else {
			need_help = 1;
			goto help;
		}
	} else if (!strcmp(argv[1], "close")) {
		if (argc == 3) {
			dm_name = argv[2];
			r = action_close(dm_name);
			if (r != 0)
				goto err;
			else
				goto out;
		} else {
			need_help = 1;
			goto help;
		}
	} else {
		need_help = 1;
	}
err:
	printf("Something wrong. Check password/device please!\n");
	return r;
help:
	if (need_help) {
		puts("Options: create/open/close");
		puts("Usage: ");
		puts("jindisksetup create/open <password> <device_name> <dm_name>");
		puts("jindisksetup close <dm_name>");
	}
	return -1;
out:
	printf("JinZhao Disk setup done.\n");
	return 0;
}
