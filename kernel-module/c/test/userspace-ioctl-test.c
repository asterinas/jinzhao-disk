/*
 * This is a userspace program for testing some ioctl API, exported by
 * `/dev/jindisk` device.
 * Compile & run test:
 * ```
 * gcc userspace-ioctl-test.c -o test
 * ./test
 * ```
 */
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

typedef unsigned long long u64;
struct calc_task {
	u64 real_sectors;
	u64 avail_sectors;
};

#define AES_GCM_AUTH_SIZE 16

#define JINDISK_IOC_MAGIC 'J'
#define NR_CALC_AVAIL_SECTORS 0
#define NR_GET_MEASUREMENT 1
#define JINDISK_CALC_AVAIL_SECTORS	\
	_IOWR(JINDISK_IOC_MAGIC, NR_CALC_AVAIL_SECTORS, struct calc_task)
#define JINDISK_GET_MEASUREMENT	\
	_IOR(JINDISK_IOC_MAGIC, NR_GET_MEASUREMENT, char[AES_GCM_AUTH_SIZE])

#define EXPECT_THRESHOLD(x, percent) ((x) / 100 * (percent))

void assert_CALC_AVAIL_SECTORS(int fd, u64 real_sectors, int percent)
{
	int r = 0;
	struct calc_task ct;
	u64 threshold_sector;

	threshold_sector = EXPECT_THRESHOLD(real_sectors, percent);
	ct.real_sectors = real_sectors;
	r = ioctl(fd, JINDISK_CALC_AVAIL_SECTORS, &ct);
	if (r < 0) {
		printf("do ioctl failed\n");
		goto out;
	}
	if (ct.avail_sectors < threshold_sector) {
		printf("assert_CALC_AVAIL_SECTORS failed\n");
		printf("actual: %llu\n", ct.avail_sectors);
		printf("threshold: %llu\n", threshold_sector);
		goto out;
	}
	printf("assert_CALC_AVAIL_SECTORS successed\n");
out:
	return;
}

void get_measurement(int fd)
{
	int r = 0;
	char mac[AES_GCM_AUTH_SIZE];

	r = ioctl(fd, JINDISK_GET_MEASUREMENT, mac);
	if (r < 0) {
		printf("JINDISK_GET_MEASUREMENT ioctl failed\n");
		goto out;
	}
	printf("JINDISK_GET_MEASUREMENT ioctl successed\n");
out:
	return;
}

int main()
{
	int fd;
	int r = 0;

	fd = open("/dev/jindisk", O_RDWR);
	if (fd < 0) {
		printf("open /dev/jindisk failed\n");
		r = -EAGAIN;
		goto out;
	}
	assert_CALC_AVAIL_SECTORS(fd, 0ull, 0);
	assert_CALC_AVAIL_SECTORS(fd, 0xFFFFFFFFFFFFFFFF, 80);

	get_measurement(fd);

	close(fd);
out:
	return r;
}
