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

#define JINDISK_IOC_MAGIC 'J'
#define NR_CALC_AVAIL_SECTORS 0
#define JINDISK_CALC_AVAIL_SECTORS	\
	_IOWR(JINDISK_IOC_MAGIC, NR_CALC_AVAIL_SECTORS, struct calc_task)

void assert_CALC_AVAIL_SECTORS(int fd, u64 real_sectors,
			       u64 avail_sectors)
{
	int r = 0;
	struct calc_task ct;

	ct.real_sectors = real_sectors;
	r = ioctl(fd, JINDISK_CALC_AVAIL_SECTORS, &ct);
	if (r < 0) {
		printf("do ioctl failed\n");
		goto out;
	}
	if (ct.avail_sectors != avail_sectors) {
		printf("assert_CALC_AVAIL_SECTORS failed\n");
		printf("actual: %llu\n", ct.avail_sectors);
		printf("excepted: %llu\n", avail_sectors);
		goto out;
	}
	printf("assert_CALC_AVAIL_SECTORS successed\n");
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
	assert_CALC_AVAIL_SECTORS(fd, 0ull, 0ull);
	assert_CALC_AVAIL_SECTORS(fd, 0xFFFFFFFFFFFFFFFF,
				  18372064450009194496ull);

	close(fd);
out:
	return r;
}
