# JinDisk Linux Kernel Module

## A New Device Mapper Target

This Linux kernel module implements `dm-jindisk`, a new Linux [device mapper](https://docs.kernel.org/admin-guide/device-mapper/index.html) target that adds JinDisk as a new type of secure block devices to Linux.

In a nut shell, a device mapper target provides a class of virtual block devices with some unique functionalities, including security enhancement. For example, there are various kinds of secure virtual block devices provided by device mapper targets, including `dm-crypt`, `dm-integrity`, and `dm-verity`. Although `dm-jindisk` is late to join the party, it is unique in its strong security protection against TEE adversaries.

## Build Instructions

JinDisk is developed and tested with Linux kernel v5.15.x, later version may also work. Since JinDisk is an external module, to build and install JinDisk, you must have a prebuilt kernel available that contains the configuration and header files used in the build.

### Prepare Kernel Development Environment

If you are using a distribution kernel, there will be a package for the kernel you are running provided by your distribution, but make sure that the kernel version is v5.15.x or later. Take CentOS and Ubuntu for example:
- CentOS: `$ sudo yum install kernel-devel`
- Ubuntu: `$ sudo apt install linux-source`

Nevertheless, building Linux kernel from scratch is more recommended. Following steps will introduce you to build & install the Linux kernel, and you can refer to this [document](https://wiki.linuxquestions.org/wiki/How_to_build_and_install_your_own_Linux_kernel) for more information.

#### Step 1. Get Linux Kernel Source
```bash
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
$ cd linux
$ git checkout v5.15.1
```

#### Step 2. Install Required Packages (Ubuntu)
```bash
$ sudo apt install dpkg-dev libncurses5-dev openssl libssl-dev build-essential pkg-config libc6-dev libc6-dev flex libelf-dev zlibc minizip libidn11-dev libidn11-dev bison dwarves
```

#### Step 3. Configure with CONFIG_DM_BUFIO=m/y

We need to enable `dm-bufio`, a kernel module that `dm-jindisk` depends on.

```bash
$ make mrproper
$ cp -v /boot/config-$(uname -r) .config
$ make olddefconfig
$ ./scripts/config --module CONFIG_DM_BUFIO
$ make prepare
```

#### Step 4. Build the Kernel
```bash
$ make -j$(nproc)
```

#### Step 5. Install Modules & Kernel
```bash
$ sudo make modules_install
$ sudo make install
```

#### Step 6. Update Bootloader (Optional)
```bash
$ sudo update-initramfs -c -k 5.15.1
$ sudo update-grub
```

#### Step 7. Reboot and Verify Kernel Version
```bash
$ uname -mrs
```

### Build JinDisk


To build JinDisk's kernel module (`dm-jindisk.ko`), run the following commands.

```bash
$ cd <jindisk_repo>/kernel-module/c
$ make
```
or
```bash
$ make DEBUG=1
```

### Enable JinDisk

To load JinDisk's kernel module, run the following commands.

```bash
$ sudo modprobe dm-bufio
$ sudo insmod dm-jindisk.ko
```

### Create a JinDisk device

To create a virtual block device of JinDisk, one can use the [dmsetup](https://man7.org/linux/man-pages/man8/dmsetup.8.html) command of the following form.

```bash
$ sudo dmsetup create <jindisk_dev_name> <<JINDISK_ARGS
<start_sector> <num_sectors> jindisk <root_key> <root_iv> <untrusted_dev_path> <format>
JINDISK_ARGS
```

The `create` sub-command of `dmsetup` takes as the first argument the name of the JinDisk logical block device to be created. If the command succeeds, the new JinDisk device will appear at `/dev/mapper/<jindisk_dev_name>`.

The second argument, which is read from the standard input (between the pair of `JINDISK_ARGS`), is a data structure called _table_, which gives the parameters of the logical block device to be created by a device mapper target. For JinDisk, the table contains the following fields:

- `<start_sector>`: the start sector of the logical device. Usually set to `0`.
- `<num_sectors>`: the capacity of the logical device in sectors.
- `jindisk`: the device mapper type of the logical device.
- `<root_key>`: the root key of the logical device, represented in hexadecimal numbers. JinDisk utilizes [AES-128-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) to encrypt and decrypt blocks. The root key has a length of 128 bits, which means 32 hexadecimal digits (e.g., `a7f67ad520bd83b971225df6ebd76c3e`).
- `<root_iv>`: the root initialization vector (IV) of the logical device, represented in hexadecimal numbers. The IV has a length of 96 bits, which means 24 hexadecimal digits (e.g., `c01be00ba5f730aacb039e86`).
- `<untrusted_dev_path>`: the path of the underlying _untrusted_ block device where the JinDisk logical block device stores its data. This device is not trusted by JinDisk.
- `<format>`: deciding whether the untrusted device should be formatted when creating the JinDisk device. If `<format>` equals to `1`, then all data on the untrusted device will be wiped out and an empty JinDisk instance will be created with `root_key` and `root_iv`. If `<format>` equals to `0`, then an JinDisk instance will be loaded from the untrusted device, using the `root_key` and `root_iv`.

Here is a concrete example.

```bash
$ sudo dmsetup create test-jindisk <<JINDISK_ARGS
0 20971520 jindisk a7f67ad520bd83b971225df6ebd76c3e c01be00ba5f730aacb039e86 /dev/sdb 1
JINDISK_ARGS
```

Note that the capacity of a JinDisk logical block device must be less than that of the underlying untrusted block device. This is because some storage space of the untrusted block device is consumed by JinDisk to store metadata, instead of user data. Given the capacity of an untrusted block device, one can use the following sysfs interface provided by JinDisk to calculate the maximum capacity of a JinDisk instance that may be created on the untrusted block device.

```bash
$ sudo echo <untrusted_dev_sectors> > /sys/module/jindisk/calc_avail_sectors
$ sudo cat /sys/module/jindisk/calc_avail_sectors
```

If a JinDisk instance is created successfully, then you should find the JinDisk device in the system with `lsblk`.

```bash
$ sudo lsblk
NAME           MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sdb              8:16   0   12G  0 disk
└─test-jindisk 253:0    0   10G  0 dm
```

## Fio Benchmark

To benchmark persistent disk performance, you can use [FIO](https://fio.readthedocs.io/) instead of other disk benchmarking tools such as [dd](https://en.wikipedia.org/wiki/Dd_(Unix)). By default, `dd` uses a very low I/O queue depth, so it is difficult to ensure that the benchmark is generating a sufficient number of I/Os and bytes to accurately test disk performance.

#### Step 1. Install FIO (use apt or yum)

```bash
$ sudo apt update
$ sudo apt install -y fio
```

#### Step 2. Benchmarking with FIO

- sequential read
```bash
$ sudo fio -ioengine=sync -size=4G -iodepth=16 -rw=read -filename=/dev/mapper/test-jindisk -name=seqread -bs=64K -direct=1 -numjobs=1 -fsync_on_close=1
```

- sequential write
```bash
$ sudo fio -ioengine=sync -size=4G -iodepth=16 -rw=write -filename=/dev/mapper/test-jindisk -name=seqwrite -bs=64K -direct=1 -numjobs=1 -fsync_on_close=1
```

- random read
```bash
$ sudo fio -ioengine=sync -size=4G -iodepth=16 -rw=randread -filename=/dev/mapper/test-jindisk -name=randread -bs=64K -direct=1 -numjobs=1 -fsync_on_close=1
```

- random write
```bash
$ sudo fio -ioengine=sync -size=4G -iodepth=16 -rw=randwrite -filename=/dev/mapper/test-jindisk -name=randwrite -bs=64K -direct=1 -numjobs=1 -fsync_on_close=1
```