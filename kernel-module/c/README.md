# JinDisk Linux Kernel Module Source

This is the prototype of JinDisk, a Linux kernel module written in C.

JinDisk is based on an OS abstraction layer for virtual block devices, which enables file systems to use different virtual block devices as storage in a uniform way. In the Linux kernel, this abstraction layer is called [device mapper](https://docs.kernel.org/admin-guide/device-mapper/index.html).

## Build Instructions

JinDisk is developed and tested with Linux kernel v5.15.x, later version may also work. Since JinDisk is an external module, to build and install JinDisk, you must have a prebuilt kernel available that contains the configuration and header files used in the build. Also, the kernel must have been built with modules enabled.

### Prepare Kernel Development Environment

If you are using a distribution kernel, there will be a package for the kernel you are running provided by your distribution, but make sure that the kernel version is v5.15.x or later. Take CentOS and Ubuntu for example:
- CentOS: `$ sudo yum install kernel-devel`
- Ubuntu: `$ sudo apt install linux-source`

Nevertheless, building Linux kernel from scratch is more recommended. Following steps will introduce you to build & install the Linux kernel, and you can refer to this [document](https://wiki.linuxquestions.org/wiki/How_to_build_and_install_your_own_Linux_kernel) for more information.

#### Step 1. Get Linux Kernel Source
```bash
$ git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
$ cd linux
$ git checkout v5.15.1 -b <your_branch_name>
```

#### Step 2. Install Required Packages (Ubuntu)
```bash
$ sudo apt install dpkg-dev libncurses5-dev openssl libssl-dev build-essential pkg-config libc6-dev libc6-dev flex libelf-dev zlibc minizip libidn11-dev libidn11-dev bison dwarves
```

#### Step 3. Configure with CONFIG_DM_BUFIO=m/y
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

### Take Advantage of JinDisk

When the kernel development environment is ready, you can clone this repository to build JinDisk.

#### Build JinDisk

```bash
$ cd <path_to_jindisk_kernel_module>
$ make
```
or
```bash
$ make DEBUG=1
```
If you followed the above instructions, you should obtain the `jindisk.ko` module in the current directory eventually.

#### Install JinDisk

```bash
$ cd <path_to_jindisk_kernel_module>
$ sudo modprobe dm-bufio
$ sudo insmod jindisk.ko
```

#### Create a JinDisk Device

Now you can use the following cmdline to create a virtual block device enabled by JinDisk. Each field is explained as below:
- start: the start sector of JinDisk, usually set to `0`;
- end: the end sector of JinDisk;
- root_key: JinDisk utilized [AES-128-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) to encrypt & decrypt blocks, so you should specify the key/iv to format or reload a JinDisk; here, `key` should be a `128 bit` hexadecimal number (one character represents 4 bits), such as `a7f67ad520bd83b971225df6ebd76c3e`;
- root_iv: the the initialization vector used by AES-128-GCM, `96 bit` hexadecimal number, such as `c01be00ba5f730aacb039e86`;
- host_dev_path: the underlying host disk, JinDisk will store data & metadata on it;
- format: indicate that if the driver should format the `host_dev` when create a  `logical_dev` of JinDisk; `1` means that it will `wipe out` old data in host_dev, and write the metadate of JinDisk; `0` means that it will only try to reload metadata of JinDisk, using the root_key/iv to decrypt host_dev;
- logical_dev_name: the name of virtual block device;

```bash
$ sudo echo <start> <end> jindisk <root_key> <root_iv> <host_dev_path> <format> | dmsetup create <logic_dev_name>
```
For example:
```bash
$ sudo echo 0 20971520 jindisk a7f67ad520bd83b971225df6ebd76c3e c01be00ba5f730aacb039e86 /dev/sdb 1 | dmsetup create test-jindisk
```
**NOTICE**: the logical_dev_size should be less than the host_dev_size, you can calculate available logical_dev_size using such sysfs interface:
```bash
$ sudo echo <host_dev_size> > /sys/module/jindisk/calc_avail_sectors
$ sudo cat /sys/module/jindisk/calc_avail_sectors
```
Now, you should find the JinDisk in the system, like that:
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