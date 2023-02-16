#!/bin/sh

# For Linux 5.15/5.17

SHELL_FOLDER=$(cd "$(dirname "$0")";pwd)

KERNEL_MODULE_SRC="${SHELL_FOLDER}/../../../../kernel-module/c"

rmmod dm-jindisk
modprobe -r dm-bufio dm-jindisk

cd $KERNEL_MODULE_SRC

make clean
make

modprobe dm-bufio
insmod ./dm-jindisk.ko

cp ./dm-jindisk.ko /lib/modules/`uname -r`/kernel
depmod

echo "Adding the JinDisk kernel-module into the initramfs..."
echo "" >> /etc/initramfs-tools/modules
echo "dm-bufio" >> /etc/initramfs-tools/modules
echo "dm-jindisk" >> /etc/initramfs-tools/modules
update-initramfs -u -k all
