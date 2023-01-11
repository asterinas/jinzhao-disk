#!/bin/sh

# For Linux 5.15/5.17

SHELL_FOLDER=$(cd "$(dirname "$0")";pwd)

KERNEL_MODULE_SRC="${SHELL_FOLDER}/../../../kernel-module/c"

rmmod jindisk
modprobe -r dm-bufio jindisk

cd $KERNEL_MODULE_SRC

make clean
make

modprobe dm-bufio
insmod ./jindisk.ko

cp ./jindisk.ko /lib/modules/`uname -r`/kernel
depmod

echo "" >> /etc/initramfs-tools/modules
echo "dm-bufio" >> /etc/initramfs-tools/modules
echo "jindisk" >> /etc/initramfs-tools/modules
update-initramfs -u -k all
