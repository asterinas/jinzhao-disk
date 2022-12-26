#!/bin/sh

if [ $# -ne 1 ];
then
	echo "Usage: sudo install-km <your_path_to_jindisk-linux/kernel-module/c>!"
	exit
fi


jindisk_SRC="$1"

rmmod jindisk
modprobe -r dm-bufio jindisk

cd $jindisk_SRC

make clean
make

modprobe dm-bufio
insmod ./jindisk.ko

cp ./jindisk.ko /lib/modules/`uname -r`/kernel
depmod

echo "" >> /etc/initramfs-tools/modules
echo "dm-persistent-data" >> /etc/initramfs-tools/modules
echo "jindisk" >> /etc/initramfs-tools/modules
update-initramfs -u -k all
