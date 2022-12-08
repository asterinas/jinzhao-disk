#!/bin/sh

if [ $# -ne 1 ];
then
	echo "Usage: sudo install-jindisk <your_path_to_jindisk-linux-c>!"
	exit
fi


jindisk_SRC="$1"

rmmod jindisk
modprobe -r dm-persistent-data jindisk

cd $jindisk_SRC

make clean
make

modprobe dm-persistent-data
insmod ./jindisk.ko

cp ./jindisk.ko /lib/modules/`uname -r`/kernel
depmod

echo "" >> /etc/initramfs-tools/modules
echo "dm-persistent-data" >> /etc/initramfs-tools/modules
echo "jindisk" >> /etc/initramfs-tools/modules
update-initramfs -u -k all
