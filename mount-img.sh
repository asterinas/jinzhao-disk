#!/bin/sh

dd if=/dev/null of=./disk.img seek=20971520 # 10G
dd if=/dev/null of=./meta.img seek=4194304  # 2G

losetup /dev/loop0 ./disk.img
losetup /dev/loop1 ./meta.img

modprobe dm-persistent-data
insmod sworndisk.ko

echo 0 20971520 sworndisk a7f67ad520bd83b971225df6ebd76c3eee c01be00ba5f730aacb039e86 /dev/loop0 /dev/loop1 | dmsetup create test-sworndisk
