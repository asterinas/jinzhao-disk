#!/bin/sh

dd if=/dev/null of=./disk.img seek=25165824 # data: 10G meta: 2G

losetup /dev/loop0 ./disk.img

modprobe dm_bufio
insmod dm-jindisk.ko

echo 0 20971520 jindisk a7f67ad520bd83b971225df6ebd76c3e c01be00ba5f730aacb039e86 /dev/loop0 1 | dmsetup create test-jindisk
