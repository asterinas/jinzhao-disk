#!/bin/sh

dmsetup remove test-sworndisk

rmmod sworndisk.ko
modprobe -r dm-persistent-data

losetup -d /dev/loop0
losetup -d /dev/loop1

rm ./disk.img ./meta.img -f
