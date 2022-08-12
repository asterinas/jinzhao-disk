#!/bin/sh

dmsetup remove test-sworndisk

rmmod sworndisk.ko
modprobe -r dm-persistent-data

losetup -d /dev/loop0

rm ./disk.img  -f
