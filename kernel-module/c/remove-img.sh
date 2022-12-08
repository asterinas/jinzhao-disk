#!/bin/sh

dmsetup remove test-jindisk

rmmod jindisk.ko
modprobe -r dm_bufio

losetup -d /dev/loop0

rm ./disk.img  -f
