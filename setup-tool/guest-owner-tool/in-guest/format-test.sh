#!/bin/sh

ref_rootfs=/dev/sda2
jindisk_partition=/dev/sdb

jindisk_partition_size=`blockdev --getsize ${jindisk_partition}`
echo "jindisk_partition_size: "${jindisk_partition_size}

sudo jindisksetup create 2333 ${jindisk_partition} jindisk_rootfs
if [ $? -ne 0 ]; then
	echo "jindisksetup failed"
else
	echo "jindisksetup succeeded"
fi

dd if=${ref_rootfs} of=/dev/mapper/jindisk_rootfs status=progress

