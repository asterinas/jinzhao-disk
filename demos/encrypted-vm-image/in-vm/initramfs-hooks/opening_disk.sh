#!/bin/sh

# Saved for RA
key=`/sbin/getting_key.sh`

jindisksetup open ${key} /dev/vda3 jindisk_rootfs

# For jindisksetup-rust
# jindisksetup-rust open -p ${key} -d /dev/sda3 -t jindisk_rootfs

# fsck /dev/mapper/jindisk_rootfs
