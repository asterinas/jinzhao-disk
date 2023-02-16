#!/bin/bash

set -e
trap cleanup ERR EXIT

LINUX_RESERVED_PART_CODE="8300"

# Default arguments
src_dir="/home/weijie/dev/demo/jinzhao-disk"
dest_image="/home/weijie/dev/demo/ubuntu-20.04-jindisk.qcow2"
dest_dir="/home/ref"

usage() {
	echo "$0 [options]"
	echo "Available <commands>:"
	echo " -src         source directory that needs to be copied into the target image"
	echo " -image       target image"
	echo " -dest        destination directory in the target image"
	exit 1
}

# Parsing arguments
while [[ $1 != "" ]]; do
	case "$1" in
		-src) 		src_dir="${2}"
				shift
				;;
		-image) 	dest_image="${2}"
				shift
				;;
		-dest) 		dest_dir="${2}"
				shift
				;;
		*) 		usage;;
	esac
	shift
done

REF_NBD="/dev/nbd7"
REF_MNT=$(mktemp -d /tmp/dest-mnt-XXXXXX)

cleanup()
{
	echo "Cleaning up ..."
	# Unmount
	umount -R ${REF_MNT}

	# Disconnect qemu-nbd
	rmdir ${REF_MNT}
	qemu-nbd -d ${REF_NBD}
}

get_partition_number()
{
	local dev=${1}
	local code=${2^^}	# Convert to upper case

	[ -z "${dev}" ] && die "block device is unspecified."
	[ -z "${code}" ] && die "partition code is unspecified."

	sgdisk --print ${dev} | \
		grep "^ \+[0-9]\+" | \
		sed -e 's/  */ /g' | \
		cut -d ' ' -f 2,7 | \
		grep ${code} | \
		cut -d ' ' -f 1
}


if [ `id -u` -ne 0 ]; then
        echo "Must be run as root!"
        exit 1
fi

modprobe nbd max_part=8

# Connect the image files to nbd devices
qemu-nbd -c ${REF_NBD} -f qcow2 ${dest_image}

# Determine which partition on the reference image contains the rootfs
ref_linux_part=$(get_partition_number ${REF_NBD} ${LINUX_RESERVED_PART_CODE})
ref_rootfs=${REF_NBD}p${ref_linux_part}

# Mount the image files
mkdir -p ${REF_MNT}
mount ${ref_rootfs} ${REF_MNT}

# Copy files
echo "Copying ${src_dir} to ${dest_image}'s ${dest_dir} ..."
cp -rf ${src_dir} ${REF_MNT}/${dest_dir}/

echo "Exiting ..."