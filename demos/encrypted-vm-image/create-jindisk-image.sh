#!/bin/bash

CURR_DIR=$(readlink -f "$(dirname "$0")")

# Default arguments
ref_image="/home/jindisk/td-guest-ubuntu-22.04-jindisk.qcow2"
ref_image_username="root"
ref_image_password="123456"
new_image="/home/jindisk/encrypted-td-guest-ubuntu-22.04.qcow2"
new_image_size="60G"

ovmf_dir="/home/weijie/dev/demo"
ovmf_code="${ovmf_dir}/OVMF_CODE.fd"
ovmf_vars="${ovmf_dir}/OVMF_VARS.fd"

usage() {
	echo "$0 [options]"
	echo "Available <commands>:"
	echo " -ref          reference image file"
	echo " -username     reference image username"
	echo " -password     reference image password"
	echo " -new          new image file"
	echo " -size         new image size"
	exit 1
}

if [ `id -u` -ne 0 ]; then
        echo "Must be run as root!"
        exit 1
fi

# Parsing arguments
while [[ $1 != "" ]]; do
	case "$1" in
		-ref) 		ref_image="${2}"
				shift
				;;
		-username) 	ref_image_username="${2}"
				shift
				;;
		-password) 	ref_image_password="${2}"
				shift
				;;
		-new) 		new_image="${2}"
				shift
				;;
		-size) 		new_image_size="${2}"
				shift
				;;
		*) 		usage;;
	esac
	shift
done

echo "Creating a blank image ..."
sudo rm -f ${new_image}
qemu-img create -f qcow2 ${new_image} ${new_image_size}

echo "Launching the secure VM ..."
sudo ${CURR_DIR}/start-qemu.sh \
    -i ${ref_image} \
	-t efi \
    -b grub \
	-o ${ovmf_code} \
	-a ${ovmf_vars} \
	-n ${new_image}

# sleep 60s

# echo "Transforming the VM ..."
# # sudo apt install sshpass
# sshpass \
#     -p ${ref_image_password} \
#     ssh -t -p ${ssh_port} ${ref_image_username}@localhost 'bash -s' \
#     < ./assemble-in-vm.sh ${ref_image_password}
