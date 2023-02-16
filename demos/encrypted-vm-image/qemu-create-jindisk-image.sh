#!/bin/bash

# Default arguments
qemu_binary_dir="${HOME}/AMDSEV/usr/local/bin"
image_dir="${HOME}/dev/demo"
ref_image="${image_dir}/ubuntu-20.04-jindisk.qcow2"
ref_image_username="ref"
ref_image_password="ref"
new_image="${image_dir}/ubuntu-20.04-new-jindisk.qcow2"
new_image_size="60G"
ovmf_code="${image_dir}/OVMF_CODE.fd"
ovmf_vars="${image_dir}/OVMF_VARS.fd"
smp_num="8"
mem_size="16G"
ssh_port="10086"
vnc_port="2"

usage() {
	echo "$0 [options]"
	echo "Available <commands>:"
	echo " -qemu         QEMU to use"
	echo " -ref          reference image file"
	echo " -username     reference image username"
	echo " -password     reference image password"
	echo " -new          new image file"
	echo " -size         new image size"
	echo " -mem          guest memory"
	echo " -smp          number of cpus"
	echo " -ssh          SSH port to use"
	echo " -vnc          VNC port to use"
	echo " -uefi_code    OVMF_CODE to use"
	echo " -uefi_vars    OVMF_VARS to use"
	exit 1
}

add_opts() {
	echo -n "$* " >> ${QEMU_CMDLINE}
}

# we add all the qemu command line options into a file
QEMU_CMDLINE=/tmp/cmdline.$$
rm -rf ${QEMU_CMDLINE}

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
		-username) 		ref_image_username="${2}"
				shift
				;;
		-password) 		ref_image_password="${2}"
				shift
				;;
		-new) 		new_image="${2}"
				shift
				;;
		-size) 		new_image_size="${2}"
				shift
				;;
		-mem)  		mem_size=${2}
				shift
				;;
		-smp)		smp_num=${2}
				shift
				;;
		-ssh)		ssh_port=${2}
				shift
				;;
		-vnc)		vnc_port=${2}
				shift
				;;
		-uefi_code)	ovmf_code="`readlink -f ${2}`"
				shift
				;;
		-uefi_vars)	ovmf_vars=${2}
				shift
				;;
		*) 		usage;;
	esac
	shift
done

QEMU="${qemu_binary_dir}/qemu-system-x86_64"

CPU="-smp ${smp_num}"
MEM="-m ${mem_size}"

OVMF_CODE_PARAM="-drive if=pflash,format=raw,unit=0,file=${ovmf_code},readonly=on"
OVMF_VARS_PARAM="-drive if=pflash,format=raw,unit=1,file=${ovmf_vars}"

DISK="-drive file=${ref_image},if=none,id=disk0,format=qcow2"
NEW_DISK="-drive file=${new_image},format=qcow2,media=disk"
VIRTIO="-device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -device scsi-hd,drive=disk0"

NETSSH="-netdev user,id=unet0,hostfwd=tcp::${ssh_port}-:22 -device e1000,netdev=unet0"
VNC="-vnc :${vnc_port} -monitor pty"

# SEV="-cpu EPYC -object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 -machine memory-encryption=sev0"

if [ `id -u` -ne 0 ]; then
	echo "Must be run as root!"
	exit 1
fi

# set QEMU binary
add_opts "${QEMU} -enable-kvm -machine q35"

# add number of VCPUs
[ ! -z ${smp_num} ] && add_opts "${CPU},maxcpus=64"

# define guest memory
[ ! -z ${mem_size} ] && add_opts "${MEM},slots=5,maxmem=30G"

# set OVMF
[ ! -z ${ovmf_code} ] && add_opts "${OVMF_CODE_PARAM}"
[ ! -z ${ovmf_vars} ] && add_opts "${OVMF_VARS_PARAM}"

# set HDA
[ ! -z ${ref_image} ] && add_opts "${DISK}"
[ ! -z ${new_image} ] && add_opts "${NEW_DISK}"

# set IO
add_opts "${VIRTIO}"

# set SSH
[ ! -z ${ssh_port} ] && add_opts "${NETSSH}"

# start VNC server
[ ! -z ${vnc_port} ] && add_opts "${VNC}"

echo "Terminating the current VM ..."
qemu_pid=`lsof ${ref_image} ｜ grep qemu | awk 'END {print $2}'`
sudo kill ${qemu_pid}
sleep 1s

echo "Creating a blank image ..."
sudo rm -f ${new_image}
qemu-img create -f qcow2 ${new_image} ${new_image_size}

echo "Launching the secure VM ..."
bash ${QEMU_CMDLINE} &
sleep 30s

echo "Transforming the VM ..."
# sudo apt install sshpass
sshpass -p ${ref_image_password} ssh -t -p ${ssh_port} ${ref_image_username}@localhost 'bash -s' < ./assemble-in-vm.sh ${ref_image_password}

