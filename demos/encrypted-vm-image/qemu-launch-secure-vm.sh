#!/bin/bash

# Default arguments
home="/home/weijie"
qemu_binary_dir="${home}/AMDSEV/usr/local/bin"
image_dir="${home}/dev/demo"
image="${image_dir}/ubuntu-20.04-jindisk.qcow2"
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
	echo " -hda          guest disk file"
	echo " -mem          guest memory"
	echo " -smp          number of cpus"
	echo " -ssh          SSH port to use"
	echo " -vnc          VNC port to use"
	echo " -uefi_code    OVMF_CODE to use"
	echo " -uefi_vars    OVMF_VARS to use"
	echo " -tee          VM-based TEE to use, SEV-SNP or TDX"
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

while [[ $1 != "" ]]; do
	case "$1" in
		-hda) 		image="${2}"
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
		-tee)		tee_option=${2}
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

DISK="-drive file=${image},if=none,id=disk0,format=qcow2"
VIRTIO="-device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -device scsi-hd,drive=disk0"

NETSSH="-netdev user,id=unet0,hostfwd=tcp::${ssh_port}-:22 -device e1000,netdev=unet0"
VNC="-vnc :${vnc_port} -monitor pty"

SEV_SNP="-cpu EPYC -object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 -machine memory-encryption=sev0"
# TODO
TDX=""

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
# [ ! -z ${ovmf_vars} ] && add_opts "${OVMF_VARS_PARAM}"

# set HDA
[ ! -z ${image} ] && add_opts "${DISK}"

# set IO
add_opts "${VIRTIO}"

# set SSH
[ ! -z ${ssh_port} ] && add_opts "${NETSSH}" && echo "Starting SSH on port ${ssh_port}"

# start VNC server
[ ! -z ${vnc_port} ] && add_opts "${VNC}" && echo "Starting VNC on port ${vnc_port}"

# If this is a TEE-specific guest, add the encryption device objects to enable respective supports
if [[ ${tee_option} == "sev" ]]; then
	echo "Starting up an SEV guest"
	add_opts "${SEV_SNP}"
elif [[ ${tee_option} == "tdx" ]]; then
	echo "Starting up a TDX guest"
	add_opts "${TDX}"
else
	echo "No TEE speficied"
	add_opts ""
fi

echo "Terminating the current VM ..."
qemu_pid=`lsof ${image} | awk 'END {print $2}'`
sudo kill ${qemu_pid}
sleep 1s

echo "Launching secure VM ..."
cat ${QEMU_CMDLINE}
echo ""
bash ${QEMU_CMDLINE} &

