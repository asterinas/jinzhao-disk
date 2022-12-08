#!/bin/bash

. ./env.sh

OVMF_CODE_PARAM="-drive if=pflash,format=raw,unit=0,file=${OVMF_CODE},readonly=on"
OVMF_VARS_PARAM="-drive if=pflash,format=raw,unit=1,file=${OVMF_VARS}"

NEW_DISK="-drive file=${new_image},if=none,id=disk0,format=qcow2"
VIRTIO="-device virtio-scsi-pci,id=scsi,disable-legacy=on,iommu_platform=true -device scsi-hd,drive=disk0"

NETSSH="-netdev user,id=unet0,hostfwd=tcp::10086-:22 -device e1000,netdev=unet0"

# SEV="-object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1 -machine memory-encryption=sev0"

VNC="-vnc :2 -monitor pty"

sudo ${QEMU} \
	-enable-kvm -machine q35 \
	${CPU} \
	${MEM} \
	${OVMF_CODE_PARAM} \
	${OVMF_VARS_PARAM} \
	${NEW_DISK} \
	${VIRTIO} \
	${NETSSH} \
	${SEV} \
	${VNC}

