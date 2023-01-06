# SEV Installation Guide

## SEV Enablement

### Hardware checking

Make sure to allocate enough ASIDs for SEV-SNP guests:
https://github.com/AMDESE/AMDSEV/issues/84

```
# dmesg | grep -i -e rmp -e sev
SEV-SNP: RMP table physical address 0x0000000035600000 - 0x0000000075bfffff
ccp 0000:23:00.1: sev enabled
ccp 0000:23:00.1: SEV-SNP API:1.51 build:1
SEV supported: 410 ASIDs
SEV-ES and SEV-SNP supported: 99 ASIDs
# cat /sys/module/kvm_amd/parameters/sev
Y
# cat /sys/module/kvm_amd/parameters/sev_es 
Y
# cat /sys/module/kvm_amd/parameters/sev_snp 
Y
```

### Firmware support

Make sure the firmware version >= 1.51. If you see the following message, update the firmware.

```
[    6.367999] ccp 0000:46:00.1: sev enabled
[    6.381981] ccp 0000:46:00.1: SEV-SNP support requires firmware version >= 1:51
[    6.399721] ccp 0000:46:00.1: SEV: failed to INIT error 0x1
[    6.400343] ccp 0000:46:00.1: SEV API:1.40 build:40
```

The steps to update the firmware are as follows.

```
# wget https://developer.amd.com/wp-content/resources/amd_sev_fam19h_model0xh_1.33.03.zip
# unzip amd_sev_fam19h_model0xh_1.33.03.zip
# mkdir -p /lib/firmware/amd
# cp amd_sev_fam19h_model0xh_1.33.03.sbin /lib/firmware/amd/amd_sev_fam19h_model0xh.sbin
```

Reboot and install necessary kernel modules.

```
# rmmod kvm_amd
# rmmod ccp
# modprobe ccp
# modprobe kvm_amd
```

## Software Dependencies

### Hypervisor (Linux KVM and Qemu)

KVM is the kernel-mode component of the KVM-Qemu hypervisor on Linux and makes use of the virtualization instructions of modern x86 processors.
Specifically, the `kvm_amd.ko` and `ccp.ko` Linux kernel modules are needed. The `ccp.ko` module can optionally store the VCEK certificate for the platform along with the certificate chain necessary to validate the VCEK certificate.

Qemu should be updated to the latest version.

Installation guide:
https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel#build


### OVMF

The aim is to build the following.

```
Build/Ovmf3264/DEBUG_GCC5/FV/OVMF_CODE.fd
Build/Ovmf3264/DEBUG_GCC5/FV/OVMF_VARS.fd
```

To install edk2, you should first install the following packages:
`lib32z1 nasm python uuid-dev iasl python libssl-dev libelf-dev flex bison`

The version of edk2 should be selected carefully:
https://github.com/AMDESE/AMDSEV/issues/83


## SEV VM Boot

Before booting a SEV-SNP guest, you should install some necessary kernel packages:
https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel#prepare-guest

Boot a SEV-SNP guest:
https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel#launch-snp-guest
