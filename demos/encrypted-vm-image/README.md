# Trusted startup of Encrypted VM image

This demo shows how one can start up a [confidential virtual machine (CVM)](https://cloud.google.com/compute/confidential-vm/docs/about-cvm) whose VM image is protected with JinDisk. It provides tools that (1) can convert a plain virtual machine (VM) image into a JinDisk-protected one and (2) can use a JinDisk-protected VM image to start up a confidential VM. During the VM startup, a customizable process of remote attestation is triggered to fetch the root key that can unlock the JinDisk-protected VM image.

This demo is intended for TEE VMs, including Intel TDX and AMD SEV, although it is also runnable on non-TEE VMs (with weaker security guarantees, of course).

## High-level Workflow

![](./workflow.jpeg)

The workflow of this demo can be described as the following steps.

- Step 1: Create a JinDisk-protected VM image from a base image. Specifically, a new VM image that includes an EFI partition, a boot partition, and the most crucial one - a root partition is created. The root partition (RootFS) should be transformed into the JinDisk format using a predetermined disk encryption key. Necessary components (initramfs hooks, RA scripts, and other software dependencies) will be included into the new image to enable the subsequent guest VM startup.

- Step 2: The guest owner uses a TEE-supported Hypervisor (such as QEMU/KVM) to initiate a secure VM. Here, the *Guest Owner* is the client in a VM-based TEE environment that would like to use the confidential computing cloud.

- Step 3, 4, and 5: The hooks inside the initramfs request the attestation report and sent it to the guest owner/key server when the kernel is booted. If the verification is passed, a trusted communication channel can be built and the key to decrypt the root partition is retrieved by the guest VM. The initramfs hooks then decrypt the guest VM's root filesystem with the key.

## Step-by-step Instructions

A step-by-step guide is given here to show how the guest owner can create the JinDisk-protected image and unlock the image during startup. All commands in this guide are to be executed on the host machine if not specified otherwise.

### Environment settings

If one just intends to test the functionalities of JinDisk through this demo, this step may be skipped. However, if running the demo on a TDX or an SEV-SNP machine, it is imperative to have a TEE host system in place. The TEE host system requires the installation of essential software including QEMU, OVMF, and a patched Linux kernel.

*A warning here: this demo represents the state of the art and includes patches that are certainly not deployed in distributions and may not even be upstream, so anyone follows along will need to patch things like QEMU, Grub, and OVMF as below.*

Check [Intel TDX's manual](xxxxx) and [AMD SEV-SNP's Github repository](https://github.com/AMDESE/AMDSEV/tree/sev-snp-devel) for more details to deploy and bring up a confidential guest VM.


### Preparing the reference image

A reference image must include the JinDisk driver and the corresponding components. 
Anyone can prepare their own customized image which includes TEE-specific kernel modules and other tailored software packages if desired. Nonetheless it is worth noting that this demo at present can only convert Ubuntu-based images.

One option is to download a pre-installed VM image.
For example, a TD image (equipped with JinDisk) can be downloaded via the following commands.

```bash
cd ~
docker pull xxx/xxxx:xxxxx
docker run -d --name "encrypted-image-demo" xxx/xxxx:xxxxx
docker cp encrypted-image-demo:<path-to-the-image> .
```

Or one can munually install the driver and components on a clean image from scratch using the [JinDisk kernel module installation](./in-vm/installation-scripts/install-kernel-module.sh) script and the [Jindisk user CLI installation](./in-vm/installation-scripts/install-user-cli.sh) script.


### Assembling the new JinDisk-encrypted image

Once the reference image is ready, one can assemble the new JinDisk-encrypted on different TEE platforms.

For TDX, you should apply certain patches and use the following commands to build the new image.

*Todo: add TDX's patches*


For non-TEE or AMD SEV-SNP environment, the [qemu-create-jindisk-image.sh](./qemu-create-jindisk-image.sh) script can be used to create the new JinDisk-encrypted image using the above-mentioned reference image as a base. Encrypted partitions will be created and initramfs hooks will be placed.

Invoke the `qemu-create-jindisk-image.sh` script to create a new QCOW2 image file called `ubuntu-20.04-new-jindisk.qcow2` with the `-new` option, and resize it to `60GB`.
Note that this command assumes that a QEMU executable is located at `~/AMDSEV/snp-release-<DATE>/usr/local/bin/qemu-system-x86_64` if the AMD SEV-SNP is enabled on the host. Feel free to change it to a customized version if necessary.

```bash
sudo ./qemu-create-jindisk-image.sh 
    -qemu         ~/AMDSEV/snp-release-<DATE>/usr/local/bin/qemu-system-x86_64 \
    -ref          ~/ubuntu-20.04-jinzhao-disk.qcow2 \
    -new          ~/ubuntu-20.04-new-jinzhao-disk.qcow2 \
    -size         60G
```

### Launching the attestation/key service

To decrypt a non-TEE VM, the key can be located at the initramfs or can be input by the user manually. Therefore, the service is not required.

In TDX, the service
*Todo: add TDX's Attestation service*


### Launching the new VM and unlocking the JinDisk-encrypted image

In a non-TEE environment, one can use the [qemu-launch-secure-vm.sh](./qemu-launch-secure-vm.sh) script to launch a secure VM and to verify whether the image is created successfully.
Use the `-hda` option to specify the image file. The command assumes the OVMF is located at `~/AMDSEV/snp-release-<DATE>/usr/local/share/qemu/`. Use `-tee` to specify which TEE guest is expected to be launched. For example in the following command, the last argument `-tee sev` will force the QEMU to start up an SEV guest VM. A normal VM will be launched if the `-tee` option is not specified.
Utilize the command line options `-mem`, `-smp`, `-ssh`, and `-vnc` to specify the virtual machine's allocated memory capacity, count of virtual CPU cores assigned, as well as the respective ports for SSH and VNC communication channels.


```bash
sudo ./qemu-launch-secure-vm.sh \
    -qemu         ~/AMDSEV/snp-release-<DATE>/usr/local/bin/qemu-system-x86_64 \
    -hda          ubuntu-20.04-new-jinzhao-disk.qcow2 \
    -mem          8 \
    -smp          16G \
    -ssh          10086 \
    -vnc          1 \
    -uefi_code    ~/AMDSEV/snp-release-<DATE>/usr/local/share/qemu/OVMF_CODE.fd \
    -uefi_vars    ~/AMDSEV/snp-release-<DATE>/usr/local/share/qemu/OVMF_VARS.fd \
    -tee sev
```

For TDX,

*Todo: add TD's the launch script*
```bash
sudo ./start-qemu \
    -i      xxx.qcow2
```







If the instructions have been followed correctly, a JinDisk-formatted block device mounted as the RootFS can be listed by the `lsblk` command running inside the VM.


## Compatibility and Security

This demo has been tested on Ubuntu 20.04/22.04 as the guest VM's OS, with Linux 5.15/5.17/5.19 as the guest VM's kernel. Other versions may work but are not guaranteed.

Architectural discussions and security considerations are available in the [docs](../../docs/) directory. To better understand the rationale and security implications behind it, consult [security-considerations.md](../../docs/security-considerations.md) in docs.
