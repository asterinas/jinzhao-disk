# Trusted startup of Encrypted VM image

This demo consists of source, scripts, and configuration files for several tools that can be used together to demonstrate one way to perform remote attestation. It can help Guest Owner to transform his/her plain base image to a encrypted JinDisk image. And inside the folder there is a jindisksetup command can be used to manage a JinDisk-formatted partition by creating, controlling, and removing a JinDisk DM target.

The operating principle and the workflow of this demo is provided at [overview](./overview.md).

This (README) guide also covers the usage of deploying a confidential VM image from the Guest Owner's perspective. 

## Prerequisites

### Environment settings

The first thing of building a confidential computing environment is preparing a TEE-equipped host. Installation instructions for the cloud host and the Guest Owner infrastructure are outlined below. Note that for simplicity, these two servers can be the same physical machine.

We take SEV-SNP as an example. To deploy and test a confidential Guest VM using Qemu, check the [sev-snp-installation.md](../docs/sev-snp-installation.md) in the docs directory.

NOTE: For standard instructions to build SEV and SEV-ES kernels, see the main branch of the AMDSEV repository. For instructions to build SEV-SNP kernels, see the sev-snp-devel.

Once upon the boot test is done, you can use this JinDisk user-space CLI to prepare your own encrypted VM image. The aim is to fully protect the confidentiality of Guest Owner's secret data. To better understand the security rationale behind it, see [security-considerations.md](../docs/security-considerations.md) in docs.

## Usage

### Guest Disk Preparation

The scripts in [guest-owner-tool](./guest-owner-tool/) directory can be used to prepare a JinDisk-encrypted virtual machine image using an existing Qcow2 image as a base. Additionally, kernel modules such as CCP and dm-jindisk as well as other dependent software packages are to be installed into the encrypted image. 

For example, like what's provided in AMD's public [sev-guest](https://github.com/AMDESE/sev-guest) repository, we provide scripts to generate the image.

**Note that to generate JinDisk-encrypted image we recommand to use in-guest approach, which is faster and has less compatibility issues.**

To launch a reference image (a clean image that can be deployed from a Linux distribution ISO, saying Ubuntu 22.04 would be a good choice), you can use the [startup-ref.sh](./guest-owner-tool/startup-ref.sh) script to do so. Remember to set the configurations in the [env.sh](./guest-owner-tool/env.sh) before launching the guest VM, and remember to attach a blank new QCOW2 file to the reference image as the virtual disk of the new image.

Right after starting up and logging on the reference VM, you can start to prepare the JinDisk-encrypted image. In the `guest-owner-tool`  directory you can find [in-guest](./guest-owner-tool/in-guest/) directory. Here you need to install the JinDisk first.

After the JinDisk driver (kernel module) and JinDisk user-space tool are installed, you can use [assemble.sh](./guest-owner-tool/in-guest/assemble.sh) to create the new JinDisk-encrypted image.

If not specified, the output file name will be `new_image`, and the size will be DEFAULT_IMG_SIZE. If additional debian packages are listed on the command line, they will be installed into the encrypted guest image.

Once the `assemble.sh` script being executed successfully, you will see three partitions have been built on the virtual disk of the new image, aka. the `/dev/sdb`, including a boot partition, an EFI partition, and a JinDisk RootFS partition. Then, you can shutdown the reference VM (or detach the virtual disk `/dev/sdb`).

Use the [startup-new.sh](./guest-owner-tool/startup-new.sh) to launch the new encrypted image after all set.

Architectural discussions and security considerations for each example are available in the [docs](../docs/) directory. 


## Compatibility Policy

This demo has been tested on Ubuntu 20.04/22.04 as the guest OS, with Linux 5.15 and 5.17 as the guest VM's kernel. Other versions may work, but are not guaranteed.


## Future Work

Future updates to this repository will include additional examples of how to perform RA on TEE platforms like Intel TDX.
