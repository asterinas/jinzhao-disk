## Prerequisites

### Environment settings

The first thing of building a confidential computing environment is preparing a TEE-equipped host. Installation instructions for the cloud host and the Guest Owner infrastructure are outlined below. Note that for simplicity, these two servers can be the same physical machine.

We take SEV-SNP as an example. To deploy and test a confidential Guest VM using Qemu, check the [sev-snp-installation.md](../docs/sev-snp-installation.md) in the docs directory.

NOTE: For standard instructions to build SEV and SEV-ES kernels, see the main branch of the AMDSEV repository. For instructions to build SEV-SNP kernels, see the sev-snp-devel.

Once upon the boot test is done, you can use this jindisk-Setup toolset to prepare your own encrypted VM image. The aim is to fully protect the confidentiality of Guest Owner's secret data. To better understand the security rationale behind it, see [security-considerations.md](../docs/security-considerations.md) in docs.

## Usage

### Guest Disk Preparation

The scripts in `guest-owner-tool` directory can be used to prepare a jindisk-encrypted virtual machine image using an existing Qcow2 image as a base. Additionally, kernel modules such as CCP and dm-jindisk as well as other dependent software packages are to be installed into the encrypted image. 

For example, like what's provided in AMD's public [sev-guest](https://github.com/AMDESE/sev-guest) repository, we provide scripts to generate the image.

**Note that to generate jindisk-encrypted image we recommand to use in-guest approach, which is faster and has less compatibility issues.**

To launch a reference image (a clean image that can be deployed from a Linux distribution ISO, saying Ubuntu 22.04 would be a good choice), you can use the `startup-ref.sh` script. Remember to set the configurations in the `env.sh` before launching the guest VM, and remember to attach a blank file to the reference image as the virtual disk of the new image.

Right after starting up and logging on the reference VM, you can start to prepare the jindisk-encrypted image. In the `guest-owner-tool` directory you can find such `in-guest` directory. Here you need to install the jindisk driver and this jindisk-Setup tool first.

After the jindisk driver and this jindisk-Setup tool are installed, you can use `assemble.sh` to create the new jindisk-encrypted image.

If not specified, the output file name will be `new_image`, and the size will be DEFAULT_IMG_SIZE. If additional debian packages are listed on the command line, they will be installed into the encrypted guest image.

Once the `assemble.sh` script being executed successfully, you will see three partitions have been built on the virtual disk of the new image, aka. the `/dev/sdb`, including a boot partition, an EFI partition, and a jindisk rootfs partition. Then, you can shutdown the reference VM (or detach the virtual disk `/dev/sdb`).

Use `startup-new.sh` to launch the new encrypted image after all set.

Architectural discussions and security considerations for each example are available in the [docs](../docs/) directory. 


## Compatibility Policy

This demo has been tested on Ubuntu 20.04/22.04 as the guest OS, with Linux 5.15 and 5.17 as the guest VM's kernel. Other versions may work, but are not guaranteed.


## Future Work

Future updates to this repository will include additional examples of how to perform RA on TEE platforms like Intel TDX.
