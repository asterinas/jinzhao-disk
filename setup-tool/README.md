# Jindisk-Setup

Jindisk-Setup is a utility (set) used to conveniently set up disk encryption based on the our newly-proposed secure I/O solution for TEEs - jindisk.

It can help Guest Owner to transform his/her plain base image to a encrypted jindisk image. And inside the repo there is a jindisksetup command can be used to manage a jindisk-formatted partition by creating, controlling, and removing a jindisk DM target.

Jindisk-Setup is a part of the whole Jindisk-Linux project (the other part is dm-jindisk).

This repository contains source, scripts, and configuration files for several tools that can be used together to demonstrate one way to perform remote attestation.

This (README) guide also covers the usage and configuration of deploying a confidential VM image from the Guest Owner's perspective. 


## Prerequisites

### Environment settings

The first thing of building a confidential computing environment is preparing a TEE-equipped host. Installation instructions for the cloud host and the Guest Owner infrastructure are outlined below. Note that for simplicity, these two servers can be the same physical machine.

We take SEV-SNP as an example. To deploy and test a confidential Guest VM using Qemu, check the [sev-snp-installation.md](../docs/sev-snp-installation.md) in the docs directory.

NOTE: For standard instructions to build SEV and SEV-ES kernels, see the main branch of the AMDSEV repository. For instructions to build SEV-SNP kernels, see the sev-snp-devel.

Once upon the boot test is done, you can use this jindisk-Setup toolset to prepare your own encrypted VM image. The aim is to fully protect the confidentiality of Guest Owner's secret data. To better understand the security rationale behind it, see [security-considerations.md](../docs/security-considerations.md) in docs.

### Software dependencies

Here is the list of packages needed for the compilation of project for particular distributions:

- For Debian and Ubuntu: `git gcc make autoconf automake autopoint pkg-config libtool gettext libssl-dev libdevmapper-dev libpopt-dev uuid-dev libssh-dev`. To run the internal testsuite you also need to install `sharutils dmsetup jq xxd expect keyutils netcat passwd openssh-client sshpass`.

Note that the list could change as the distributions evolve.

### JinDisk-Setup Installation

We prepare scripts in `guest-owner-tool/in-guest` to help installing the jindisk Driver and this jindisk-Setup command line tool.

Download JinDisk source code and install setup CLI using the bash script - `guest-owner-tool/in-guest/install-setup.sh`.

```
$ git clone git@github.com:jinzhao-dev/jindisk-linux.git
$ cd jindisk-linux/setup-tool/guest-owner-tool/in-guest/
$ sudo ./install-setup ../../src/
```

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

### jindisksetup - a user space tool

jindisksetup is the command line tool for creating, accessing and managing encrypted jindisk devices. Just like dm-jindisk is an alternative of dm-crypt, jindisksetup is as a counterpart to cryptsetup. This section covers how to utilize dm-jindisk from the command line to encrypt a system.

For example, you can use `jindisksetup` to create a device mapper target. The tool will be used as follows:

```
$ jindisksetup action (device) dmname
```

The action can be **create** **open** and **close**.

- jindisksetup **create** *key* *device* *dm_name* - creating and formatting the jindisk partition using the key

For example, the following creates a root jindisk partition `/dev/sda1` and maps it to device mapper named `test-jindisk`:

```
$ jindisksetup create password /dev/sda1 test-jindisk
```

- jindisksetup **open** *key* *device* *dm_name* - unlocking the jindisk partition using the key

For example, the following unlocks a root jindisk partition `/dev/sda1` and maps it to device mapper named `test-jindisk`:

```
$ jindisksetup open password /dev/sda1 test-jindisk
```

Once opened, the `test-jindisk` device path would be `/dev/mapper/test-jindisk` instead of the partition (e.g. `/dev/sda1`).

**Note that we support to use both ways (jindisksetup/dmsetup) to manipulate dm-jindisk.** Refer to [interfaces.md](../docs/interfaces.md) for more details.

---

In order to write encrypted data into the partition it must be accessed through the device mapped name. The first step of access will typically be to create a file system. For example:

```
$ mkfs -t ext4 /dev/mapper/test-jindisk
```

- jindisksetup **close** *dm_name* - closing the jindisk target, unmount the partition and do close

For example:

```
$ jindisksetup close test-jindisk
```


## Documentation

The docs directory consists of useful manuals related to this toolset, including installation guide for users and implementation details for developers.

Architectural discussions and security considerations for each example are also available in the `docs` directory. 


## Compatibility Policy

jindisk-setup supports Ubuntu 20.04/22.04 as the guest OS, and supports Linux 5.15 and 5.17 as the guest VM's kernel. Other versions may work, but are not guaranteed.


## Future Work

Future updates to this repository will include additional examples of how to perform RA on TEE platforms like Intel TDX.


## Resources

[SEV-SNP Attestation Examples](https://github.com/AMDESE/sev-guest)
