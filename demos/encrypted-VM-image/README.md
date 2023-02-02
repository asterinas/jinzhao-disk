# Trusted startup of Encrypted VM image

This demo consists of source, scripts, and configuration files that can be used together to demonstrate how we can boot up a confidential virtual machine (VM) whose VM image protected with JinDisk. It can help the user of a confidential computing cloud to transform his/her base image to a encrypted JinDisk image. And scripts are designed for the guest user to build a confidential VM image and to start up the confidential VM automatically.

We first describe the [components](#1) that this demo needs.

We then show the [general workflow](#2) of deploying a confidential VM image from the Guest Owner's perspective. Here, the *Guest Owner (GO)* is the client in a VM-based TEE environment that would like to use the confidential computing cloud.

Finally, we give a [step-by-step guide](#3) to show how the Guest Owner can prepare the encrypted image.

---

<h2 id="1"> Components </h2>

The demo depends on several components. 
The first one is the `jindisksetup` command line tool used to conveniently set up the `dm-jindisk` kernel module, which works as a device mapper and provides transparent encryption of block devices. 
Secondly, we need an initramfs hook that can be called to decrypt the encrypted image when the guest VM is booted. 
The third one is the remote attestation part that finishes the key exchange.

### JinDisk user CLI and JinDisk kernel module

The `jindisksetup` is the command line interface for creating, accessing, and managing encrypted JinDisk devices.

In this demo, we use the CLI and the kernel module to format a blank disk to an encrypted disk.

### Initramfs hooks

To start up the encrypted VM automatically, namely to unlock the root partition (RootFS) of the the encrypted VM image, we should insert certain programs to decrypt the RootFS during the kernel boot process. We choose to deploy hooks into the initramfs of the VM image. Those hooks can be invoked after the kernel is initialized before the RootFS is mounted.

Initramfs hook is an early-stage service (in the guest kernel's initramfs image) we developed for decrypting the root partition when the guest kernel is loaded. This hook can be set to execute decryption after fstab mount. The key to decrypt the root partition is retrieved from the RA (Remote Attestation) protocol.

### Remote attestation procedure (TODO)

Remote attestation is necessary to let the confidential computing cloud user to trust the code running on a remote cloud.
The RA procedure will perform a key exchange between the guest kernel and the guest owner.

Note that the RA procedure can be implemented as a pluggable module according to corresponding RA protocols.
RA procedures can be integrated into JinDisk-Setup by replacing different RA implementations lying in the initramfs hooks (or any early-stage systemd services). To integrate RA more conveniently, the sub-procedure of retrieving the attestation reports/certificates and the sub-procedure of how disk encryption/decryption key is exchanged can be implemented modularly and separately. 

---

<h2 id="2"> High-level Workflow </h2>

The following diagram shows the high-level workflow and component relationships.

![](./workflow.jpeg)

The workflow of this demo can be described as five steps.

- Step 1: We use scripts for the guest owner to generate a protected guest image from a base image. 

- Step 2: The GO uses QEMU/KVM to launch a secure VM.

- Step 3: The initramfs hook requests the attestation report when the kernel is booted.

- Step 4: The initramfs hook sends the attestation report to GO and gets back the disk encryption/decryption key.

- Step 5: The initramfs hook decrypts guest VM's root filesystem with the disk encryption/decryption key.

### Guest Owner setup

This is the Step 1 - guest disk encryption. Specifically, we prepare image and put an encrypted (JinDisk-formatted) partition into it.

The first thing is to create a new image, which includes an EFI partition, a boot partition and the most important - a root partition. To protect the root partition, the guest owner tool will then encrypt it using JinDisk's data encryption scheme. The encryption key should be stored in a safe place and be managed properly. The tool will also set up necessary execution enviroment for later Guest Disk Unlocking and the component (the initramfs hook) to do it.

After that, GO can launch the secure VM through a TEE-supported Hypervisor (such as QEMU). The Hypervisor will help calculating the measurement of the guest VM's kernel and reported to GO, to ensure that GO is launching an expected VM image.

### Guest VM setup

To fully set up a confidential VM is not easy. It involves complex encryption complicated among multiple parties. Unlocking the RootFS of the guest's VM image is the main goal of the initramfs hook. But, before unlocking the root filesystem, the root partition should be mounted automatically during the kernel boot.

Then, initramfs hook invokes the functions in the `jindisksetup`, to open the JinDisk-formatted root partition.

### Portable RA

Various remote attestation protocols can be integrated into this JinDisk-Setup project.

Here we first brief how JinDisk-Setup works with RA. For example in SEV-SNP, a guest VM can makes use of the proposed SEV-SNP support to obtain an attestation report via the `sevguest.ko` and `ccp.ko`  kernel modules ([CCP](https://lwn.net/Articles/735732/)). The `ccp.ko` module can optionally store the VCEK certificate for the platform along with the certificate chain necessary to validate the VCEK certificate.  This guest kernel driver is responsible for sending the `SNP_GUEST_REQUEST` message to the ASP firmware and presenting the reply back to user space.

 The attestation report can then be sent to the Guest Owner.

The Guest Owner can retrieve the certificate chain necessary to validate the attestation report signature. If the verification is passed, a trusted communication channel then can be built.

Later the disk encryption key can be transmitted to the guest VM via the trusted channel.

This procedure can be portable as long as the Step 3 and Step 4 are modular. Intel TDX also uses such similar measurement hash (like SEV's attestation report) for GO to verify, so the Step 3 can be replaced with retrieving any other corresponding certificates. And Step 4 can be implemented as a protocol like RA-TLS. In this case, the establishment of secure channel could be standard and portable.

---

<h2 id="3"> Step-by-step Workflow </h2>

Here, we give step-by-step instructions to show how we can prepare the JinDisk-encrypted image and launch it.

### Environment settings

Preparing a TEE-equipped host is the prerequisite.

We take SEV-SNP as an example. To deploy and test a confidential Guest VM using QEMU, check the [sev-snp-installation.md](../../docs/sev-snp-installation.md) in the docs directory.

NOTE: For standard instructions to build SEV and SEV-ES kernels, check the main branch of the AMDSEV repository please. For instructions to build SEV-SNP kernels, see the `sev-snp-devel` branch.

Once upon the boot test is done, you can use the following steps to prepare your own encrypted VM image. The aim is to fully protect the confidentiality of Guest Owner's secret data. To better understand the security rationale behind it, see [security-considerations.md](../../docs/security-considerations.md) in docs.

### Blank (Reference) Disk Preparation (out-of-VM)

The scripts in [out-of-VM](./out-of-VM/) directory can be used to prepare a blank Qcow2 image as a base. Kernel modules such as CCP and dm-jindisk as well as other dependent software packages can be installed into the image later. 

First, prepare a clean Guest VM. We suggest using an Ubuntu 22.04 that has been tested.

```bash
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.1-desktop-amd64.iso
```

A 50+ GB disk image is preferred since we might need to re-compile the kernel in the guest from Linux source code.

```bash
qemu-img create -f qcow2 ubuntu-22.04-ref.qcow2 50G
```

Then, install the guest VM using the downloaded ISO. Refer to the [official manual](https://ubuntu.com/server/docs/installation) for more details.
After the Ubuntu has been installed, restart the guest VM and check whether the installation is successful. This time remove the `-boot dc` argument and detach the ISO drive.


After setting environment variables, you can launch the reference image (the clean image that is deployed from the Ubuntu ISO), you can use the [startup-ref.sh](./out-of-VM/startup-ref.sh) script to do so.
Feel free to modify this bash script to costomize your own VM. 
Remember to set the configurations in the [env.sh](./out-of-VM/env.sh) and the `startup-ref.sh` before launching the guest VM. 
Since we take SEV-SNP as the example to explain the image preparation procedures, therefore to launch a SEV-SNP guest, a QEMU argument has to be added: `-object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1`. Note that the params for SEV passed to the QEMU should be different from the ones on Intel TDX hosts. So, it's recommended that you use your own QEMU binary and your own path to the `OVMF_CODE`/`OVMF_VARS` (virtual firmwares). 

You can use Vncviewer to connect the guest VM (or via ssh). 


### JinDisk Installation (in-VM)

Right after starting up and logging on the reference VM, you need to install the JinDisk (the `jindisksetup` binaries and the `dm-jindisk` kernel module) in the initramfs first. **So, this step should be executed inside the VM.** To do that, simply run the [install-user-cli.sh](./in-VM/setup-scripts/install-user-cli.sh) and the [install-kernel-module.sh](./in-VM/setup-scripts/install-kernel-module.sh).

You may have to reinstall the Linux kernel when installing JinDisk kernel module. Refer to its [README](../../kernel-module/c/README.md) for more details. And you can also refer to the [README](../../user-cli/README.md) for the installation of JinDisk user-space CLI.


### Buiding the new JinDisk image (in-VM)

**Note that we recommand to use an in-VM approach to generate JinDisk-encrypted image, which is faster than generating it on a non-virtualized host (just like what the [official SEV-SNP end-to-end remote attestation example](https://github.com/AMDESE/sev-guest) does). Also, the in-VM way has less compatibility issues.**

After the kernel module and JinDisk user-space tool are installed and the initramfs hooks are placed, you can start to prepare the JinDisk-encrypted image. In the [in-VM](./in-VM/) directory, which stores the scripts that should be running inside a VM, you can use the [assemble.sh](./in-VM/assemble.sh) to create the new JinDisk-encrypted image.

If not specified, the output file name will be `new_image`, and the size will be `DEFAULT_IMG_SIZE` which can be set in the [env.sh](./out-of-VM/env.sh). 

Once the `assemble.sh` script being executed successfully, you will see three partitions have been built on the virtual disk (`/dev/sdb`) of the new image, including a boot partition, an EFI partition, and a JinDisk RootFS partition. Then, you can shutdown the reference VM (or detach the virtual disk `/dev/sdb`) for launching the newly-created image later.

### Launching the new JinDisk-encrypted guest image (out-of-VM)

Once you've done all the above-mentioned preparation, the last step is to start up the new image. Use [startup-new.sh](./out-of-VM/startup-new.sh) to do so.

When using the `startup-new.sh`, remember to set the [env.sh](./out-of-VM/env.sh) and attach the blank new Qcow2 file (e.g., `ubuntu-22.04-new.qcow2`) as the virtual disk of the new image.


## Compatibility and Security

This demo has been tested on Ubuntu 20.04/22.04 as the guest OS, with Linux 5.15 and 5.17 as the guest VM's kernel. Other versions may work, but are not guaranteed.

Architectural discussions and security considerations are available in the [docs](../../docs/) directory. 


## Future Work

Future updates to this repository will include additional examples of how to perform RA on TEE platforms like Intel TDX.
