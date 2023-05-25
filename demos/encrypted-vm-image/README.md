# Trusted startup of Encrypted VM image

This demo shows how one can start up a confidential TDVM whose TDVM image is protected with JinDisk. It provides tools that (1) can convert a plain TD virtual machine (VM) image into a JinDisk-protected one and (2) can use a JinDisk-protected VM image to start up a confidential VM. During the VM startup, a customizable process of remote attestation is triggered to fetch the root key that can unlock the JinDisk-protected VM image.

This demonstration is presently designed for Intel TDX, although it can also be executed on non-TEE environment (albeit with inferior security assurances).

## High-level Workflow

![](./workflow.jpg)

The workflow of this demo can be described as the following steps.

- Step 1: Create a JinDisk-protected TDVM image from a base image. Specifically, a new TDVM image that includes an EFI partition, a boot partition, and the most crucial one - a root partition is created. The root partition (RootFS) should be transformed into the JinDisk format using a predetermined disk encryption key. Necessary components (initramfs hooks, RA scripts, and other software dependencies) will be included into the new image to enable the subsequent guest VM startup.

- Step 2: The guest owner uses a TDX-supported Hypervisor (such as QEMU/KVM) to initiate a secure TDVM. Here, the *Guest Owner* is the client in a TDVM-based TDX environment that would like to use the confidential computing cloud.

- Step 3, 4, and 5: The hooks inside the initramfs request the attestation report and sent it to the guest owner/key server when the kernel is booted. If the verification is passed, a trusted communication channel can be built and the key to decrypt the root partition is retrieved by the TDVM. The initramfs hooks then decrypt the TDVM's root filesystem with the key.

## Step-by-step Instructions

A step-by-step guide is given here to show how the guest owner can create the JinDisk-protected TDVM image and unlock the image during startup. All commands in this guide are to be executed on the host machine if not specified otherwise.

### Environment settings

If one just intends to test the functionalities of JinDisk through this demo, this step may be skipped. However, if running the demo on a TDX machine, it is imperative to have a TDX host system in place. The TDX host system requires the installation of essential software including QEMU, OVMF, and a patched Linux kernel.

*A warning here: this demo represents the state of the art and includes patches that are certainly not deployed in distributions and may not even be upstream, so anyone follows along will need to patch things like QEMU, Grub, and OVMF as below.*

Check [Intel TDX's Linux Stack](https://cczoo.readthedocs.io/en/latest/TEE/TDX/tdxstack.html) and [Intel TDX Documents](https://cczoo.readthedocs.io/en/latest/TEE/TDX/inteltdx.html) for more details to deploy and bring up a TDVM.


### Preparing the reference image

A reference image must include the JinDisk driver and the corresponding components. 
Anyone can prepare their own customized image which includes TEE-specific kernel modules and other tailored software packages if desired. Nonetheless it is worth noting that this demo at present can only convert Ubuntu-based images.

One option is to download a pre-installed TDVM image.
For example, a TD image (equipped with JinDisk) can be downloaded via the following commands.

```bash
cd /home/jindisk
docker pull intelcczoo/encrypted-tdvm-img:jindisk
docker run -d --name "encrypted-image-demo" intelcczoo/encrypted-tdvm-img:jindisk
docker cp encrypted-image-demo:/home/td-guest-ubuntu-22.04-jindisk-img.zip .
unzip td-guest-ubuntu-22.04-jindisk-img.zip && rm td-guest-ubuntu-22.04-jindisk-img.zip
```

Or one can manually install the driver and components on a clean image from scratch using the [JinDisk kernel module installation](./in-vm/installation-scripts/install-kernel-module.sh) script and the [Jindisk user CLI installation](./in-vm/installation-scripts/install-user-cli.sh) script.


### Assembling the new JinDisk-encrypted image

Once the reference image is ready, one can assemble the new JinDisk-encrypted on different TEE platforms.

Download JinDisk source code.

```bash
mkdir -p /home/jindisk && cd /home/jindisk
git clone https://github.com/jinzhao-dev/jinzhao-disk.git
```

For TDX, certain patches need to be applied and specific commands must be utilized in order to build the new image. This step can be skipped if no TEE platform is available.

```bash
cd /home/jindisk/jinzhao-disk/
git apply demos/encrypted-vm-image/in-vm/TDX/0001-Add-TDVM-Encrypted-image-boot.patch
```

Copy the (newly patched) JinDisk source code to the reference TDVM image by following the steps below with the [copy-into-image.sh](./copy-into-image.sh) script.

```bash
cd /home/jindisk/jinzhao-disk/demos/encrypted-vm-image
./copy-into-image.sh -src /home/jindisk/jinzhao-disk -image /home/jindisk/td-guest-ubuntu-22.04-jindisk.qcow2 -dest /home/
```

*Note:* 
Please update the `IP address` of machine running `ra-server` in the file `TDX/ra-client/etc/hosts`.

Invoke the `create-jindisk-image.sh` script to create a new encrypted QCOW2 image file called `encrypted-td-guest-ubuntu-22.04.qcow2` with the `-new` option, and resize it to `60GB`. And it will boot into the reference image.

```bash
./create-jindisk-image.sh 
    -ref          /home/jindisk/td-guest-ubuntu-22.04-jindisk.qcow2 \
    -new          /home/jindisk/encrypted-td-guest-ubuntu-22.04.qcow2 \
    -size         60G
```

After booting into reference TDVM, proceed to create the encrypted TDVM image as below. 

*Note:* 
The initial user and password combination in this demo for the TDVM image is "root/123456".

```bash
cd /home/jinzhao-disk/demos/encrypted-vm-image/in-vm
./assemble.sh
```

Upon successful encryption of the image, a message - "Encrypted Image Successfully Created!" - will be displayed. Subsequently, the host should be returned and the image, named `encrypted-td-guest-ubuntu-22.04.qcow2`, should be readily accessible.


### Launching the key service

To decrypt the a non-TEE VM, the key may be found within the initramfs or provided manually by the user. Thus, the utilization of the key service is unnecessary.

Assuming the TDX Linux stack is already installed and configured correctly to support TDX remote attestation, you can launch the key service using the following command.

```bash
cd /home/jindisk/jinzhao-disk/demos/encrypted-vm-image/in-vm/TDX/ra-server
unzip ra-server.zip
http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=./roots.pem ./ra-server -host=0.0.0.0:50051 -cfg=dynamic_config.json -s=secret.json
```

*Note:*
1. The port of the remote attestation service is 50051.
2. The secret key (whose value ought to match that of `preset_key` in [assemble.sh](./in-vm/assemble.sh)) should be configured in the [secret.json](./in-vm/TDX/ra-server/secret.json) file, and can be reset by the user as necessary.

Please refer to the source code of `ra-server` [here](https://github.com/intel/confidential-computing-zoo/tree/main/cczoo/tdx-encrypted-vfs/get_secret) for more detials about the key service. 


### Launching and unlocking the JinDisk-encrypted image

One can use the [start-qemu.sh](./start-qemu.sh) script to launch a VM and to verify whether the image is created successfully.

Use the `-i` option to specify the image file. 
Use the `-t` option to specify the VM type. To launch a normal VM, one can use the `-t legacy` option. To launch a VM with a custom EFI configuration (such as a SEV secure VM), one should specify `-t efi` and use `-o` and `-a` to indicate the OVMF code and OVMF vars. The script assumes the OVMF binaries are located at `/usr/share/qemu/`.

For TDX, you should use the `-t td` option to indicate a TD will be launched with the following commands.

```bash
./start-qemu.sh \
    -i /home/jindisk/encrypted-td-guest-ubuntu-22.04.qcow2 \
    -b grub \
    -t td
```

Note that this command assumes that a QEMU executable is located at `/usr/libexec/qemu-kvm` if the TDX is enabled and TDX Linux stack is installed on the host.
Utilize the command line options `-c`, `-f`, and `-p` to specify the count of virtual CPU cores assigned, the port for SSH, and the port Telnet, respectively.

During the boot sequence, the `getting_key.sh` script within the initramfs will endeavor to establish a connection with the `ra-server`, which will subsequently receive the attestation request and proceed to authenticate the TD report. Upon successful authentication, the `opening_disk.sh` script will proceed to decrypt the encrypted rootfs utilizing the obtained key.


## Compatibility and Security

This demo has been tested on Ubuntu 20.04/22.04 as the guest VM's OS, with Linux 5.15/5.17/5.19 as the guest VM's kernel. Other versions may work but are not guaranteed.

Architectural discussions and security considerations are available in the [docs](../../docs/) directory. To better understand the rationale and security implications behind it, consult [security-considerations.md](../../docs/security-considerations.md) in docs.
