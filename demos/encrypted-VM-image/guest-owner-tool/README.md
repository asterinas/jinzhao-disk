## Jindisk Guest-Owner-Tool Usage

### Reference Image Preparation

First, prepare a clean Guest VM. We suggest using an Ubuntu 22.04 that has been tested.

```bash
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.1-desktop-amd64.iso
```

A 50+ GB disk image is preferred since we need to re-compile the kernel in the guest from Linux source code.

```bash
qemu-img create -f qcow2 ubuntu-22.04-sworndisk.qcow2 50G
```

Then, launch the VM, using the downloaded ISO to boot the VM at the first time.

Here we take SEV-SNP as the example to explain the image preparation procedures. Therefore to launch a SEV-SNP guest, a QEMU argument has to be added: `-object sev-guest,id=sev0,cbitpos=51,reduced-phys-bits=1`. Note that the params for SEV passed to the QEMU should be different from the ones on Intel TDX hosts. So, it's recommended that you use your own QEMU binary and your own path to the OVMF_CODE/OVMF_VARS (virtual firmwares). Remember to set those environment variables in [env.sh](./env.sh).

After setting environment variables, you can use [startup-ref.sh](./startup-ref.sh) to start up the guest. Feel free to modify this bash script to costomize your own VM.
You can use Vncviewer to connect the image (or via ssh). 

After the Ubuntu has been installed, restart the guest. This time remove the `-boot dc` argument and detach the ISO drive.

### Jindisk Installation

The second step is to install Jindisk kernel module and Jindisk setup tool on the Guest VM. You can find build instructions in the [In-guest Installation Guide](in-guest/README.md).

You may have to reinstall the Linux kernel when installing Jindisk kernel module. Refer to its [README](../../kernel-module/c/README.md) for more details.

### Jindisk Image preparation

After the kernel module and the setup tool are installed, you can prepare a Jindisk-encrypted guest image with the [assemble script](in-guest/assemble.sh) automatically.

### Launching a Jindisk-encrypted Guest

Once you've done all the above-mentioned preparation, the last step is to startup the new image. Use [startup-new.sh](./startup-new.sh) to do so.