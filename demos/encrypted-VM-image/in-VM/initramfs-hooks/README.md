### Initramfs hooks

To start up the encrypted VM, namely to unlock the root partition (RootFS) of the the encrypted VM image, we should insert certain programs/hooks to decrypt the RootFS during the kernel boot process. We choose to deploy hooks into the initramfs of the VM image. This initramfs also contains a minimal version of jindisksetup, which is used to unlock the encrypted RootFS partition. When the kernel starts, it will first invoke the initramfs scripts to decrypt the RootFS before mounting it to the root file system. In this way, the RootFS will be decrypted and accessible automatically.

Initramfs hook is an early-stage service (in the guest kernel's initramfs image) we developed for decrypting the root partition when the guest kernel is loaded. This hook can be set to execute decryption after fstab mount. 

We implement the initramfs hooks with Ubuntu's [initramfs-tools](https://manpages.ubuntu.com/manpages/xenial/en/man8/initramfs-tools.8.html). 
They provide an easy way to implement initramfs hooks. The easiest way to create an initramfs hook is to modify the `scripts/init-premount/` directory inside the initramfs-tools package.