### Inner Workings of the Initramfs Hooks

The initramfs hooks are an early-stage service (in the guest kernel's initramfs image) developed for decrypting the root partition when the guest kernel is loaded.

To start up the encrypted VM, namely to unlock the root partition (RootFS) of the the encrypted VM image, certain programs/hooks are inserted to decrypt the RootFS during the kernel boot process. This initramfs also contains the `jindisksetup` CLI and the `dm-jindisk` kernel module, which are used to unlock the encrypted RootFS partition. When the kernel starts, it will first invoke the initramfs scripts to decrypt the RootFS before mounting it to the root file system. In this way, the RootFS will be decrypted and accessible automatically.

To install the JinDisk (the `jindisksetup` binaries and the `dm-jindisk` kernel module) in the initramfs, simply run the [install-user-cli.sh](./install-user-cli.sh) and the [install-kernel-module.sh](./install-kernel-module.sh) inside a guest VM.

The initramfs hooks are implemented using Ubuntu's [initramfs-tools](https://manpages.ubuntu.com/manpages/xenial/en/man8/initramfs-tools.8.html). 
The tools provide an easy way to write initramfs hooks. For example, the hooks in the `scripts/init-premount/` directory happens after modules specified by the `/etc/initramfs-tools/modules` hooks have been loaded. To this end, an unlocking script can be called right after the `dm-jindisk` module is loaded in the initramfs.