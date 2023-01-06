# Threat Model

Trusted components:

- AMD hardware and signed firmware,
- OS software inside the target VM.

Untrusted components:

- Everything else (including other VMs),
- External devices.

Untrusted components are assumed to be malicious and may be conspiring with each other.

# Deploying Encrypted Images from Boot

In the case of confidential computing, the most basic requirement is to ensure the confidentiality of user data. If we use VM-based TEE techniques to implement a confidential computing cloud, the confidentiality of the VM's **whole life cycle** from *the deployment of a secure VM by the guest owner* to *the execution of a secure VM* must be guaranteed.

On AMD SEV and Intel TDX, the secure VM runs on an untrusted hypervisor, and the contents of its memory are encrypted, which is protected by hardware. However, when these data need to be persisted on the hard disk, its content is not protected by hardware-assisted technology.
Therefore, we need a security mechanism to protect the confidentiality of the data written on the disk.

In the current software implementation, DM-crypt (the standard device encryption module provided by the Linux kernel) or our JinDisk can provide encryption and decryption of the disk. And to a certain extent, it provides confidentiality protection. However, it is not enough to complete the security deployment of secure VMs only by relying on the functions in one kernel. If a confidential computing user wants to securely deploy his/her image on the confidential computing cloud, he/she (guest owner) needs to cooperate with the hypervisor/platform to complete a series of operations such as secure boot/remote attestation/disk encryption with the support of secure element (taking SEV as an example, here referred to as PSP firmware).

DM crypt still has some shortcomings in some aspects. So we proposed JinDisk. Similarly, it is not enough to rely solely on the JinDisk kernel module. Therefore, we propose JinDisk-setup to help solve this **Deploying Encrypted Images from Boot** problem.

# Security Requirements

To ensure that sensitive information of the secure VM is not leaked during deployment, two points should be ensured:

- The confidential information in the guest image is encrypted in advance and can be decrypted at run time
- The key for encrypting the guest image is provided by the Guest Owner (GO) and cannot be disclosed when used. 

Therefore, this requires that: 1) the data on the guest VM is encrypted before the trusted startup phase; 2) Receiving the decryption key from GO during the secure boot and RA phases; 3) Decrypting when the disk is used (mounted) after startup.

# Automatic "full" Disk Encryption from Boot

Theoretically speaking, any disk encryption tool can not achieve real **Automatic "full" Disk Encryption from Boot** without the help of external mechanisms. To start automatically, there must be a bootstrap. Yet the bootstrap cannot be encrypted at least (if the bootstrap is encrypted, it cannot be booted).

When using the JinDisk-Setup toolkit to encrypt the VM image, there are two options: one is to encrypt the partition where the root filesystem is located storing sensitive data, and not to encrypt the boot partition or the EFI partition; Second, to encrypt the root filesystem partition and also the boot partition, while only the EFI partition is not encrypted. The difference between the two options is whether to encrypt the boot partition.

Usually, the EFI partition stores the Grub EFI program, which is called by the guest OVMF. Either way, OVMF/Grub should not be tampered with, that is, their integrity must be ensured. If there is no sensitive information and confidential data in the boot partition of the guest image (that is, the boot guest VM kernel does not contain sensitive data), we can consider only encrypting the root filesystem (RootFS) and ensuring the integrity of the boot partition (when generating the launch digest, including the kernel, initrd, and cmdline into the measurement calculation). Therefore, in JinDisk-Setup, we do not encrypt the boot partition and set the decryption in a systemd service (in CentOS) or an initramfs hook (in Ubuntu) which is invoked at the early stage of kernel boot.
