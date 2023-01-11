#!/bin/bash
#
#
# Assume we already have a JinDisk-installed image

set -e

trap cleanup ERR EXIT

preset_key="2333"

new_img_dev=/dev/sdb

BOOT_PART_NR="1"
BOOT_PART_NAME="boot"
BOOT_PART_LABEL="${BOOT_PART_NAME}"

EFI_PART_NR="2"
EFI_PART_NAME="UEFI"
EFI_PART_LABEL="${EFI_PART_NAME}"

jindisk_PART_NR="3"
jindisk_PART_NAME="jindisk-rootfs"
jindisk_PART_LABEL="${jindisk_PART_NAME}"
jindisk_DM_NAME="${jindisk_PART_NAME}"

boot_partition=${new_img_dev}${BOOT_PART_NR}
efi_partition=${new_img_dev}${EFI_PART_NR}
jindisk_partition=${new_img_dev}${jindisk_PART_NR}

ref_rootfs=/dev/sda2

jindisk_MNT=$(mktemp -d /tmp/jindisk-mnt-XXXXXX)

initramfs_hook_dir=../../initramfs-hook-ubuntu

cleanup()
{
    echo "Cleaning up..."

    # Unmount filesystems
    if mount | grep ${jindisk_MNT} > /dev/nul 2>&1; then
        umount -R ${jindisk_MNT}
        rmdir ${jindisk_MNT}
    fi

    # Close the jindisk device
    [ -a /dev/mapper/jindisk_rootfs ] && dmsetup remove jindisk_rootfs
}

create_disk_partitions()
{
        local dev=${1}

        [ -z "${dev}" ] && die "disk device unspecified"

        sgdisk --zap-all ${dev}

        sgdisk --new=${BOOT_PART_NR}:0:+1024M ${dev}     # /boot
        sgdisk --typecode=${BOOT_PART_NR}:8301 ${dev}   # type = Linux reserved
        sgdisk --change-name=${BOOT_PART_NAME}:${BOOT_PART_NAME} ${dev}

        sgdisk --new=${EFI_PART_NR}:0:+512M ${dev}              # /boot/efi
        sgdisk --typecode=${EFI_PART_NR}:ef00 ${dev}    # type = EFI System Partition
        sgdisk --change-name=${EFI_PART_NR}:${EFI_PART_NAME} ${dev}

        sgdisk --new=${jindisk_PART_NR}:0:0 ${dev}            # /
        sgdisk --typecode=${jindisk_PART_NR}:8309 ${dev}      # type = Linux LUKS
        sgdisk --change-name=${jindisk_PART_NR}:${jindisk_PART_NAME} ${dev}
}

get_partition_number()
{
    local dev=${1}
    local code=${2^^}   # Convert to upper case

    [ -z "${dev}" ] && die "block device is unspecified."
    [ -z "${code}" ] && die "partition code is unspecified."

    sgdisk --print ${dev} | \
        grep "^ \+[0-9]\+" | \
        sed -e 's/  */ /g' | \
        cut -d ' ' -f 2,7 | \
        grep ${code} | \
        cut -d ' ' -f 1
}

add_fstab_entry()
{
    local fstab=${1}
    local entry=${2}

    [ -z "${fstab}" ] && die "fstab location is empty!"
    [ -z "${entry}" ] && die "fstab entry is empty!"

    [ ! -w "${fstab}" ] && die "${fstab} is not writable!"

    # Read the existing fstab entries
    local -a fstab_entries=( "${entry}" )
    readarray -O 1 -t fstab_entries < ${fstab}

    # Sort all fstab entries by mount point and write the new fstab
    for i in ${!fstab_entries[@]}; do
        echo ${fstab_entries[${i}]}
    done | sort -k 2,3 -o ${fstab}
}

run_chroot_cmd()
{
    local new_root=${1}
    shift

    [ -z "${new_root}" ] && die "new root directory is empty!"
    [ ${#} -eq 0 ] && die "no command specified!"

    # Mount /dev and virtual filesystems inside the chroot
    mount --bind /dev ${new_root}/dev
    mount --bind /dev/pts ${new_root}/dev/pts
    mount -t proc proc ${new_root}/proc
    mount -t sysfs sysfs ${new_root}/sys
    mount -t tmpfs tmpfs ${new_root}/run

    # Bind mount /etc/resolv.conf to enable DNS within the chroot jail
    local resolv=$(realpath -m ${new_root}/etc/resolv.conf)
    local parent=$(dirname ${resolv})
    [ ! -d "${parent}" ] && mkdir -p ${parent}
    touch ${resolv}
    mount --bind /etc/resolv.conf ${resolv}

    chroot "${new_root}" \
        /usr/bin/env -i HOME=/root TERM="${TERM}" PATH=/usr/bin:/usr/sbin \
        ${@}

    # Unmount virtual filesystems
    umount ${resolv}
    umount ${new_root}/dev{/pts,}
    umount ${new_root}/{sys,proc,run}
}

########################################

# Partition the virtual disk
echo "Partitioning virtual disk..."
create_disk_partitions ${new_img_dev}

# Format filesystems
echo "Formatting ${BOOT_PART_NAME} partition ${boot_partition} ..."
mkfs.ext4 -L ${BOOT_PART_LABEL} ${boot_partition}

echo "Formatting ${EFI_PART_NAME} partition ${efi_partition} ..."
mkfs.vfat -F 16 -n ${EFI_PART_LABEL} ${efi_partition}

# Setup jindisk on the root partition
jindisk_mnt=${jindisk_MNT}
mkdir -p ${jindisk_mnt}

echo "Prepare jindisk partition: ${jindisk_partition} ..."
jindisk_partition_size=`blockdev --getsize ${jindisk_partition}`
echo "jindisk partition size: "${jindisk_partition_size}

# sudo jindisksetup-rust create -p ${preset_key} -d ${jindisk_partition} -t jindisk_rootfs
sudo jindisksetup create ${preset_key} ${jindisk_partition} jindisk_rootfs
if [ $? -ne 0 ]; then
	echo "jindisksetup failed"
	exit -1
else
	echo "jindisksetup succeeded"
fi

dd if=${ref_rootfs} of=/dev/mapper/jindisk_rootfs status=progress

mount -t ext4 /dev/mapper/jindisk_rootfs ${jindisk_mnt}

# Move the contents of /boot to the new boot partition
#NOTE: make sure the ref image consists of (efi, root) partitions and the root partition should have a /boot dir

echo "Preparing boot partition..."
mv ${jindisk_mnt}/boot ${jindisk_mnt}/boot.orig
mkdir -p ${jindisk_mnt}/boot
mount ${boot_partition} ${jindisk_mnt}/boot
mv ${jindisk_mnt}/boot.orig/* ${jindisk_mnt}/boot
rm -rf ${jindisk_mnt}/boot.orig

# Update etc/fstab to include the new boot partition
add_fstab_entry ${jindisk_mnt}/etc/fstab "LABEL=boot /boot ext4 defaults 0 1"

# Set up initramfs hook
echo "Add initramfs-jindisk hooks..."

. ${jindisk_mnt}/etc/os-release
#TODO: make sure this script can be also used in CentOS

if [ "${ID}" == "ubuntu" ]; then

    echo "Copying initramfs hooks..."
    cp -f ${initramfs_hook_dir}/hook-add-binary ${jindisk_mnt}/etc/initramfs-tools/hooks/
    cp -f ${initramfs_hook_dir}/hook-unlock ${jindisk_mnt}/etc/initramfs-tools/scripts/init-premount/

    #uuid=$(blkid -s UUID -o value ${jindisk_partition})

    echo "Replacing fstab..."
    cp -f ${initramfs_hook_dir}/fstab ${jindisk_mnt}/etc/fstab

    echo "Preparing RA & unlocking scripts..."
    pushd ${initramfs_hook_dir}
        #TODO: remove the following later
        cp -f key.example ${jindisk_mnt}/sbin/
        echo "Filling getting-key script..."
        #TODO: reading key/certificate using RA script/binary 'getting_key'
        cp -f getting_key ${jindisk_mnt}/sbin/
        echo "Filling unlocking script..."
        #TODO: entry can be read from /etc/jindisktab
        cp -f jindisk_unlocking ${jindisk_mnt}/sbin/
    popd
    

    run_chroot_cmd ${jindisk_mnt} update-initramfs -u -k all
fi

# Install GRUB
echo "Installing GRUB..."
mount ${efi_partition} ${jindisk_mnt}/boot/efi
run_chroot_cmd ${jindisk_mnt} grub-install --target=x86_64-efi ${new_img_dev}

#TODO: intall packages

# Update the GRUB menu
# Disabling os-prober ensures that only the kernels in /boot are added to the menu, and OSes on other disks (like the host OS) are ignored.
echo "Updating GRUB Menu..."
cp ${jindisk_mnt}/etc/default/grub ${jindisk_mnt}/etc/default/grub.orig
echo "GRUB_DISABLE_OS_PROBER=true" >> ${jindisk_mnt}/etc/default/grub
run_chroot_cmd ${jindisk_mnt} update-grub
mv ${jindisk_mnt}/etc/default/grub.orig ${jindisk_mnt}/etc/default/grub

echo "Successfully created ${new_image}!"
exit 0
