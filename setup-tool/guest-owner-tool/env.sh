image_dir="/var/lib/libvirt/images/"

ref_image=${image_dir}"ubuntu22.04-ref.qcow2"
new_image=${image_dir}"ubuntu22.04-new.qcow2"

test_image=${image_dir}"test.img"

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS_4M.fd"

ref_img_nbd="/dev/nbd2"
new_img_nbd="/dev/nbd3"

QEMU="/usr/bin/qemu-system-x86_64"

CPU="-smp 8"
MEM="-m 16G"

DEFAULT_IMG_SIZE="65G"