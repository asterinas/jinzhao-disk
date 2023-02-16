#!/bin/sh

# For Ubuntu 20.04/22.04

SHELL_FOLDER=$(cd "$(dirname "$0")";pwd)

SETUP_TOOL_SRC="${SHELL_FOLDER}/../../../../user-cli/src/c"

# apt update
apt install build-essential libssl-dev
apt install libdevmapper-dev

cd ${SETUP_TOOL_SRC}/
make clean
make
make install

echo "Adding the JinDisk user-space CLI into the initramfs..."
cp ${SHELL_FOLDER}/hook-add-user-cli /etc/initramfs-tools/hooks/
update-initramfs -u -k all