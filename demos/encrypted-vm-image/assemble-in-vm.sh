#!/bin/sh

password=$1

cd ~
rm -rf jinzhao-disk/

git clone git@github.com:jinzhao-dev/jinzhao-disk.git

cd jinzhao-disk/
cd demos/encrypted-vm-image/
cd in-vm/

cd installation-scripts/
echo ${password} | sudo -S ./install-kernel-module.sh
echo ${password} | sudo -S ./install-user-cli.sh

cd ..
echo ${password} | sudo -S ./assemble.sh

sleep 3s
echo ${password} | sudo -S poweroff
