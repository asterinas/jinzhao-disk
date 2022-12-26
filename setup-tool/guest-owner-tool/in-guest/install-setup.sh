#!/bin/sh

# For Ubuntu 20.04/22.04

if [ $# -ne 1 ];
then
        echo "Usage: sudo install-setup <your_path_to_jindisk-linux/setup-tool/src/c>!"
        exit
fi


SETUP_SRC="$1"

# sudo apt update
sudo apt install build-essential libssl-dev
sudo apt install libdevmapper-dev

cd ${SETUP_SRC}/
make clean
make
make install

make clean
