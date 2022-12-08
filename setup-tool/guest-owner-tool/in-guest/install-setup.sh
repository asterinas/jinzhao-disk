#!/bin/sh

# For Ubuntu 20.04/22.04

if [ $# -ne 1 ];
then
        echo "Usage: sudo install-jindisk <your_path_to_jindisk-setup>!"
        exit
fi


SETUP_SRC="$1"

# sudo apt update
sudo apt install build-essential libssl-dev
sudo apt install libdevmapper-dev

cd ${SETUP_SRC}/c/
make clean
make
make install

make clean
