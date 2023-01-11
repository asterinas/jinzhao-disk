#!/bin/sh

# For Ubuntu 20.04/22.04

SHELL_FOLDER=$(cd "$(dirname "$0")";pwd)

SETUP_TOOL_SRC="${SHELL_FOLDER}/../../src/c"

# sudo apt update
sudo apt install build-essential libssl-dev
sudo apt install libdevmapper-dev

cd ${SETUP_TOOL_SRC}/
make clean
make
sudo make install
