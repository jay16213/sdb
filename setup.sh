#!/bin/sh

# clone capstone
git clone https://github.com/capstone-engine/capstone.git

# install capstone
CAPSTONE_ARCHS="arm aarch64 x86" ./make.sh
sudo ./make.sh install
