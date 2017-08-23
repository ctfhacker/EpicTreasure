#!/bin/bash

HOMEDIR=/home/vagrant

# Updates
sudo update-locale LANG=en_US.UTF-8 LANGUAGE=en.UTF-8
sudo apt-get -y update

sudo apt-get -y install git
sudo apt-get -y install vim
sudo apt-get -y install python-pip
sudo apt-get -y install python3-pip
sudo apt-get -y install tmux
sudo apt-get -y install gdb gdb-multiarch
sudo apt-get -y install unzip
sudo apt-get -y install foremost
sudo apt-get -y install ipython
sudo apt-get -y install silversearcher-ag
sudo apt-get -y install virtualenv


cd $HOMEDIR
mkdir tools
cd tools

# Install pwndbg
cd $HOMEDIR/tools
sudo apt-get -y install libglib2.0
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Install radare2
cd $HOMEDIR/tools
git clone https://github.com/radare/radare2
cd radare2
./sys/install.sh

# Install 32 bit libs
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get -y install libc6:i386 libncurses5:i386 libstdc++6:i386
sudo apt-get -y install libc6-dev-i386

# Install r2pipe
sudo pip install r2pipe

# Personal config
sudo sudo apt-get -y install stow
cd $HOMEDIR
rm .bashrc
git clone --recursive https://github.com/ctfhacker/dotfiles
cd dotfiles
./install.sh
source ~/.bash_profile

sudo apt-get install -y qemu-user-static qemu binfmt*
