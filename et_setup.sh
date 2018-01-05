#!/bin/bash

HOMEDIR=/home/$USER

# Updates
sudo apt-get -y update

sudo apt-get -y install python3-pip
sudo apt-get -y install tmux
sudo apt-get -y install gdb gdb-multiarch
sudo apt-get -y install unzip
sudo apt-get -y install foremost
sudo apt-get -y install ipython
sudo apt-get -y install python2.7 python-pip python-dev git libssl-dev libffi-dev
sudo apt-get -y install vim curl

# Ptrace enable
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Install virtualenvwrapper
pip install virtualenvwrapper
export WORKON_HOME=$HOMEDIR/.virtualenvs
export PROJECT_HOME=$HOMEDIR/Devel
source /usr/local/bin/virtualenvwrapper.sh

# Switch to tools dir for installation
cd $HOMEDIR
mkdir tools
cd tools

# Install pwndbg
mkvirtualenv pwn
pip install --upgrade pwntools
deactivate

# Install pwndbg
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh

# Install radare2
cd ~
git clone https://github.com/radare/radare2
cd radare2
./sys/install.sh

# Install binwalk
cd ~
git clone https://github.com/devttys0/binwalk
cd binwalk
sudo python setup.py install
sudo apt-get install squashfs-tools

# Install Firmware-Mod-Kit
sudo apt-get -y install git build-essential zlib1g-dev liblzma-dev python-magic
cd ~/tools
wget https://firmware-mod-kit.googlecode.com/files/fmk_099.tar.gz
tar xvf fmk_099.tar.gz
rm fmk_099.tar.gz
cd fmk_099/src
./configure
make

# Install american-fuzzy-lop
sudo apt-get -y install clang llvm
cd $HOMEDIR/tools
wget --quiet http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
tar -xzvf afl-latest.tgz
rm afl-latest.tgz
wget --quiet http://llvm.org/releases/3.8.0/clang+llvm-3.8.0-x86_64-linux-gnu-ubuntu-14.04.tar.xz
xz -d clang*
tar xvf clang*
cd clang*
cd bin
export PATH=$PWD:$PATH
cd ../..
(
  cd afl-*
  make
  # build clang-fast
  (
    cd llvm_mode
    make
  )
  sudo make install

  # build qemu-support
  sudo apt-get -y install libtool automake bison libglib2.0-dev
  ./build_qemu_support.sh
)

# Install 32 bit libs
sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get -y install libc6:i386 libncurses5:i386 libstdc++6:i386
sudo apt-get -y install libc6-dev-i386

# Install r2pipe
pip install r2pipe

# Install ROPGadget
git clone https://github.com/JonathanSalwan/ROPgadget
cd ROPgadget
sudo python setup.py install

# Install GO
cd $HOMEDIR
wget https://storage.googleapis.com/golang/go1.6.2.linux-amd64.tar.gz
tar zxvf go1.*
mkdir $HOMEDIR/.go

# Install crashwalk
go get -u github.com/arizvisa/crashwalk/cmd/...
mkdir $HOMEDIR/src
cd $HOMEDIR/src
git clone https://github.com/jfoote/exploitable

# Install Delve - go debugging
go get github.com/derekparker/delve/cmd/dlv

# Install joern
sudo apt-get install ant
wget https://github.com/fabsx00/joern/archive/0.3.1.tar.gz
tar xfzv 0.3.1.tar.gz
cd joern-0.3.1
wget http://mlsec.org/joern/lib/lib.tar.gz
tar xfzv lib.tar.gz
ant
alias joern='java -jar $JOERN/bin/joern.jar'

mkvirtualenv joern
wget https://github.com/nigelsmall/py2neo/archive/py2neo-2.0.7.tar.gz
tar zxvf py2neo*
cd py2neo
python setup.py install

# Install Rust
curl https://sh.rustup.rs -sSf | sh
cargo install ripgrep

# Personal config
sudo sudo apt-get -y install stow
cd $HOMEDIR
rm .bashrc
git clone --recursive https://github.com/ctfhacker/dotfiles
cd dotfiles
./install.sh


