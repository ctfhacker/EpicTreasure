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
sudo pip install r2pipe

# Personal config
sudo apt-get -y install stow
cd $HOMEDIR
rm .bashrc
git clone https://github.com/ctfhacker/dotfiles --recursive
cd dotfiles
./install.sh
source ~/.bash_profile

# Install GO
cd $HOMEDIR
wget https://storage.googleapis.com/golang/go1.7.1.linux-amd64.tar.gz
tar zxvf go1.*
mkdir $HOMEDIR/.go

# Install crashwalk
go get -u github.com/arizvisa/crashwalk/cmd/...
mkdir $HOMEDIR/src
cd $HOMEDIR/src
git clone https://github.com/jfoote/exploitable

# Install afl-utils
sudo pip2 install virutalenv virtualenvwrapper
source /usr/local/bin/virtualenvwrapper.sh
cd $HOMEDIR/tools
git clone https://github.com/rc0r/afl-utils
cd afl-utils
mkvirtualenv afl -p /usr/bin/python3
python setup.py install
echo "source /home/vrt/.virtualenvs/afl/lib/python3.5/site-packages/exploitable-1.32_rcor-py3.5.egg/exploitable/exploitable.py" >> $HOMEDIR/.gdbinit

# Install valgrind
sudo apt-get -y install valgrind

# Install Dr. Memory
cd $HOMEDIR/tools
wget https://github.com/DynamoRIO/drmemory/releases/download/release_1.11.0/DrMemory-Linux-1.11.0-2.tar.gz
tar zxvf DrMemory*
cd DrMemory*
sudo ln -s $PWD/bin/drmemory /usr/bin/drmemory-32
sudo ln -s $PWD/bin64/drmemory /usr/bin/drmemory-64

# Install rr
sudo apt-get -y install ccache cmake make g++-multilib gdb pkg-config libz-dev realpath python-pexpect manpages-dev git zlib1g-dev ninja-build
mkdir rr
cd rr
git clone https://github.com/mozilla/rr.git
mkdir obj
cd obj
cmake ../rr
make -j8
sudo make install
