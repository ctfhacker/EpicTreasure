############################################################
# Dockerfile to build Binjitsu container
# Based on Ubuntu
############################################################

FROM ubuntu
MAINTAINER Maintainer Cory Duplantis

RUN apt-get update && apt-get install -y software-properties-common # feb 16 2016
RUN apt-get update
RUN apt-get install -y \
    build-essential \
    curl \
    gdb \
    gdb-multiarch \
    gdbserver \
    git \
    libc6-arm64-cross \
    libc6-armhf-cross \
    libc6-dev-i386 \
    libc6-i386 \
    libffi-dev \
    libncurses5-dev \
    libncursesw5-dev \
    python-dev \
    python-dev \
    python-pip \
    python2.7 \
    python3-pip \
    tmux \
    tree \
    virtualenvwrapper \
    wget \
    vim

# Install radare2
RUN git clone https://github.com/radare/radare2 \
    && cd radare2 \
    && ./sys/install.sh

# Install angr
RUN pip install angr --upgrade

RUN pip install --upgrade ipython
# RUN useradd -m epictreasure
# RUN usermod -U epictreasure
# USER epictreasure
# RUN chsh -s /bin/bash epictreasure
# RUN mkdir /home/epictreasure/tools
RUN mkdir /root/tools

# Install binjitsu
RUN apt-get -y install python2.7 python-pip python-dev git \ 
    && pip install --upgrade git+https://github.com/binjitsu/binjitsu.git

RUN git clone https://github.com/aquynh/capstone \
	&& cd capstone \
	&& git checkout -t origin/next \
	&& sudo ./make.sh install \
	&& cd bindings/python \
	&& python2 setup.py install \
	&& python3 setup.py install
RUN pip install --upgrade pycparser
RUN pip3 install --upgrade pycparser

RUN pip install --upgrade git+https://github.com/binjitsu/binjitsu.git # 2016-2-15

RUN git clone https://github.com/zachriggle/pwndbg /root/tools/pwndbg
RUN echo "source /root/tools/pwndbg/gdbinit.py" > /root/.gdbinit
RUN pip3 install -Ur /root/tools/pwndbg/requirements.txt

RUN apt-get install -y libglib2.0-dev \ 
    && cd /root/tools \ 
    && git clone https://github.com/unicorn-engine/unicorn \ 
    && cd unicorn \ 
    && ./make.sh install \ 
    && cd bindings/python \ 
    && python3 setup.py install

COPY emdebian.list /etc/apt/sources.list.d/emdebian.list
RUN apt-get -y install qemu qemu-user qemu-user-static 
RUN apt-get -y install 'binfmt*' 
RUN apt-get -y install libc6-armhf-armel-cross
RUN apt-get -y install debian-keyring
RUN apt-get -y install debian-archive-keyring
RUN apt-get -y install emdebian-archive-keyring
RUN apt-get -m update; echo 0 # Always success from update
RUN apt-get -y install libc6-mipsel-cross
RUN apt-get -y install libc6-armel-cross libc6-dev-armel-cross
RUN apt-get -y install libc6-armhf-cross libc6-dev-armhf-cross
RUN apt-get -y install binutils-arm-linux-gnueabi
RUN apt-get -y install libncurses5-dev
RUN mkdir /etc/qemu-binfmt
RUN ln -s /usr/mipsel-linux-gnu /etc/qemu-binfmt/mipsel 
RUN ln -s /usr/arm-linux-gnueabihf /etc/qemu-binfmt/arm
RUN rm /etc/apt/sources.list.d/emdebian.list
RUN sudo apt-get update

# Install binwalk
RUN cd /root/tools \
    && git clone https://github.com/devttys0/binwalk \
    && cd binwalk \ 
    && python setup.py install \ 
    && apt-get -y install squashfs-tools

# Install firmware-mod-kit
RUN apt-get -y install git build-essential zlib1g-dev liblzma-dev python-magic \ 
    && cd /root/tools \ 
    && wget https://firmware-mod-kit.googlecode.com/files/fmk_099.tar.gz \ 
    && tar zxvf fmk_099.tar.gz \ 
    && rm fmk_099.tar.gz \
    && cd fmk/src \
    && ./configure \
    && make

# Install AFL with QEMU and clang-fast
RUN apt-get -y install clang llvm
RUN cd /root/tools \
    && wget --quiet http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz \
    && tar -xzvf afl-latest.tgz \
    && rm afl-latest.tgz \
    && wget --quiet http://llvm.org/releases/3.8.0/clang+llvm-3.8.0-x86_64-linux-gnu-ubuntu-14.04.tar.xz \
    && xz -d clang* \
    && tar xvf clang* \
    && cd clang* \
    && cd bin \
    && export PATH=$PWD:$PATH \
    && cd ../.. \
    && cd afl-* \
    && make \
    && cd llvm_mode \
    && make \
    && cd .. \
    && sudo make install \
    && sudo apt-get -y install libtool automake bison libglib2.0-dev \
    && cd qemu* \ 
    && ./build_qemu_support.sh

RUN apt-get -y install cmake

RUN dpkg --add-architecture i386
RUN apt-get update
RUN apt-get -y install libc6:i386 libncurses5:i386 libstdc++6:i386 libc6-dev-i386

# Install apktool
RUN apt-get update \
    && apt-get install -y default-jre \
    && wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
    && wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.0.2.jar \
    && sudo mv apktool_2.0.2.jar /bin/apktool.jar \
    && sudo mv apktool /bin/ \
    && sudo chmod 755 /bin/apktool \
    && sudo chmod 755 /bin/apktool.jar

# Install Pillow
RUN apt-get -y build-dep python-imaging \
    && apt-get -y install libjpeg8 libjpeg62-dev libfreetype6 libfreetype6-dev \
    && pip install Pillow

# Install r2pipe
RUN pip install r2pipe

# Install ROPGadget
RUN cd /root/tools \
    && git clone https://github.com/JonathanSalwan/ROPgadget \
    && cd ROPgadget \
    && python setup.py install

# Install personal config
RUN apt-get -y install stow \
    && cd /root \
    && rm .bashrc \
    && git clone --recursive https://github.com/ctfhacker/dotfiles \
    && cd dotfiles \
    && ./install.sh

# Install fzf for fuzzing searching on command line
RUN cd /root/tools \
    && git clone --depth 1 https://github.com/junegunn/fzf.git /root/.fzf \
    && /root/.fzf/install --all --key-bindings --completion

# Install libheap in GDB
RUN cd /root/tools \
    && git clone https://github.com/cloudburst/libheap \
    && cd libheap \
    && cp libheap.py /usr/lib/python3.4 \
    && echo "python from libheap import *" >> /root/.gdbinit

# Install QIRA
RUN cd /root/tools \
    && git clone https://github.com/BinaryAnalysisPlatform/qira.git \
    && cd qira/ \ 
    && ./install.sh

# Install decompile
COPY decompile /usr/bin/decompile
RUN chmod +x /usr/bin/decompile

RUN apt-get install silversearcher-ag
RUN apt-get install unzip

RUN locale-gen en_US.UTF-8  
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8     
