############################################################
# Dockerfile to build Binjitsu container
# Based on Ubuntu
############################################################

FROM ubuntu:16.04
MAINTAINER Maintainer Cory Duplantis

RUN mkdir /root/tools
RUN apt-get update && apt-get install -y software-properties-common && \
    apt-get update && \ apt-get install -y build-essential curl gdb \
    gdb-multiarch gdbserver git \
    libc6-arm64-cross libc6-armhf-cross libc6-dev-i386 \
    libc6-i386 libffi-dev libssl-dev libncurses5-dev \
    libncursesw5-dev python-dev python-dev python-pip \
    python2.7 python3-pip tmux tree virtualenvwrapper \
    wget vim silversearcher-ag unzip && \

    pip install -Iv ipython==5.3.0 && \

    pip install angr --upgrade && \

    git clone https://github.com/radare/radare2 && \
    cd radare2 && \
    ./sys/install.sh && \
    make install && \

    pip install --upgrade pwntools && \

    cd /root/tools && \
    git clone https://github.com/zachriggle/pwndbg && \
    cd pwndbg && \
    sed 's/sudo//g' setup.sh > non_sudo_setup.sh && \
    chmod +x non_sudo_setup.sh && \
    ./non_sudo_setup.sh && \

    cd /root/tools \
    && git clone https://github.com/devttys0/binwalk \
    && cd binwalk \ 
    && python setup.py install \ 
    && apt-get -y install squashfs-tools && \

    apt-get -y install git build-essential zlib1g-dev liblzma-dev python-magic \ 
    && cd /root/tools \ 
    && wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/firmware-mod-kit/fmk_099.tar.gz \
    && tar zxvf fmk_099.tar.gz \ 
    && rm fmk_099.tar.gz \
    && cd fmk/src \
    && ./configure \
    && make && \

    apt-get -y install cmake && \

    dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get -y install libc6:i386 libncurses5:i386 libstdc++6:i386 libc6-dev-i386 && \

    apt-get update \
    && apt-get install -y default-jre \
    && wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool \
    && wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.0.2.jar \
    && mv apktool_2.0.2.jar /bin/apktool.jar \
    && mv apktool /bin/ \
    && chmod 755 /bin/apktool \
    && chmod 755 /bin/apktool.jar && \

    apt-get -y build-dep python-imaging \
    && apt-get -y install libjpeg8 libjpeg62-dev libfreetype6 libfreetype6-dev \
    && pip install Pillow && \

    pip install r2pipe && \

    cd /root/tools && \
    git clone https://github.com/JonathanSalwan/ROPgadget && \
    cd ROPgadget && \
    python setup.py install && \

    apt-get -y install stow && \
    cd /root && \
    rm .bashrc && \
    git clone --recursive https://github.com/ctfhacker/dotfiles && \
    cd dotfiles && \
    ./install.sh && \

    cd /root/tools && \
    git clone --depth 1 https://github.com/junegunn/fzf.git /root/.fzf && \
    /root/.fzf/install --all --key-bindings --completion && \

    cd /root/tools && \
    apt-get install libc6-dbg && \
    git clone https://github.com/cloudburst/libheap && \
    cd libheap && \
    python setup.py install && \
    echo "python from libheap import *" >> /root/.gdbinit && \

    locale-gen en_US.UTF-8 && \

    apt-get -y install qemu qemu-user qemu-user-static && \
    apt-get -y install 'binfmt*' && \
    apt-get -y install libc6-armhf-armel-cross && \
    apt-get -y install debian-keyring && \
    apt-get -y install debian-archive-keyring && \
    apt-get -y install emdebian-archive-keyring && \
    apt-get -m update; echo 0 && \
    apt-get -y install libc6-mipsel-cross && \
    apt-get -y install libc6-armel-cross libc6-dev-armel-cross && \
    apt-get -y install libc6-armhf-cross libc6-dev-armhf-cross && \
    apt-get -y install binutils-arm-linux-gnueabi && \
    apt-get -y install libncurses5-dev && \
    mkdir /etc/qemu-binfmt && \
    ln -s /usr/mipsel-linux-gnu /etc/qemu-binfmt/mipsel && \
    ln -s /usr/arm-linux-gnueabihf /etc/qemu-binfmt/arm && \

    apt-get install -y z3 python-pip && \
    python -m pip install -U pip && \
    cd /root/tools && \
    git clone https://github.com/trailofbits/manticore.git && cd manticore && \
    pip install . && \
    rm -rf /var/lib/apt/lists/* && \

    wget https://sh.rustup.rs && chmod +x index.html && ./index.html -y && /root/.cargo/bin/cargo install ripgrep && \

    cd /root/tools && \
    wget https://github.com/DynamoRIO/dynamorio/releases/download/release_7_0_0_rc1/DynamoRIO-Linux-7.0.0-RC1.tar.gz && \
    tar zxvf Dynamo* && \
    rm DynamoRIO-Linux-7.0.0-RC1.tar.gz && \
    wget https://github.com/DynamoRIO/drmemory/releases/download/release_1.11.0/DrMemory-Linux-1.11.0-2.tar.gz && \
    tar zxvf DrMem* && \
    rm DrMemory-Linux-1.11.0-2.tar.gz  && \

    apt-get -y install clang llvm libtool-bin && \

    cd /root/tools \
    && wget --quiet http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz \
    && tar -xzvf afl-latest.tgz \
    && rm afl-latest.tgz \
    && wget --quiet http://llvm.org/releases/3.8.0/clang+llvm-3.8.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
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
    && apt-get -y install libtool automake bison libglib2.0-dev \
    && cd qemu* \ 
    && ./build_qemu_support.sh \
    && cd .. \
    && make install

RUN locale-gen en_US.UTF-8  
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8     
