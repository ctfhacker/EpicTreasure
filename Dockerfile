############################################################
# Dockerfile to build Epictreasure container
# Based on Ubuntu
############################################################

FROM ubuntu:16.04
MAINTAINER Maintainer Cory Duplantis

RUN mkdir -p /root/tools
RUN apt-get update && apt-get install -y software-properties-common
RUN apt-get update && apt-get install -y build-essential curl gdb \
    gdb-multiarch gdbserver git locales \
    libc6-arm64-cross libc6-armhf-cross libc6-dev-i386 \
    libc6-i386 libffi-dev libssl-dev libncurses5-dev \
    libncursesw5-dev python-dev python-dev python-pip \
    python2.7 python3-pip tmux tree stow virtualenvwrapper \
    wget vim unzip python-imaging \
    libjpeg8 libjpeg62-dev libfreetype6 libfreetype6-dev \
    squashfs-tools zlib1g-dev liblzma-dev python-magic cmake z3

RUN cd /root && \
    rm .bashrc && \
    git clone --recursive https://github.com/ctfhacker/dotfiles.git && \
    cd dotfiles && \
    ./install.sh

RUN pip install -Iv ipython==5.3.0 && \
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
    ./non_sudo_setup.sh

RUN cd /root/tools \
    && git clone https://github.com/devttys0/binwalk \
    && cd binwalk \ 
    && python setup.py install \ 

    && cd /root/tools \ 
    && wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/firmware-mod-kit/fmk_099.tar.gz \
    && tar zxvf fmk_099.tar.gz \ 
    && rm fmk_099.tar.gz \
    && cd fmk/src \
    && ./configure \
    && make

RUN dpkg --add-architecture i386 && \
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

    pip install Pillow && \

    pip install r2pipe && \

    cd /root/tools && \
    git clone https://github.com/JonathanSalwan/ROPgadget.git && \
    cd ROPgadget && \
    python setup.py install && \

    cd /root/tools && \
    git clone --depth 1 https://github.com/junegunn/fzf.git /root/.fzf && \
    /root/.fzf/install --all --key-bindings --completion

RUN locale-gen en_US.UTF-8 && \

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

    cd /root/tools && \
    git clone https://github.com/trailofbits/manticore.git && cd manticore && \
    pip install . && \
    rm -rf /var/lib/apt/lists/* && \

    wget https://sh.rustup.rs && chmod +x index.html && ./index.html -y && /root/.cargo/bin/cargo install ripgrep

RUN wget http://ftp.gnu.org/gnu/bash/bash-4.4.tar.gz && \ 
    tar zxvf bash-4.4.tar.gz && \
    cd bash-4.4 && \
    ./configure && \
    make && \
    make install && \
    cd .. && \
    rm bash-4.4.tar.gz && rm -rf bash-4.4 && \
    chsh -s /usr/local/bin/bash

COPY .tmux.conf /root/.tmux.conf

RUN locale-gen en_US.UTF-8  
ENV LANG en_US.UTF-8  
ENV LANGUAGE en_US:en  
ENV LC_ALL en_US.UTF-8     
