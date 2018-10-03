# EpicTreasure - Batteries included CTF VM

## Tools included
* [Pwntools](https://github.com/gallopsled/pwntools)
* [Pwndbg](https://github.com/zachriggle/pwndbg)
* [Radare2](https://github.com/radare/radare2)
* [Firmware tools (fmk / qemu)](http://reverseengineering.stackexchange.com/questions/8829/cross-debugging-for-mips-elf-with-qemu-toolchain)
* [angr](https://github.com/angr/angr)
* [ROPGadget](https://github.com/JonathanSalwan/ROPgadget)
* [binwalk](https://github.com/devttys0/binwalk)
* [apktool](http://ibotpeaches.github.io/Apktool/)

## Docker

```
docker pull ctfhacker/epictreasure
docker run --rm -v /path/to/host/share/folder:/root/host-share --privileged -it --workdir=/root ctfhacker/epictreasure
```

## Default settings
By default, [my dotfiles](http://github.com/ctfhacker/dotfiles) are installed onto the VM. Simply comment out the following lines in `Dockerfile` if you don't want my settings.

```
# Personal dotfiles
RUN cd /root && \
    rm .bashrc && \
    git clone --recursive https://github.com/ctfhacker/dotfiles.git && \
    cd dotfiles && \
    ./install.sh
```

Then rebuild the Docker

```
docker build -t et .
```

#### Terminal
* Colorscheme for the terminal and vim is [solarized](https://github.com/altercation/solarized)

#### Vim
* `jk` or `jj` to `ESC` out of Vim 
* `ESC` and `Arrow keys` are hard coded to not work in Vim (as a teaching mechanism)
* `:` is remapped to `;` (who uses ; anyway?)
* leader key is `SPACE` (thanks to [spacemacs](https://github.com/syl20bnr/spacemacs))
* `SPACE p` will drop an embedded IPython line in a python script
* `H` moves to beginning of line, `L` moves to end of line (instead of `^` and `$`)

#### Tmux
* A new shell spawns a fresh `tmux` session
* `tmux` leader switched to `Ctrl+A`
* `Ctrl+A -` produces a horizontal pane. `Ctrl+A \` produces a vertical pane.
* `Ctrl+A [hjkl]` moves around available panes as vim motion

## Check correct installation

### Pwndbg

Run the following command in the VM:
```
gdb /bin/ls
```

Expected output:
```
Reading symbols from host-share/crackme...(no debugging symbols found)...done.
Only available when running
pwndbg>
```

### Radare

Run the following command in the VM:
```
r2 /bin/ls
```

Expected output:
```
[0x00404890]> aaa
```

### Pwntools

Run the following command in the VM:
```
python
>>> from pwn import *
>>> elf = ELF('/bin/ls')
[*] '/bin/ls'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
    FORTIFY:  Enabled
>>> rop = ROP(elf)
[*] Loading gadgets for '/bin/ls'
```

### angr

Run the following commands in the VM:
```
python
>>> import angr
>>>
```

### capstone / keystone / unicorn

Run the following commands in the VM:
```
python
>>> import capstone
>>> import keystone
>>> import unicorn
>>>
```

### Shared folder

Drop files in the `host-share` folder on your host to find them on your VM at `/home/vagrant/host-share`

### Tests

Using Google's [container-structure-test](https://github.com/GoogleContainerTools/container-structure-test) to test our new container

```
./container-structure-test-darwin-amd64 test --image ctfhacker/epictreasure --config tests.yaml
```
