# d21x

ArtInChip D21x board

The board is built around 88-pin D21x CPU with 64mb of DRAM included.

The board is capabile to run FreeBSD, but no support yet available.

This is a 'hello world' app using MDEPX real-time operating system.

### Setup your compiler

Use T-Head compiler that supports (non-standard) instruction set extensions

    $ export CROSS_COMPILE=/path/to/bin/riscv64-unknown-elf-

### Get sources and build the project
    $ git clone --recursive https://github.com/mdepx/d21x
    $ cd d21x
    $ make clean all

### sdcard ###

 1. Create a single-partition fat32 image

    $ mkfs.vfat /dev/sdb

 1. Copy obj/d21x.aic and aic/bootcfg.txt to that partition

    $ mount /dev/sdb /mnt
    $ cp obj/d21x.aic aic/bootcfg.txt /mnt/
    $ umount /mnt
