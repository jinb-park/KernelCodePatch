#!/bin/sh

ARCH="arm"
CROSS_COMPILE="arm-linux-gnueabi-"
KDIR="/home/pjb1027/OpenSource/linux_4.1.10/linux-4.1.5"

make CROSS_COMPILE="$CROSS_COMPILE" ARCH="$ARCH" KDIR="$KDIR"
