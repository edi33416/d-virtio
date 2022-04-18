#!/bin/bash
#
# This script runs qemu and creates a symbolic link named serial.pts
# to the qemu serial console (pts based). Because the qemu pts
# allocation is dynamic, it is preferable to have a stable path to
# avoid visual inspection of the qemu output when connecting to the
# serial console.

case $ARCH in
    x86)
	qemu=qemu-system-i386
	;;
    arm)
	qemu=qemu-system-arm
	;;
    x86_64)
	qemu=qemu-system-x86_64
	;;
esac

echo info chardev | nc -U -l qemu$ID.mon | egrep --line-buffered -o "/dev/pts/[0-9]*" | xargs -I PTS ln -fs PTS serial$ID.pts &
$qemu "$@" -monitor unix:qemu$ID.mon
rm -f qemu$ID.mon 
rm -f serial$ID.pts
