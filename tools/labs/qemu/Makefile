QEMU_DISPLAY ?= none
ARCH ?= x86
ifeq ($(ARCH),x86_64)
b = b
endif
ZIMAGE=$(KDIR)/arch/$(ARCH)/boot/$(b)zImage
KCONFIG=$(KDIR)/.config
NTTCP=$(KDIR)/tools/labs/templates/assignments/6-e100/nttcp

YOCTO_URL=http://downloads.yoctoproject.org/releases/yocto/yocto-2.3/machines/qemu/qemux86-64
#YOCTO_IMAGE=core-image-minimal-qemux86-64.ext4
#YOCTO_URL=http://downloads.yoctoproject.org/releases/yocto/yocto-2.3/machines/qemu/qemu$(ARCH)/
#YOCTO_IMAGE=core-image-minimal-qemu$(ARCH).ext4
#YOCTO_IMAGE=core-image-minimal-dev-qemu$(ARCH).ext4
#YOCTO_IMAGE=core-image-sato-dev-qemux86-64.ext4
#YOCTO_IMAGE=core-image-sato-qemu$(ARCH).ext4
YOCTO_IMAGE=core-image-sato-sdk-qemux86-64.ext4
YOCTO_IMAGE2=2core-image-sato-sdk-qemux86-64.ext4

QEMU_OPTS = -kernel $(ZIMAGE) \
	-device virtio-serial \
	-chardev pty,id=virtiocon0 -device virtconsole,chardev=virtiocon0 \
	-serial pipe:pipe1 -serial pipe:pipe2 \
	-net nic,model=virtio,vlan=0 -net tap,ifname=tap0,vlan=0,script=no,downscript=no \
	-net nic,model=i82559er,vlan=1 -net tap,ifname=tap1,vlan=1,script=no,downscript=no \
	-drive file=$(YOCTO_IMAGE),if=virtio,format=raw \
	-drive file=disk1.img,if=virtio,format=raw \
	-drive file=disk2.img,if=virtio,format=raw \
	--append "root=/dev/vda console=hvc0" \
	--display $(QEMU_DISPLAY) -s

QEMU_OPTS_1 = -kernel $(ZIMAGE) \
	-device virtio-serial \
	-chardev pty,id=virtiocon0 -device virtconsole,chardev=virtiocon0 \
	-serial pipe:pipe1 -serial pipe:pipe2 \
	-net nic,model=virtio,vlan=0 -net tap,ifname=tap0,vlan=0,script=no,downscript=no \
	-net nic,model=i82559er,vlan=1 -net tap,ifname=tap1,vlan=1,script=no,downscript=no \
	-drive file=$(YOCTO_IMAGE),if=virtio,format=raw \
	-drive file=disk1.img,if=virtio,format=raw \
	-drive file=disk2.img,if=virtio,format=raw \
	--append "root=/dev/vda console=hvc0" \
	--display $(QEMU_DISPLAY) -s

QEMU_OPTS_2 = -kernel $(ZIMAGE) \
	-device virtio-serial \
	-chardev pty,id=virtiocon0 -device virtconsole,chardev=virtiocon0 \
	-serial pipe:pipe3 -serial pipe:pipe4 \
	-net nic,model=virtio,vlan=0 -net tap,ifname=tap2,vlan=0,script=no,downscript=no \
	-net nic,model=i82559er,vlan=1 -net tap,ifname=tap3,vlan=1,script=no,downscript=no \
	-drive file=$(YOCTO_IMAGE2),if=virtio,format=raw \
	-drive file=disk3.img,if=virtio,format=raw \
	-drive file=disk4.img,if=virtio,format=raw \
	--append "root=/dev/vda console=hvc0" \
	--display $(QEMU_DISPLAY) -s

boot: .modinst tap0 tap1 pipe1.in pipe1.out pipe2.in pipe2.out disk1.img disk2.img nttcp-run
	ARCH=$(ARCH) qemu/qemu.sh $(QEMU_OPTS)

boot_1: .modinst_1 tap0 tap1 pipe1.in pipe1.out pipe2.in pipe2.out disk1.img disk2.img nttcp-run
	ARCH=$(ARCH) ID=1 qemu/qemu.sh $(QEMU_OPTS_1)

boot_2: .modinst_2 tap2 tap3 pipe3.in pipe3.out pipe4.in pipe4.out disk3.img disk4.img nttcp-run
	ARCH=$(ARCH) ID=2 qemu/qemu.sh $(QEMU_OPTS_2)

TEMPDIR := $(shell mktemp -u)
TEMPDIR_1 := $(shell mktemp -u)
TEMPDIR_2 := $(shell mktemp -u)

$(KCONFIG): qemu/kernel_config.$(ARCH)
	cp $^ $@
	$(MAKE) -C $(KDIR) oldnoconfig

zImage: $(ZIMAGE)

$(ZIMAGE): $(KCONFIG)
	$(MAKE) -C $(KDIR)
	$(MAKE) -C $(KDIR) modules

.modinst: $(ZIMAGE) $(YOCTO_IMAGE)
	mkdir $(TEMPDIR)
	sudo mount -t ext4 -o loop $(YOCTO_IMAGE) $(TEMPDIR)
	sudo $(MAKE) -C $(KDIR) modules_install INSTALL_MOD_PATH=$(TEMPDIR)
	sudo umount $(TEMPDIR)
	rmdir $(TEMPDIR)
	sleep 1 && touch .modinst

.modinst_1: $(ZIMAGE) $(YOCTO_IMAGE)
	mkdir $(TEMPDIR_1)
	sudo mount -t ext4 -o loop $(YOCTO_IMAGE) $(TEMPDIR_1)
	sudo $(MAKE) -C $(KDIR) modules_install INSTALL_MOD_PATH=$(TEMPDIR_1)
	sudo umount $(TEMPDIR_1)
	rmdir $(TEMPDIR_1)
	sleep 1 && touch .modinst_1

.modinst_2: $(ZIMAGE) $(YOCTO_IMAGE)
	mkdir $(TEMPDIR_2)
	sudo mount -t ext4 -o loop $(YOCTO_IMAGE2) $(TEMPDIR_2)
	sudo $(MAKE) -C $(KDIR) modules_install INSTALL_MOD_PATH=$(TEMPDIR_2)
	sudo umount $(TEMPDIR_2)
	rmdir $(TEMPDIR_2)
	sleep 1 && touch .modinst_2

gdb: $(ZIMAGE)
	gdb -ex "target remote localhost:1234" $(KDIR)/vmlinux

$(YOCTO_IMAGE):
	wget $(YOCTO_URL)/$(YOCTO_IMAGE)
	sudo qemu/prepare-image.sh $(YOCTO_IMAGE)

$(YOCTO_IMAGE2):
	wget $(YOCTO_URL)/$(YOCTO_IMAGE2)
	sudo qemu/prepare-image.sh $(YOCTO_IMAGE2)

tap0:
	qemu/create_net.sh $@

tap1:
	qemu/create_net.sh $@

tap2:
	qemu/create_net.sh $@

tap3:
	qemu/create_net.sh $@

nttcp-run: $(NTTCP) tap1
	$(NTTCP) -v -i &

pipe1.in:
	mkfifo $@

pipe1.out:
	mkfifo $@

pipe2.in: pipe1.out
	ln $< $@

pipe2.out: pipe1.in
	ln $< $@

pipe3.in: pipe1.out
	ln $< $@

pipe3.out: pipe1.in
	ln $< $@

pipe4.in: pipe1.out
	ln $< $@

pipe4.out: pipe1.in
	ln $< $@

disk1.img:
	qemu-img create -f raw $@ 8G
disk2.img:
	qemu-img create -f raw $@ 8G
disk3.img:
	qemu-img create -f raw $@ 8G
disk4.img:
	qemu-img create -f raw $@ 8G

clean::
	rm -f .modinst disk1.img disk2.img .modinst_1 .modinst_2 disk1.img disk2.img disk3.img disk4.img

.PHONY: clean tap0 tap1 tap1 tap2

