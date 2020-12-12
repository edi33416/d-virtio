#CC=ldc2
CC=gdc-10
#CFLAGS=-betterC -c -release -boundscheck=on -O1 -enable-inlining -disable-red-zone
#CFLAGS=-betterC -c -release -boundscheck=on -enable-inlining -aarch64-enable-cond-br-tune -aarch64-enable-condopt
#CFLAGS=-fno-druntime -mcmodel=kernel -fno-pie -O1 -Wframe-larger-than=1024 -fno-stack-protector -fno-stack-check -fconserve-stack -c

#CFLAGS=-fno-druntime -mcmodel=kernel -fno-pie -c

#CFLAGS=-fno-druntime -mcmodel=kernel -fno-pie -c -Wall -fno-strict-aliasing -fno-common -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -msoft-float -mregparm=3 -freg-struct-return -fno-pic  -Wa,-mtune=generic64 -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -DRETPOLINE -fno-delete-null-pointer-checks -O2  -Wframe-larger-than=1024 -fno-stack-protector -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -fno-strict-overflow -fno-stack-check -fconserve-stack

CFLAGS=-fno-druntime -mcmodel=kernel -fno-pie -c -Wall -fno-strict-aliasing -fno-common -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -msoft-float -mregparm=3 -freg-struct-return -fno-pic  -Wa,-mtune=generic64 -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -DRETPOLINE -fno-delete-null-pointer-checks -O2  -Wframe-larger-than=1024 -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -fno-strict-overflow -fno-stack-check -fconserve-stack

#CFLAGS=-fno-druntime -mcmodel=kernel -fno-pie -finline-functions -c
#CFLAGS=-fno-druntime -mcmodel=kernel -fno-pie -fno-pic -O2 -c
#CFLAGS=-fno-druntime -mcmodel=kernel -fno-pie -fno-pic -O2 -fno-stack-check -fconserve-stack -c

#CFLAGS=-betterC -c
ext=.o_shipped
CC_PATH=~/dlang/ldc-1.14.0/activate
SHELL := /bin/bash
SRC=$(wildcard *.d)
TAR=$(SRC:.d=.o_shipped)
#D_FLAGS=-d-version=CONFIG_LOCKDEP,CONFIG_DEBUG_LOCK_ALLOC,CONFIG_DEBUG_SPINLOCK,CONFIG_NETPOLL,CONFIG_64BIT,CONFIG_MUTEX_SPIN_ON_OWNER,CONFIG_DEBUG_MUTEXES,CONFIG_SMP,CONFIG_NET_NS,CONFIG_IPV6,CONFIG_SYSFS,CONFIG_NETFILTER_INGRESS,CONFIG_RFS_ACCEL,CONFIG_XPS,CONFIG_XFRM,CONFIG_IPV6_NDISC_NODETYPE,CONFIG_NET_RX_BUSY_POLL,CONFIG_ARCH_DMA_ADDR_T_64BIT,CONFIG_NEED_SG_DMA_LENGTH,CONFIG_SPARSEMEM,CONFIG_SPARSEMEM_VMEMMAP,CONFIG_NR_CPUS
D_FLAGS=-fversion=CONFIG_LOCKDEP -fversion=CONFIG_DEBUG_LOCK_ALLOC -fversion=CONFIG_DEBUG_SPINLOCK -fversion=CONFIG_NETPOLL -fversion=CONFIG_64BIT -fversion=CONFIG_MUTEX_SPIN_ON_OWNER -fversion=CONFIG_DEBUG_MUTEXES -fversion=CONFIG_SMP -fversion=CONFIG_NET_NS -fversion=CONFIG_IPV6 -fversion=CONFIG_SYSFS -fversion=CONFIG_NETFILTER_INGRESS -fversion=CONFIG_RFS_ACCEL -fversion=CONFIG_XPS -fversion=CONFIG_XFRM -fversion=CONFIG_IPV6_NDISC_NODETYPE -fversion=CONFIG_NET_RX_BUSY_POLL -fversion=CONFIG_ARCH_DMA_ADDR_T_64BIT -fversion=CONFIG_NEED_SG_DMA_LENGTH -fversion=CONFIG_SPARSEMEM -fversion=CONFIG_SPARSEMEM_VMEMMAP -fversion=CONFIG_NR_CPUS

all: build

build: $(TAR) copy

%.o_shipped: %.d
	#source $(CC_PATH) && $(CC) $(CFLAGS) $(D_FLAGS) $< -of=$@
	$(CC) $(CFLAGS) $(D_FLAGS) $< -o $@

copy:
	mv $(TAR) ..

print:
	echo $(TAR)

clean:
	cd .. ; rm -f $(TAR); rm -f virtio_net_tmp* virtio_net.o

