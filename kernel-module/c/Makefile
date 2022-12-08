KER_SRC			:= /lib/modules/$(shell uname -r)/build

ifeq (${DEBUG}, 1)
	ccflags-y	+= -g -DDEBUG
endif

jindisk-objs		+= src/dm-jindisk.o src/metadata.o src/memtable.o      \
			   src/lsm_tree.o src/crypto.o src/segment_buffer.o    \
			   src/segment_allocator.o src/journal.o src/cache.o   \
			   src/disk_structs.o src/async.o

obj-m			+= jindisk.o

all:
	make -C ${KER_SRC} M=$(PWD) modules
clean:
	make -C ${KER_SRC} M=$(PWD) clean
