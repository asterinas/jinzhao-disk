KER_SRC		:= /lib/modules/$(shell uname -r)/build
# KER_SRC	:= /home/qingsong/workspace/linux-stable

ccflags-y	+= -I${KER_SRC}/drivers/md

sworndisk-objs	+= source/dm-sworndisk.o source/metadata.o source/memtable.o \
		   source/bio_operate.o source/crypto.o \
		   source/segment_allocator.o source/segment_buffer.o \
		   source/cache.o source/disk_structs.o source/lsm_tree.o \
		   source/bloom_filter.o source/async.o source/hashtable.o \
		   source/journal.o

obj-m		+= sworndisk.o

all:
	make -C ${KER_SRC} M=$(PWD) modules
clean:
	make -C ${KER_SRC} M=$(PWD) clean
