#! /bin/bash
# See http://narendrapal2020.blogspot.com/2014/03/device-mapper.html and
# http://techgmm.blogspot.com/p/writing-your-own-device-mapper-target.html.

usage ()
{
	echo "usage: `basename $0` [-swrh]"
	echo "      -s            setup device mapper target"
	echo "      -w            test using dd write"
	echo "      -r            test using dd read"
	echo "      -h            display help"
}

if ( ! getopts ":swrh" option )
then
       usage
       exit 1
fi

while getopts ':swrhmf' option;
do
	case "$option" in
	s)
		# touch disk0
		# touch disk1
		# dd if=/dev/zero of=disk0 bs=1M count=5120 # 5GB file
		dd if=/dev/zero of=disk1 bs=1M count=128 # 128MB file
		losetup /dev/loop0 disk0
		losetup /dev/loop1 disk1 
		;;
	w)
		# dd if=/dev/urandom of=/dev/mapper/sworndisk  bs=512 count=100
		dd if=/home/lnhoo/Downloads/kfpd.qlv of=/dev/mapper/sworndisk bs=9833460 count=1
		# dd if=/dev/urandom of=/dev/mapper/sworndisk  bs=64K count=1280
		;;
	r)
		dd if=/dev/mapper/sworndisk of=out bs=9833460 count=1
		;;
	h)
		;;
	m)
		rm -rf -r sworndisk/source/*.o
		rm -rf -r sworndisk.o sworndisk.mod.o sworndisk.ko
		cd ../../
		#make CONFIG_DM_CACHE=m M=drivers/md
		make CONFIG_SWORNDISK=m CONFIG_DM_PERSISTENT_DATA=m M=drivers/md
		make modules_install M=drivers/md
		cd drivers/md
		dmsetup remove sworndisk
		modprobe -r sworndisk dm-persistent-data 
		modprobe dm-persistent-data
		modprobe sworndisk
		# insmod persistent-data/dm-persistent-data.ko
		# insmod mappery.ko
		echo 0 10485760 sworndisk /dev/loop0 /dev/loop1 0 | dmsetup create sworndisk
		;;
		
	h)
		usage
		exit
		;;
	\?)
		printf "illegal option: -%s\n" "$OPTARG" >&2
		usage
		exit 1
		;;
	esac
done
shift $((OPTIND - 1))
