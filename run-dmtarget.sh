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
		dd if=/dev/zero of=/dev/sdc bs=1M count=4 # Erase superblock 
		;;
	w)
		dd if=/home/lnhoo/dream.txt of=/dev/mapper/sworndisk bs=8624271 count=1
		;;
	r)
		dd if=/dev/mapper/sworndisk of=out bs=8624271 count=1
		;;
	h)
		;;
	m)
		rm -rf -r sworndisk/source/*.o
		rm -rf -r sworndisk.o sworndisk.mod.o sworndisk.ko
		cd ../../
		# make CONFIG_DM_CACHE=m M=drivers/md
		make CONFIG_DM_SWORNDISK=m CONFIG_DM_PERSISTENT_DATA=m M=drivers/md
		make modules_install M=drivers/md
		cd drivers/md
		# dmsetup remove sworndisk
		modprobe -r sworndisk dm-persistent-data 
		modprobe dm-persistent-data
		modprobe sworndisk
		# insmod persistent-data/dm-persistent-data.ko
		# insmod mappery.ko
		echo 0 146800640 sworndisk /dev/sdb /dev/sdc 0 | dmsetup create sworndisk
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
