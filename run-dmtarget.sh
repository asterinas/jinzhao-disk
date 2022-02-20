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
		touch disk0
		touch disk1
		touch disk2
		dd if=/dev/zero of=disk0 bs=1M count=128 # 128MB file
		dd if=/dev/zero of=disk1 bs=1M count=128 # 128MB file
		dd if=/dev/zero of=disk2 bs=1M count=128 # 128MB file
		losetup /dev/loop0 disk0
		losetup /dev/loop1 disk1 
		losetup /dev/loop2 disk2 
		;;
	w)
		dd if=/dev/urandom of=/dev/mapper/sworndisk_dev_mapper  bs=64K count=1280
		;;
	r)
		dd if=/dev/mapper/sworndisk_dev_mapper of=out bs=4096 count=128
		;;
	h)
		;;
	m)
		cd ../../
		#make CONFIG_DM_CACHE=m M=drivers/md
		make CONFIG_SWORNDISK=m CONFIG_DM_PERSISTENT_DATA=m M=drivers/md
		make modules_install M=drivers/md
		cd drivers/md
		dmsetup remove sworndisk_dev_mapper
		modprobe -r sworndisk dm-persistent-data 
		modprobe dm-persistent-data
		modprobe sworndisk
		# insmod persistent-data/dm-persistent-data.ko
		# insmod mappery.ko
		echo 0 262144 sworndisk /dev/loop0 /dev/loop1 /dev/loop2 0 | dmsetup create sworndisk_dev_mapper
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
