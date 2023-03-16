use nix::{ioctl_read, ioctl_readwrite};

use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;

use nix::errno::Errno;

pub enum DeviceError {
    NotBlockDevice,
    DeviceBusy,
    NoPermission,
    WrongIOCTL,
    WrongSize,
}

// Defined in linux/fs.h
const BLKGETSIZE64_CODE: u8 = 0x12;
const BLKGETSIZE64_SEQ: u8 = 114;
ioctl_read!(ioctl_blkgetsize64, BLKGETSIZE64_CODE, BLKGETSIZE64_SEQ, u64);

// JinDisk interface for querying disk available size
pub struct CalcSectors {
    pub real: u64,
    pub available: u64,
}

const JINDISK_IOC_MAGIC: u8 = b'J';
const NR_CALC_AVAIL_SECTORS: u8 = 0;
ioctl_readwrite!(
    ioctl_jindisk_calc_sector,
    JINDISK_IOC_MAGIC,
    NR_CALC_AVAIL_SECTORS,
    CalcSectors
);

pub fn device_ready(device: &str) -> Result<&str, DeviceError> {
    let meta = fs::metadata(device).unwrap();
    let file_type = meta.file_type();

    if file_type.is_block_device() {
        println!("Device {} is ready.", device);
        return Ok(device);
    } else {
        println!("{} is not a block device!", device);
        return Err(DeviceError::NotBlockDevice);
    }
}

fn ioctl_err_handler(errno: Errno, device_path: &str) -> DeviceError {
    match errno {
        nix::errno::Errno::EBUSY => {
            println!("Cannot use device {} which is in use.", device_path);
            return DeviceError::DeviceBusy;
        }
        nix::errno::Errno::EACCES => {
            println!("Cannot use device {} which is in use.", device_path);
            return DeviceError::NoPermission;
        }
        _ => {
            println!("Cannot get info about device {}.", device_path);
            return DeviceError::WrongIOCTL;
        }
    }
}

/// Determine the device size
fn device_info(device_path: &str) -> Result<u64, DeviceError> {
    device_ready(device_path)?;

    let file = OpenOptions::new().write(true).open(device_path).unwrap();
    let fd = file.as_raw_fd();
    let mut size = 0u64;
    let size_ptr = &mut size as *mut u64;

    unsafe {
        let r = ioctl_blkgetsize64(fd, size_ptr);
        match r {
            Ok(_) => return Ok(size),
            Err(errno) => return Err(ioctl_err_handler(errno, device_path)),
        }
    }
}

fn get_payload_size(disk_size: u64) -> Result<u64, DeviceError> {
    // use std::ffi or a safer OpenOptions to handle the path
    let jindisk_interface = "/dev/jindisk";

    let file = OpenOptions::new()
        .write(true)
        .open(jindisk_interface)
        .unwrap();
    let fd = file.as_raw_fd();
    let mut cs = CalcSectors {
        real: disk_size,
        available: 0,
    };
    let cs_ptr = &mut cs as *mut CalcSectors;

    println!("Querying {} ...", jindisk_interface);
    unsafe {
        let r = ioctl_jindisk_calc_sector(fd, cs_ptr);
        match r {
            Ok(_) => {
                let data_size = cs.available;
                println!("Real size: {}, available size: {}", cs.real, cs.available);
                return Ok(data_size);
            }
            Err(errno) => return Err(ioctl_err_handler(errno, jindisk_interface)),
        }
    }
}

pub fn device_size_adjust(device: &str, device_offset: u64) -> Result<u64, DeviceError> {
    let dev_size = device_info(device)?;
    // every sector has 512 bytes
    let blk_dev_sector_size = dev_size >> 9;

    if device_offset >= blk_dev_sector_size {
        println!("Requested offset is beyond real size of device {}", device);
        return Err(DeviceError::WrongSize);
    }
    let size = blk_dev_sector_size - device_offset;

    let avail_size = get_payload_size(size)?;
    return Ok(avail_size);
}
