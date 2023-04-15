use std::fs;
use std::fs::OpenOptions;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::io::AsRawFd;

use nix::{ioctl_read, ioctl_readwrite};
use nix::errno::Errno;

use derive_more::{Add, Div, From, Into, Mul, Sub};

// Defined in linux/fs.h
const BLKGETSIZE64_CODE: u8 = 0x12;
const BLKGETSIZE64_SEQ: u8 = 114;
ioctl_read!(ioctl_blkgetsize64, BLKGETSIZE64_CODE, BLKGETSIZE64_SEQ, u64);

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Add, Sub, Mul, Div, From, Into)]
pub struct Sectors(pub u64);

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

pub enum DeviceError {
    NotBlockDevice,
    DeviceBusy,
    NoPermission,
    WrongIOCTL,
    WrongSize,
}

impl From<Errno> for DeviceError {
    fn from(errno: Errno) -> Self {
        match errno {
            nix::errno::Errno::EBUSY => {
                return DeviceError::DeviceBusy;
            }
            nix::errno::Errno::EACCES => {
                return DeviceError::NoPermission;
            }
            _ => {
                return DeviceError::WrongIOCTL;
            }
        }
    }
}

/// Check if the input path points to a valid device
pub fn is_device_ready(device: &str) -> Result<&str, DeviceError> {
    let meta = fs::metadata(device).unwrap();
    let file_type = meta.file_type();

    if file_type.is_block_device() {
        return Ok(device);
    } else {
        return Err(DeviceError::NotBlockDevice);
    }
}

/// Determine the device size in bytes
fn fetch_device_size_in_bytes(device_path: &str) -> Result<u64, DeviceError> {
    is_device_ready(device_path)?;

    let file = OpenOptions::new().write(true).open(device_path).unwrap();
    let fd = file.as_raw_fd();
    let mut size = 0u64;
    let size_ptr = &mut size as *mut u64;

    unsafe {
        ioctl_blkgetsize64(fd, size_ptr)?;
    }
    return Ok(size);
}

/// Calculate the payload size of a JinDisk device with the given IOCTL interface
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
    unsafe {
        ioctl_jindisk_calc_sector(fd, cs_ptr)?;
    }
    let data_size = cs.available;
    return Ok(data_size);
}

/// Determine the device size in sectors
pub fn get_device_available_size(device: &str, dev_offset: u64) -> Result<u64, DeviceError> {
    let dev_size_in_bytes = fetch_device_size_in_bytes(device)?;
    // every sector has 512 bytes
    let dev_size_in_sectors: Sectors = (dev_size_in_bytes >> 9).into();
    let dev_offset_in_sectors: Sectors = dev_offset.into();
    if dev_offset_in_sectors >= dev_size_in_sectors {
        return Err(DeviceError::WrongSize);
    }
    let size = dev_size_in_sectors - dev_offset_in_sectors;

    let avail_size = get_payload_size(size.into())?;
    return Ok(avail_size);
}
