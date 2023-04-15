use data_encoding::HEXLOWER;
use nix::unistd::Uid;
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;

mod backend;
use crate::backend::device::*;
use crate::backend::dm::*;

extern crate clap;
use clap::load_yaml;
use clap::App;

enum SetupErr {
    DeviceError,
    DmTargetError,
}

const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;

fn generate_keyset(password: &str) -> [u8; CREDENTIAL_LEN] {
    // use a fixed round and a fixed salt
    let n_iter = NonZeroU32::new(131072).unwrap();
    let salt = [0u8; CREDENTIAL_LEN];
    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt,
        password.as_bytes(),
        &mut pbkdf2_hash,
    );
    return pbkdf2_hash;
}

fn jindisk_activate(
    device_path: &str,
    dm_name: &str,
    keyset: [u8; 64],
    flag: u64,
) -> Result<(), SetupErr> {
    let mut tgt = DmTarget {
        device: device_path.to_string(),
        offset: 0,
        size: 0,
        action_flag: flag,
        key: keyset,
    };

    let r = get_device_available_size(device_path, tgt.offset);
    match r {
        Ok(adjusted_size) => {
            tgt.size = adjusted_size;
        }
        Err(errortype) => {
            match errortype {
                DeviceError::DeviceBusy => {
                    println!("Cannot use device {} which is in use!", device_path);
                }
                DeviceError::NoPermission => {
                    println!("No permission to access device {}!", device_path);
                }
                DeviceError::WrongIOCTL => {
                    println!("Cannot get info about device {}!", device_path);
                }
                DeviceError::WrongSize => {
                    println!("Requested offset is beyond device {}'s size!", device_path);
                }
                DeviceError::NotBlockDevice => {
                    println!("{} is not a block device!", device_path);
                }
            }
            return Err(SetupErr::DeviceError);
        }
    }

    let r = dm_create_device(dm_name, tgt);
    match r {
        Ok(_) => return Ok(()),
        Err(_) => {
            println!("Set DM target {} failed!", dm_name);
            return Err(SetupErr::DmTargetError);
        }
    }
}

fn jindisk_deactivate(name: &str) -> Result<(), SetupErr> {
    let r = dm_remove_device(name);
    match r {
        Ok(_) => return Ok(()),
        Err(_) => {
            println!("Remove DM target {} failed!", name);
            return Err(SetupErr::DmTargetError);
        }
    }
}

fn action_create(password: &str, data_dev: &str, dm_name: &str) {
    let pbkdf2_hash = generate_keyset(password);
    println!("PBKDF2 hash: {}", HEXLOWER.encode(&pbkdf2_hash));

    match jindisk_activate(data_dev, dm_name, pbkdf2_hash, 1) {
        Ok(_) => println!("JinDisk DM target '{}' created successfully.", dm_name),
        Err(_) => println!("Activation failed!"),
    };
}

fn action_open(password: &str, data_dev: &str, dm_name: &str) {
    let pbkdf2_hash = generate_keyset(password);
    println!("PBKDF2 hash: {}", HEXLOWER.encode(&pbkdf2_hash));

    match jindisk_activate(data_dev, dm_name, pbkdf2_hash, 0) {
        Ok(_) => println!("DM target {} opened.", dm_name),
        Err(_) => println!("Activation failed!"),
    };
}

fn action_close(dm_name: &str) {
    match jindisk_deactivate(dm_name) {
        Ok(_) => println!("JinDisk DM target '{}' closed.", dm_name),
        Err(_) => println!("Deactivation failed!"),
    };
}

fn main() {
    if !Uid::effective().is_root() {
        panic!("You must run this executable with root permissions!");
    }

    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    if let Some(matches) = matches.subcommand_matches("create") {
        let password = matches.value_of("password").expect("`password`is required");
        let device_name = matches
            .value_of("device_name")
            .expect("`device`is required");
        let dm_target = matches.value_of("dm_target").expect("`dmname`is required");
        action_create(password, device_name, dm_target);
    }
    if let Some(matches) = matches.subcommand_matches("open") {
        let password = matches.value_of("password").expect("`password`is required");
        let device_name = matches
            .value_of("device_name")
            .expect("`device`is required");
        let dm_target = matches.value_of("dm_target").expect("`dmname`is required");
        action_open(password, device_name, dm_target);
    }
    if let Some(matches) = matches.subcommand_matches("close") {
        let dm_target = matches.value_of("dm_target").expect("`dmname`is required");
        action_close(dm_target);
    }
}
