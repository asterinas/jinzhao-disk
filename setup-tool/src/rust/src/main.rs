use std::os::raw::c_int;
use std::os::raw::c_uchar;

use data_encoding::HEXLOWER;
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;

#[macro_use]
extern crate clap;
use clap::App;

#[link(name = "dm_jindisk")]
extern "C" {
    fn jindisk_activate(
        device_path: *const c_uchar,
        name: *const c_uchar,
        keyset: *const c_uchar,
        keysize: u32,
        action_flag: u64,
    ) -> c_int;

    fn jindisk_deactivate(name: *const c_uchar) -> c_int;
}

fn action_create(password: &str, data_dev: &str, dm_name: &str) {
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
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
    println!("PBKDF2 hash: {}", HEXLOWER.encode(&pbkdf2_hash));
    
    unsafe {
        match jindisk_activate(
            data_dev.as_ptr(),
            dm_name.as_ptr(),
            pbkdf2_hash.as_mut_ptr(),
            128,
            1,
        ) {
            0 => println!("Activation done."),
            _ => println!("Activation failed!"),
        };
    }
}

fn action_open(password: &str, data_dev: &str, dm_name: &str) {
    const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;
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
    println!("PBKDF2 hash: {}", HEXLOWER.encode(&pbkdf2_hash));
    
    unsafe {
        match jindisk_activate(
            data_dev.as_ptr(),
            dm_name.as_ptr(),
            pbkdf2_hash.as_mut_ptr(),
            128,
            0,
        ) {
            0 => println!("Activation done."),
            _ => println!("Activation failed!"),
        };
    }
}

fn action_close(dm_name: &str) {
    unsafe {
        match jindisk_deactivate(dm_name.as_ptr()) {
            0 => println!("Activation done."),
            _ => println!("Activation failed!"),
        };
    }
}

fn main() {
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
