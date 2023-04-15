use data_encoding::HEXLOWER;

use devicemapper::{DevId, DmName, DmOptions, DmResult, DM};

#[derive(Debug)]
pub struct DmTarget {
    pub device: String,
    pub key: [u8; 64],
    pub offset: u64,
    pub size: u64,
    pub action_flag: u64,
}

fn get_params(tgt: DmTarget) -> String {
    let kdf_result = tgt.key;

    let key_string = HEXLOWER.encode(&kdf_result[0..16]);
    let iv_string = HEXLOWER.encode(&kdf_result[16..28]);
    let dev = tgt.device;
    let action_flag = tgt.action_flag;

    let params = format!("{} {} {} {}", key_string, iv_string, dev, action_flag);

    println!("DM table params: {}", params);
    return params;
}

pub fn dm_create_device(dmname: &str, tgt: DmTarget) -> DmResult<()> {
    let offset = tgt.offset;
    let size = tgt.size;
    let dm = DM::new().unwrap();
    let dm_table_params = get_params(tgt);

    // The device type should be "jindisk".
    let table = vec![(offset, size, "jindisk".into(), dm_table_params)];
    let name = DmName::new(dmname).expect("is valid DM name");
    let id = DevId::Name(name);

    // Before they can be used, DM devices must be created using DM::device_create(),
    // have a mapping table loaded using DM::table_load(),
    // and then activated with DM::device_suspend(). (This function is used for both suspending and activating a device.)
    // Once activated, they can be used as a regular block device.

    // Create a DM device. It starts out in a "suspended" state
    dm.device_create(name, None, DmOptions::default())?;

    // Load targets for a device into its inactive table slot
    let r = dm.table_load(&id, &table, DmOptions::default());
    // Roll back the side effect of 'device_create' if the 'table_load' failed
    match r {
        Ok(_) => println!("Loading the mapping table..."),
        Err(_) => {
            // Clean up the device
            dm.device_remove(&id, DmOptions::default())?;
        }
    }

    // Resume a DM device (moves a table loaded into the "active" slot)
    // Roll back the side effect of 'device_create' and 'table_load' if the 'device_suspend' failed
    let r = dm.device_suspend(&id, DmOptions::default());
    match r {
        Ok(_) => println!("Activating the mapping table..."),
        Err(_) => {
            // Clear the “inactive” table
            dm.table_clear(&id)?;
            // Clean up the device
            dm.device_remove(&id, DmOptions::default())?;
        }
    }
    Ok(())
}

pub fn dm_remove_device(dmname: &str) -> DmResult<()> {
    let dm = DM::new().unwrap();

    let name = DmName::new(dmname).expect("is valid DM name");
    let id = DevId::Name(name);

    dm.device_remove(&id, DmOptions::default())?;
    Ok(())
}
