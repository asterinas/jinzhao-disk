
use data_encoding::HEXLOWER;

use devicemapper::{DevId, DmName, DmOptions, DM, DmResult};

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

    // be careful with the String
    let mut params: String = key_string;
    params += " ";
    params += &iv_string;
    params += " ";
    params += &dev;
    params += " ";
    params += action_flag.to_string().as_str();

    println!("DM table params: {}", params);
    return params;
}

pub fn dm_create_device(dmname: &str, tgt: DmTarget) -> DmResult<()> {
    let offset = tgt.offset;
    let size = tgt.size;
    let dm = DM::new().unwrap();
    let dm_table_params = get_params(tgt);

    let table = vec![(
        offset,
        size,
        "jindisk".into(),
        dm_table_params,
    )];

    let name = DmName::new(dmname).expect("is valid DM name");
    let id = DevId::Name(name);

    dm.device_create(name, None, DmOptions::default())?;

    dm.table_load(&id, &table, DmOptions::default())?;

    dm.device_suspend(&id, DmOptions::default())?;
    Ok(())
}

pub fn dm_remove_device(dmname: &str) -> DmResult<()> {
    let dm = DM::new().unwrap();

    let name = DmName::new(dmname).expect("is valid DM name");
    let id = DevId::Name(name);

    dm.device_remove(&id, DmOptions::default())?;
    Ok(())
}