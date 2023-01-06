## JinDisk (Linux) Functionalities

### JinDisk User CLI APIs

Currently, `jindisksetup` provides the following functions.

```
$ jindisksetup action (password) (device) dmname
```

The action can be **create** **open** and **close**.

- jindisksetup **create** *key* *device* *dm_name* - creating and formatting the JinDisk partition using the key

For example, the following creates a root JinDisk partition `/dev/sda1` and maps it to device mapper named `test-jindisk`:

```
$ jindisksetup create password /dev/sda1 test-jindisk
```

- jindisksetup **open** *key* *device* *dm_name* - unlocking the JinDisk partition using the key

For example, the following unlocks a root JinDisk partition `/dev/sda1` and maps it to device mapper named `test-jindisk`:

```
$ jindisksetup open password /dev/sda1 test-jindisk
```

Once opened, the `test-jindisk` device path would be `/dev/mapper/test-jindisk` instead of the partition (e.g. `/dev/sda1`).

### dm-jindisk APIs

Currently, `dm-jindisk` provides these operations: *ctr* and *dtr*.

*ctr* operation invokes the `dm_jindisk_target_ctr` function inside dm-jindisk. This is the constructor function of the target which is called when we create some device of type 'dm_jindisk'.

*dtr* operation invokes the `dm_jindisk_target_dtr`. It is the destruction function, which removes device and decrement device count.

### Mapping table for JinDisk DM target

Mapping table in device mapper is defined like `<start_sector> <size> <target name> <target mapping table>`.

You can also use `dmsetup` to control the underlying dm-jindisk module manually. 

```
$ echo 0 27262976 jindisk <key> <iv> <dev_path> <flag> | sudo dmsetup create test-jindisk
```

Here, `key` should be a 128 bit hexadecimal number (one character represents 4 bits), such as `a7f67ad520bd83b971225df6ebd76c3e`.

`iv` should be a 96 bit hexadecimal number, such as `c01be00ba5f730aacb039e86`.

`flag` is to indicate if the JinDisk device/partition should be formatted. `1` means the disk should be formatted and the disk will be mapped as a new DM target. `0` means we only want to open the encrypted disk using the key we already have.

To uninstall the JinDisk-formatted DM, you probably need to un-mount JinDisk virtual device (if applicable), and then do:

`dmsetup remove test-jindisk` . You can add `--force` or `--retry` to try harder to complete operations.