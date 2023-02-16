# JinDisk User CLI

JinDisk User CLI is a utility (set) used to conveniently set up disk encryption based on the JinDisk. This is a part of the whole JinDisk project (the other part is dm-jindisk). `jindisksetup` is the command line tool for creating, accessing ,and managing encrypted JinDisk devices. Just like dm-jindisk is an alternative to dm-crypt, `jindisksetup` is a counterpart to cryptsetup. 

This README covers how this user-space CLI utilizes dm-jindisk to encrypt a disk device.

## Software dependencies

Here is the list of packages recommended for the compilation for particular distributions:

- For Debian and Ubuntu: `git gcc make autoconf automake autopoint pkg-config libtool gettext libssl-dev libdevmapper-dev libpopt-dev uuid-dev libssh-dev`. To run the demo(s) you probably also need to install `sharutils dmsetup jq xxd expect keyutils netcat passwd openssh-client sshpass`.

Note that the list could change as the distributions evolve.

## Installation

Download the JinDisk source code and install the user-space CLI.

```bash
sudo apt install build-essential libssl-dev libdevmapper-dev
git clone git@github.com:jinzhao-dev/jinzhao-disk.git
cd jinzhao-disk/user-cli/src/c/
make
sudo make install
```

## Usage

For example, you can use `jindisksetup` to create a device mapper target. The tool will be used as follows:

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

**Note that we support using both ways (jindisksetup/dmsetup) to manipulate dm-jindisk.** Refer to [interfaces.md](../docs/interfaces.md) for more details.

---

To write encrypted data into the partition it must be accessed through the device mapper name. The first step of access will typically be to create a file system. For example:

```
$ mkfs -t ext4 /dev/mapper/test-jindisk
```

- jindisksetup **close** *dm_name* - closing the JinDisk target, unmount the partition and do close

For example:

```
$ jindisksetup close test-jindisk
```
