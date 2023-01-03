# JinDisk-Setup

JinDisk-Setup is a utility (set) used to conveniently set up disk encryption based on the our newly-proposed secure I/O solution for TEEs - jindisk.

It can help Guest Owner to transform his/her plain base image to a encrypted jindisk image. And inside the repo there is a jindisksetup command can be used to manage a jindisk-formatted partition by creating, controlling, and removing a jindisk DM target.

Jindisk-Setup is a part of the whole Jindisk-Linux project (the other part is dm-jindisk).

This repository contains source, scripts, and configuration files for several tools that can be used together to demonstrate one way to perform remote attestation.

This (README) guide also covers the usage and configuration of deploying a confidential VM image from the Guest Owner's perspective. 


### Usage

jindisksetup is the command line tool for creating, accessing and managing encrypted jindisk devices. Just like dm-jindisk is an alternative of dm-crypt, jindisksetup is as a counterpart to cryptsetup. This section covers how to utilize dm-jindisk from the command line to encrypt a system.

For example, you can use `jindisksetup` to create a device mapper target. The tool will be used as follows:

```
$ jindisksetup action (device) dmname
```

The action can be **create** **open** and **close**.

- jindisksetup **create** *key* *device* *dm_name* - creating and formatting the jindisk partition using the key

For example, the following creates a root jindisk partition `/dev/sda1` and maps it to device mapper named `test-jindisk`:

```
$ jindisksetup create password /dev/sda1 test-jindisk
```

- jindisksetup **open** *key* *device* *dm_name* - unlocking the jindisk partition using the key

For example, the following unlocks a root jindisk partition `/dev/sda1` and maps it to device mapper named `test-jindisk`:

```
$ jindisksetup open password /dev/sda1 test-jindisk
```

Once opened, the `test-jindisk` device path would be `/dev/mapper/test-jindisk` instead of the partition (e.g. `/dev/sda1`).

**Note that we support to use both ways (jindisksetup/dmsetup) to manipulate dm-jindisk.** Refer to [interfaces.md](../docs/interfaces.md) for more details.

---

In order to write encrypted data into the partition it must be accessed through the device mapped name. The first step of access will typically be to create a file system. For example:

```
$ mkfs -t ext4 /dev/mapper/test-jindisk
```

- jindisksetup **close** *dm_name* - closing the jindisk target, unmount the partition and do close

For example:

```
$ jindisksetup close test-jindisk
```

### Software dependencies

Here is the list of packages needed for the compilation of project for particular distributions:

- For Debian and Ubuntu: `git gcc make autoconf automake autopoint pkg-config libtool gettext libssl-dev libdevmapper-dev libpopt-dev uuid-dev libssh-dev`. To run the internal testsuite you also need to install `sharutils dmsetup jq xxd expect keyutils netcat passwd openssh-client sshpass`.

Note that the list could change as the distributions evolve.

### Installation

Download JinDisk source code and install user-space CLI.

```bash
sudo apt install openssl libssl-dev libdevmapper-dev
git clone git@github.com:jinzhao-dev/jindisk.git
cd jindisk/user-cli/src/c/
make
sudo make install
```
