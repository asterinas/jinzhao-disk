### Usage

```
jindisksetup [FLAGS] [SUBCOMMAND]

FLAGS:

    -h, --help       Prints help information
    -V, --version    Prints version information
    -v               verbosity level

SUBCOMMANDS:

    create    Create a JinDisk device from a file or a partition. A password is required.
    USAGE:
    jindisksetup create [OPTIONS]
    FLAGS:
        -h, --help       Prints help information
        -V, --version    Prints version information
    OPTIONS:
        -d <device_name>        Specify a device to open
        -t <dm_target>          Specify the dm target you want to create
        -p <password>           Specify password
        help      Prints this message or the help of the given subcommand(s)

    open      Open an encrypted JinDisk device. A password is required.
    USAGE:
        jindisksetup open [OPTIONS]
    FLAGS:
        -h, --help       Prints help information
        -V, --version    Prints version information
    OPTIONS:
        -d <device_name>        Specify a device to open
        -t <dm_target>          Specify the dm target you want to create
        -p <password>           Specify password

    close     Close a JinDisk device
    USAGE:
        jindisksetup close [OPTIONS]
    FLAGS:
        -h, --help       Prints help information
        -V, --version    Prints version information
    OPTIONS:
        -t <dm_target>        Specify a dm target
```