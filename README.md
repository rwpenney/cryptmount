# Cryptmount - user-mode management of Linux encrypted filesystems

cryptmount allows any user to access encrypted filing systems on demand
under GNU/Linux systems running at least a 2.6-series kernel.
It also assists the system administrator in creating and managing
encrypted filesystems based on the kernel's dm-crypt device-mapper target.

After initial configuration by the superuser, an ordinary user can
mount or unmount filesystems managed by cryptmount solely by providing
the decryption password, with any system devices needed to access
the filing system being configured automatically. A wide variety of
encryption schemes (provided by the kernel and the libgcrypt library)
can be used to protect both the filing system and the access key.
The protected filing systems can reside in either ordinary files,
or raw disk partitions.


## Installation

To build cryptmount from source, please follow the instructions in
the file 'INSTALL.md' in the same directory as this file.

cryptmount has been tested (using the ["mudslinger"](testing/mudslinger.in) script
on a variety of GNU/Linux platforms including:
Debian 11.0, Ubuntu 20.04, CentOS 7.6, ArchLinux etc.

For the most recent source-bundles of cryptmount, please see
[Sourceforge](http://www.sourceforge.net/projects/cryptmount).

An encrypted filing system must initially be created by the superuser.
A basic setup can be created interactively by running the `cryptmount-setup`
program, which is typically installed in `/usr/local/sbin/`, and will
use the [LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup)
encryption format by default.

More elaborate situations can be handled by manual editing of the
filesystem definition, typically in `/etc/cryptmount/cmtab`
or `/usr/local/etc/cryptmount/cmtab`. For example, an entry of the form:
```
    crypt {
        dev=/home/crypt.fs dir=/mnt/crypt
        fstype=ext4 mountoptions=defaults
        keyformat=luks
    }
```
Describes a LUKS-encrypted filesystem to be contained in an ordinary file,
and which will be mounted beneath `/mnt/crypt`.

Such a filesystem could be initialized as follows:
```
    test -e /home/crypt.fs || dd if=/dev/zero of=/home/crypt.fs bs=1M count=128
    mkdir /mnt/crypt
    cryptmount --generate-key 32 crypt
    cryptmount --prepare crypt
    mke2fs -t ext4 /dev/mapper/crypt
    cryptmount --release crypt
```
Further details are available in the installed manual pages.

Thereafter, the following command, executed by an ordinary user,
will make the filing system accessible below /mnt/crypt:
```
    cryptmount crypt
```
and the following will unmount it:
```
    cryptmount -u crypt
```

If using a separate keyfile, please take great care that you do not delete
that file, as this will make access to your filesystem (essentially) impossible.
You are strongly advised to keep a backup copy of the key-file.
