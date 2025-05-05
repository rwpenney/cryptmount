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
the [INSTALL.md](https://github.com/rwpenney/cryptmount/blob/master/INSTALL.md)
file in the top directory of the source package.

cryptmount has been tested on a wide variety of GNU/Linux platforms including:
[ArchLinux](https://aur.archlinux.org/packages/cryptmount),
CentOS, [Debian](https://packages.debian.org/stable/cryptmount), Fedora,
[Gentoo](https://packages.gentoo.org/packages/sys-fs/cryptmount),
[Mageia](https://madb.mageia.org/package/show/source/1/application/0/release/cauldron/name/cryptmount),
[Ubuntu](https://packages.ubuntu.com/noble/cryptmount) etc.

For the most recent source-bundles of cryptmount, please see
[GitHub](https://github.com/rwpenney/cryptmount/releases),
where the latest [developer versions](https://github.com/rwpenney/cryptmount)
can also be found.

An encrypted filing system must initially be created by the superuser.
A basic setup can be created interactively by running the `cryptmount-setup`
program, which is typically installed in `/usr/local/sbin/`, and will
use the [LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup)
encryption format by default.

More elaborate situations can be handled by manual editing of the
filesystem definition, typically in `/etc/cryptmount/cmtab`.
For example, an entry of the form:
```
    crypt {
        dev=/home/crypt.fs dir=/mnt/crypt
        fstype=ext4 mountoptions=defaults
        keyformat=luks
    }
```
describes a LUKS-encrypted filesystem to be contained in an ordinary file,
and which will be mounted beneath `/mnt/crypt`.

Such a filesystem could be initialized as follows:
```
    test -e /home/crypt.fs || dd if=/dev/zero of=/home/crypt.fs bs=1M count=128
    mkdir /mnt/crypt
    cryptmount --generate-key 32 crypt
    cryptmount --prepare crypt
    mke2fs -t ext4 /dev/disk/by-id/dm-name-crypt
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


## Signing keys

The current GPG signature used for cryptmount releases
has fingerprint `7A09 0051 9745 19A3 ED1B  D4CB A6CF D54C 4405 160E`.
