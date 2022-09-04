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
or disk partitions.


## Installation

To build cryptmount from source, please follow the instructions in
the file 'INSTALL' in the same directory as this file.
You will need the following packages (including 'developer' add-ons)
installed to successfully build and use cryptmount:

 *  kernel-headers
 *  libdevmapper (e.g. version 1.02 or later)

The following packages are optional, and allow a wider choice
of protection schemes for the keyfiles which govern access
to the protected filesystems:

 *  libcryptsetup (version 1.6 or later)
 *  libgcrypt (e.g. version 1.6.0 or later)

You will also need to ensure that your system has support for the
loopback and device-mapper devices, which may require loading
of kernel modules when you first use cryptmount, e.g.
```modprobe -a loop dm-crypt```
This is automatically performed on system reboot by setup scripts
supplied with cryptmount.

cryptmount has been tested (using the "mudslinger" script
in the 'testing' sub-directory) on a variety of GNU/Linux platforms including:
Debian 9.0, Ubuntu 18.04, CentOS 7.6, ArchLinux etc.

For the most recent version of cryptmount, please see
http://www.sourceforge.net/projects/cryptmount


## Configuration & usage

An encrypted filing system must initially be created by the superuser.
A basic setup can be created interactively by running the 'cryptmount-setup'
program, which is typically installed in /usr/local/sbin/ .

If you wish to use more sophisticated setup options, the setup process
will depend more on the details of the host system
and the encryption algorithms available to the kernel.
The following is an example based on housing a 128Mb AES-encrypted
filing system in an ordinary file ("/home/crypt.fs")
which will be mounted below /mnt/crypt, and where the 256-bit decryption key
is protected by the builtin SHA1/Blowfish encryption engine.

First create a configuration file (by default "/usr/local/etc/cryptmount/cmtab")
that describes the encrypted filing system that we are about to create,
containing:
```
    crypt {
        dev=/home/crypt.fs dir=/mnt/crypt
        fstype=ext2 mountoptions=defaults cipher=aes
        keyfile=/usr/local/etc/cryptmount/crypt.key
        keyformat=builtin
    }
```
Then prepare the key-file and filing system as follows:
```
    cryptmount --generate-key 32 crypt
    dd if=/dev/zero of=/home/crypt.fs bs=1M count=128
    mkdir /mnt/crypt
    cryptmount --prepare crypt
    mke2fs /dev/mapper/crypt
    cryptmount --release crypt
```
A very similar process can be used to setup an encrypted filing system using
a raw disk partition in place of a loopback file.

Thereafter, all information about the encrypted filing systems available
for mounting with cryptmount is contained in /usr/local/etc/cryptmount/cmtab .
So, the following command, executed by an ordinary user,
will make the filing system accessible below /mnt/crypt:
```
    cryptmount crypt
```
and the following will unmount it:
```
    cryptmount -u crypt
```
Please take great care that you do not delete or corrupt the key-file,
as this will make access to your filesystem (essentially) impossible.
You are strongly advised to consider keeping a backup copy of the key-file.


## Configuring filesystems at system bootup

If you want to have encrypted filesystems setup at system boot-up,
this can be achieved using either 'systemd' or the supplied 'initscript'
program which is normally automatically installed as /etc/init.d/cryptmount .
Both of these mechanisms use the 'bootaction' parameter within
/usr/local/etc/cryptmount/cmtab to adjust how each filesystem is
handled on system bootup.

If using the 'initscript' program, you may need to create symbolic links
from /etc/rc?.d to /etc/init.d/cryptmount (in a way that depends
on the precise details of your distribution), with something like
'update-rc.d cryptmount defaults 28' being suitable under Debian systems.


## Common problems

When configuring the system devices needed to support an encrypted filesystem,
cryptmount will issue various requests through the device-mapper library.
Unfortunately, many of the error messages issued by that library
(as of version 1.02) are not easy to interpret.

In situations where the device-mapper is compiled as a kernel module,
an error of the form
```
    /proc/misc: No entry for device-mapper found
    Is device-mapper driver missing from kernel?
    Failure to communicate with kernel device-mapper driver.
```
then this may indicate that the dm-mod kernel-module is not loaded.
This can be (temporarily) solved by issuing the command:
    modprobe -a dm-mod dm-crypt
as root (or 'sudo modprobe ...'). In order to ensure that this
happens automatically when you reboot, you can add a line containing
"dm-mod" to /etc/modules, or add a line of the form
```
    modprobe -q -a dm-mod dm-crypt || true
```
to /etc/rc.local, or ensure that the cryptmount-startup scripts installed
in /etc/init.d are run on system startup (e.g. by installing suitable
symbolic-links from /etc/rc*.d).

When setting up a new encrypted filing system, typically when issuing a
'cryptmount --prepare' command, you may receive an error message of the form
```
    device-mapper ioctl cmd 9 failed: Invalid argument
```
which may mean that you have chosen a key-size that isn't supported by your
chosen cipher algorithm. You can get some information about suitable key-sizes
by checking the output from 'more /proc/crypto', and looking at the
'min keysize' and 'max keysize' fields.)


## Suggestions/Patches

You are welcome to send constructive suggestions and bug-fixes to the author:
    rwpenney _AT_ users.sourceforge.net
Any feedback (including the associated log-file) from running the "mudslinger"
tests on any systems not listed above would be particularly helpful.
