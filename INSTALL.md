Installing cryptmount
=====================

There are three main routes by which cryptmount can be installed
on a Linux-based system:

  * Using a pre-compiled package provided by your flavour of Linux
  * Compiling from a source bundle containing the "configure" script
  * Compiling from a clone of the GitHub repository and using "autoconf" tools

All of these options will, at some stage, require root-level permissions,
such as "sudo".


Distro-provided packages
------------------------

A variety of flavours of Linux provide official pre-built cryptmount packages,
and these can be installed using normal package-management tools. In general,
this is by far the easiest method of installing cryptmount. For example,
on Debian or Ubuntu systems, one can simply run

    sudo apt-get install cryptmount


Manual compilation
------------------

If you want to compile cryptmount from its source-code, perhaps because
you want to customize some of its features, then this may require additional
packages to be available, and should be driven by the "configure" script.

If the configure script is missing, for example if working with a clone of
cryptmount's [GitHub repository](https://github.com/rwpenney/cryptmount),
then you may need to set up [autoconf](https://www.gnu.org/software/autoconf/)
(version 2.61 or later), and then run

    autoreconf -v -i

This `autoreconf` process may require installation of packages such as
automake, autoconf, gettext-devel,
[intltool](https://www.freedesktop.org/wiki/Software/intltool/) etc.


Dependencies
------------

A number of development packages will need to be pre-installed in order
to provide library functions on which cryptmount depends. (The precise
naming of these packages may differ between Linux systems, and
rpm-based systems may require enabling of additional repositories
such as PowerTools or CRB to access these.)
The following packages are essential:

  * kernel-headers (matching the running linux-image)
  * libdevmapper (version 1.02 or later)

The following packages are also strongly recommended, and allow a wider
range of much stronger cryptographic tools:

  * libcryptsetup (version 1.6 or later; this is essential for LUKS support)
  * libgcrypt (version 1.8 or later)
  * libudev (version 232 or later)
  * pkgconf or pkg-config

You will also need to ensure that your system has support for the
loopback and device-mapper devices, which may require loading
of kernel modules when you first use cryptmount, e.g.

    sudo modprobe -a loop dm-crypt

This is automatically performed on system reboot by setup scripts
supplied with cryptmount.


Source configuration
--------------------

The "configure" script will automatically identify the location of
key libraries and header files needed by cryptmount, and allow customization
of the directory locations where cryptmount will be installed.
Typically, one can simply run:

    ./configure

although additional command-line options can also be supplied, such as:

    --prefix=/usr
        # To install beneath /usr rather than /usr/local

    --sysconfdir=/etc/cryptmount
        # To specify the directory where the "cmtab" will be stored

    --disable-luks
        # Turn-off support for LUKS encrypted containers

    --with-systemd
        # Use systemd boot-up configuration, rather than sysvinit

A full list of options can be obtained by running

    ./configure --help


Compilation and installation
----------------------------

If "configure" has run successfully (generating a `config.h` file),
it should now be sufficient to run:

    make
    sudo make install

This should install both the `cryptmount` and `cryptmount-setup` executables,
together with manual pages and an empty filesystem configuration file. Running

    sudo cryptmount-setup

will allow interactive creation of a basic encrypted filesystem
(using LUKS, if available). More sophisticated scenarios can be handled
by manual editing of the `cmtab`, following the guidance in the manual pages:

    man cryptmount
    man 5 cmtab

In outline, if not using the cryptmount-setup script, one can add an
entry to /etc/cryptmount/cmtab that describes the encrypted filesystem
that we want to create:

    crypt {
        dev=/home/crypt.fs dir=/mnt/crypt
        fstype=ext4 mountoptions=defaults
        keyformat=luks
    }

Thereafter, one can prepare the key-file and filing system as follows:

    test -e /home/crypt.fs || sudo dd if=/dev/zero of=/home/crypt.fs bs=1M count=128
    sudo mkdir /mnt/crypt
    sudo cryptmount --generate-key 32 crypt
    sudo cryptmount --prepare crypt
    sudo mke2fs -t ext4 /dev/disk/by-id/dm-name-crypt
    sudo cryptmount --release crypt


Configuring filesystems at system bootup
----------------------------------------

If you want to have encrypted filesystems setup at system boot-up,
this can be achieved using either 'systemd' or the supplied 'initscript'
program which is normally automatically installed as /etc/init.d/cryptmount .
Both of these mechanisms use the `bootaction` parameter within
`/etc/cryptmount/cmtab` to adjust how each filesystem is
handled on system bootup.

If using the `initscript` program, you may need to create symbolic links
from /etc/rc?.d to `/etc/init.d/cryptmount` (in a way that depends
on the precise details of your distribution), with something like

    sudo update-rc.d cryptmount defaults 28

being suitable under Debian systems.


Common problems
---------------

When configuring the system devices needed to support an encrypted filesystem,
cryptmount will issue various requests through the device-mapper library.
Unfortunately, some of the error messages issued by that library
(as of version 1.02) are not easy to interpret.

In situations where the device-mapper is compiled as a kernel module,
an error of the form

    /proc/misc: No entry for device-mapper found
    Is device-mapper driver missing from kernel?
    Failure to communicate with kernel device-mapper driver.

then this may indicate that the dm-mod kernel-module is not loaded.
This can be (temporarily) solved by issuing the command:

    sudo modprobe -a dm-mod dm-crypt

In order to ensure that this happens automatically when you reboot,
you can add a line containing
`dm-mod` to `/etc/modules`, or add a line of the form

    modprobe -q -a dm-mod dm-crypt || true

to `/etc/rc.local`, or ensure that the cryptmount-startup scripts installed
in /etc/init.d are run on system startup (e.g. by installing suitable
symbolic-links from /etc/rc\*.d).

When setting up a new encrypted filing system, typically when issuing a
`cryptmount --prepare` command, you may receive an error message of the form

    device-mapper ioctl cmd 9 failed: Invalid argument

which may mean that you have chosen a key-size that isn't supported by your
chosen cipher algorithm. You can get some information about suitable key-sizes
by checking the output from `more /proc/crypto`, and looking at the
'min keysize' and 'max keysize' fields.)


** *** ***** *******

Please note that cryptmount comes with NO WARRANTY - see the "COPYING" file
in the top-level directory for further details.
