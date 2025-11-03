#
# rpm spec-file for cryptmount
# (C)Copyright 2006-2025, Holger Mueller, Eriks Zelenka & RW Penney
#
Summary:	Let ordinary users mount an encrypted file system
Name:		cryptmount
Version:	6.3.5
Release:	1%{?dist}
License:	GPL
URL:		https://github.com/rwpenney/cryptmount
Group:		System/Filesystems
Source0:	https://github.com/rwpenney/cryptmount/archive/refs/tags/v%{version}.tar.gz

# Example usage:
#   rpmbuild --build-in-place -bb cryptmount.spec

%if 0%{?fedora}
#{
# Fedora
BuildRequires:  cryptsetup-devel device-mapper-devel libgcrypt-devel
Requires:       cryptsetup-libs libgcrypt device-mapper
#}
%else
#{
%if 0%{?rhel}
#{
# RHEL, CentOS
%if 0%{?rhl} >= 7
BuildRequires:  cryptsetup-devel libgcrypt-devel systemd-devel
Requires:       cryptsetup-libs libgcrypt device-mapper
%else
BuildRequires:  cryptsetup-devel device-mapper-devel libgcrypt-devel
Requires:       cryptsetup-libs device-mapper
%endif
#}
%else
#{
# Default ~openSUSE
BuildRequires:  device-mapper-devel libcryptsetup-devel libgcrypt-devel
Requires:       libcryptsetup12 libgcrypt20 device-mapper
#}
%endif
#}
%endif
BuildRoot:	%{_tmppath}/%{name}-%{version}-root

%description
cryptmount is a utility for the GNU/Linux operating system which allows
an ordinary user to mount an encrypted filing system without requiring
superuser privileges. Filesystems can reside on raw disk partitions or
ordinary files, with cryptmount automatically configuring
device-mapper and loopback devices before mounting.


%prep
%setup -n %{name}-%{version}
%{__perl} -pi.orig -e '
	s|^(\s*)chown(\s*root)|\1echo chown\2|g;
	s|/etc/init.d|%{_initrddir}|g;
    ' Makefile.am Makefile.in


%build
%configure --with-systemd --with-systemd-unit-dir=/usr/lib/systemd/system --enable-delegation --enable-fsck
%{__make} %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
%{__install} -d -m0755 %{buildroot}%{_sbindir}
%{__install} -d -m0755 %{buildroot}/usr/lib/systemd/system
%{__make} DESTDIR=%{buildroot} install
%find_lang %{name}


%clean
%{__rm} -rf %{buildroot}


%files -f %{name}.lang
%defattr(-, root, root, 0755)
%doc AUTHORS ChangeLog COPYING README* RELNOTES
%doc %{_mandir}/man5/cmtab.5*
%doc %{_mandir}/man8/cryptmount*.8*
%doc %{_mandir}/*/man5/cmtab.5*
%doc %{_mandir}/*/man8/cryptmount*.8*
%doc /usr/share/doc/cryptmount/examples/
%config(noreplace) %{_sysconfdir}/cryptmount/
%config /etc/modules-load.d/cryptmount.conf
%config /usr/lib/systemd/system/cryptmount.service
%{_sbindir}/cryptmount-setup

%attr(4751, root, root) %{_bindir}/cryptmount


%post
systemctl enable cryptmount

%preun
if [ "$1" = 0 ]; then
    systemctl disable cryptmount
fi


%changelog
* Sun May 25 2025 RW Penney <cryptmount@rwpenney.uk> - 6.3.1
    -- Updated to prefer systemd and fix build on Rocky-9
* Sun Jul 28 2024 RW Penney <cryptmount@rwpenney.uk> - 6.3.0
    -- Preferred device-mapper paths relocated to /dev/disk/by-id
* Sat Jan 07 2023 RW Penney <cryptmount@rwpenney.uk> - 6.2.0
    -- Enabled libudev by default
* Sat Oct 08 2022 RW Penney <cryptmount@rwpenney.uk> - 6.1.0
    -- Refreshed installation documentation and inter-process locking
* Sat Sep 03 2022 RW Penney <cryptmount@rwpenney.uk> - 6.0
    -- Refreshed default ciphers and keymanager
* Wed Feb 07 2018 RW Penney <cryptmount@rwpenney.uk> - 5.3
    -- Improved support for cryptsetup-2.x
* Thu Oct 08 2015 RW Penney <cryptmount@rwpenney.org.uk> - 5.2
    -- Various bug-fixes and cleanups
* Mon May 04 2015 RW Penney <cryptmount@rwpenney.org.uk> - 5.1
    -- Improved portability across RPM-based systems
* Mon Apr 28 2014 RW Penney <cryptmount@rwpenney.org.uk> - 5.0
    -- Migrated LUKS functionality to use libcryptsetup
* Mon Dec 23 2013 RW Penney <cryptmount@rwpenney.org.uk> - 4.5
    -- Added support for TRIM on SSDs
* Tue May 21 2013 RW Penney <cryptmount@rwpenney.org.uk> - 4.4
    -- Added support systemd
* Thu Dec 29 2011 RW Penney <cryptmount@rwpenney.org.uk> - 4.3
    -- Added support for environmental variables in configuration file
* Tue May 03 2011 RW Penney <cryptmount@rwpenney.org.uk> - 4.2
    -- Added entropy-based protection against accidental swap formatting
* Wed Mar 10 2010 RW Penney <cryptmount@rwpenney.org.uk> - 4.1
    -- Improved compatability with cryptsetup-1.1
* Mon Jan 05 2009 RW Penney <cryptmount@rwpenney.org.uk> - 4.0
    -- Improved password fortification via iterated hashing
* Sun Jan 22 2006 Holger Mueller <holger@MAPS.euhm.de> - 0.1-1mr
    -- RPM spec created
