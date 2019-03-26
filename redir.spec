Name:           redir
Version:        3.3
Release:        1%{?dist}
Summary:        Redirect TCP connections

Group:          Applications/Internet
License:        GPL+
URL:            http://sammy.net/~sammy/hacks/
Source0:	https://github.com/troglobit/redir/releases/download/v%{version}/%{name}-%{version}.tar.xz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

#BuildRequires: /usr/include/tcpd.h

%description
a port redirector, used to forward incoming connections to somewhere else.
by far the cleanest piece of code here, because someone else liked it
enough to fix it.

%prep
%setup -q


%build
./configure --prefix=/usr
make %{?_smp_mflags} CFLAGS="$RPM_OPT_FLAGS" LDFLAGS="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
install -Dp -m 755 %{name} $RPM_BUILD_ROOT%{_sbindir}/%{name}
install -Dp -m 644 %{name}.1 $RPM_BUILD_ROOT%{_mandir}/man1/%{name}.1


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc README.md ChangeLog.md COPYING trans*.txt
%{_sbindir}/%{name}
%{_mandir}/man1/%{name}.1*

%changelog
