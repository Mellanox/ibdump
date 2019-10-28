Summary: Mellanox InfiniBand sniffing application
%define rel %(echo -n "") 

Name: ibdump 
Version: 5.0.0
Release: 5
License: Proprietary 
Group: System Environment/Base
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}
Source: %{name}-%{version}-%{release}.tgz
ExclusiveArch: i386 i486 i586 i686 x86_64 ppc64 ppc64le aarch64

%description
InfiniBand sniffer for MellanoX Technologies LTD. ConnectX HCAs

%prep
%setup -n %{name}-%{version}

%build

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=${RPM_BUILD_ROOT} PREFIX=%{_prefix} ibdump
make DESTDIR=${RPM_BUILD_ROOT} PREFIX=%{_prefix} install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_bindir}/ibdump
%{_bindir}/vpi_tcpdump

%changelog
* Sun Mar 19 2017 Adrian Chiris <adrianc@mellanox.co.il> 5.0.0
   ConnectX-5 Support
* Mon Nov 12 2012 Oren Kladnitsky <orenk@mellanox.co.il> 1.0.6
   Ethernet capture support, vpi_tcpdump
* Thu Nov 24 2011 Oren Kladnitsky <orenk@mellanox.co.il> 1.0.6
   ConnectX-3 Support
* Mon Feb 28 2010 Oren Kladnitsky <orenk@mellanox.co.il> 1.0.3
   initial creation

