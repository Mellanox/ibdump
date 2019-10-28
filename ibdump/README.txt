                            Mellanox Technologies

===============================================================================
                      ibdump 4.0.0 HCA Sniffing Utility 
===============================================================================

===============================================================================
Table of Contents
===============================================================================
1. Overview
2. Supported Systems
3. New features
4. Known Issues
5. Major Bugs Fixed 
6. Changes From Previous versions
===============================================================================
1. Overview
===============================================================================
The ibdump tool dumps InfiniBand traffic that flows to and from 
Mellanox ConnectX®-3/ConnectX®-3 Pro, Connect-IB® and ConnectX®-4 adapter cards.
It provides a similar functionality to the tcpdump tool on an Ethernet network.
The ibdump tool generates packet dump file is in .pcap format. 
This file can be loaded by the Wireshark tool for graphical traffic analysis.  
This provides the ability to analyze network behavior and performance, 
and to debug applications that send or receive InfiniBand network traffic.
Run "ibdump -h" to display a help message which details the tools options.

1.1 How to Get Wireshark
-------------------------------------------------------------------------------
Download the current release from www.wireshark.org for a Linux or Windows
environment.

Note: 
Although ibdump is a Linux application, the generated .pcap file may be
analyzed on either operating system.

Note:
The InfiniBand plug-in released with the current Wireshark version has a basic
IB packets parser which includes Verbs level, IPoIB adn some SMP Mads parsing. 
To get the latest version of the IB plugin, which includes EoIB, 
SDP, and FCoIB parsing, download the latest Wireshark daily build:
- For Windows: Download the exe installer from
  http://www.wireshark.org/download/automated/win32/ and install it
- For Linux: Download the Wireshark dev source tarball from
  http://www.wireshark.org/download/automated/src/ and build it


===============================================================================
2. Supported Systems
===============================================================================
- Linux Operating Systems:
  - All supported MLNX_OFED v3.0-x.0.0 OSes

===============================================================================
3. New Features
===============================================================================
* Added support for ConnectX-4 only in InfiniBand mode.

===============================================================================
4. Known Issues
===============================================================================
* ibdump may encounter packet drops upon a burst of more than 4096 (or
  2^max-burst) packets.
* Packets loss is not reported by ibdump.
* Outbound retransmitted and multicast packets may not be collected correctly.
* Ethernet sniffing is not supported in CX2
* ibdump may stop capturing packets when run on the same port of the Subnet
  Manager (E.G.: opensm). It is advised not to run the SM and ibdump on the same
  port.

===============================================================================
5. Major Bugs Fixed 
===============================================================================
* Fixed an issue causing the sniffed packets' malformation when using mem-mode.
* Fixed a firmware bug that caused the machine to hang up when using ibdump in 
  ConnectX3 ib-mode. 
* Added support for SX sniffing in Connect-IB as an issue in Firmware prevented
  this support in earlier versions.
===============================================================================	 
6. Changes From Previous versions
===============================================================================
6.1 Changes From Version 1.0.5
-------------------------------------------------------------------------------
* Improved capture performance
* Added "--silent" flag: Do not pring progress indication
* Progress indication is refreshed every 1 second in order to save overhead.
 
