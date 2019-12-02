<p align="center">

  ### Mellanox Technologies
  <br><br>
   ## ibdump HCA Sniffing Utility

</p>

# Table of Contents
1. Overview
2. How to get Wireshark
3. Known Issues
4. How to Compile




# 1. Overview
The ibdump tool dumps InfiniBand traffic that flows to and from Mellanox 
adapter cards and provides a similar functionality to the tcpdump tool 
on an Ethernet network.
The ibdump tool generates a packet dump file in .pcap format, the file can 
be loaded by the Wireshark tool for graphical traffic analysis.  
Using this tool enables the user to analyze network behavior and performance, 
and to debug applications that send or receive InfiniBand network traffic.
To display a help message which details the tools options run "ibdump -h". 




# 2. How to Get Wireshark
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




# 3. Known Issues
* ibdump may encounter packet drops upon a burst of more than 4096 (or
  2^max-burst) packets.
* Packets loss is not reported by ibdump.
* Outbound retransmitted and multicast packets may not be collected correctly.
* ibdump may stop capturing packets when run on the same port of the Subnet
  Manager (E.G.: opensm). It is advised not to run the SM and ibdump on the same
  port.




# 4. How to Compile
Setup desired                           | Compilation command
MFT Library + OFED kernel               | make
MFT Library + UPSREAM Kernel	        | make UPSTREAM_KERNEL=yes
MSTFLINT Library + OFED kerne           | make WITH_MSTFLINT=yes
MSTFLINT Library + UPSREAM kernel       | make WITH_MSTFLINT=yes UPSTREAM_KERNEL=yes
Without FW tools	                    | make WITHOUT_FW_TOOLS=yes
