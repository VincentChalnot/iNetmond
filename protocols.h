/* 
 * File:   protocols.h
 * Author: root
 *
 * Created on March 24, 2011, 3:10 PM
 */
static const char* IP_PROTOS[256]={
    "HOPOPT",  /* 0 IPv6 Hop-by-Hop Option */
    "ICMP",  /* 1 Internet Control Message */
    "IGMP",  /* 2 Internet Group Management */
    "GGP",  /* 3 Gateway-to-Gateway */
    "IPv4",  /* 4 IPv4 encapsulation */
    "ST",  /* 5 Stream */
    "TCP",  /* 6 Transmission Control */
    "CBT",  /* 7 CBT */
    "EGP",  /* 8 Exterior Gateway Protocol */
    "IGP",  /* 9 any private interior gateway (used by Cisco for their IGRP) */
    "BBN-RCC-MON",  /* 10 BBN RCC Monitoring */
    "NVP-II",  /* 11 Network Voice Protocol */
    "PUP",  /* 12 PUP */
    "ARGUS",  /* 13 ARGUS */
    "EMCON",  /* 14 EMCON */
    "XNET",  /* 15 Cross Net Debugger */
    "CHAOS",  /* 16 Chaos */
    "UDP",  /* 17 User Datagram */
    "MUX",  /* 18 Multiplexing */
    "DCN-MEAS",  /* 19 DCN Measurement Subsystems */
    "HMP",  /* 20 Host Monitoring */
    "PRM",  /* 21 Packet Radio Measurement */
    "XNS-IDP",  /* 22 XEROX NS IDP */
    "TRUNK-1",  /* 23 Trunk-1 */
    "TRUNK-2",  /* 24 Trunk-2 */
    "LEAF-1",  /* 25 Leaf-1 */
    "LEAF-2",  /* 26 Leaf-2 */
    "RDP",  /* 27 Reliable Data Protocol */
    "IRTP",  /* 28 Internet Reliable Transaction */
    "ISO-TP4",  /* 29 ISO Transport Protocol Class 4 */
    "NETBLT",  /* 30 Bulk Data Transfer Protocol */
    "MFE-NSP",  /* 31 MFE Network Services Protocol */
    "MERIT-INP",  /* 32 MERIT Internodal Protocol */
    "DCCP",  /* 33 Datagram Congestion Control Protocol */
    "3PC",  /* 34 Third Party Connect Protocol */
    "IDPR",  /* 35 Inter-Domain Policy Routing Protocol */
    "XTP",  /* 36 XTP */
    "DDP",  /* 37 Datagram Delivery Protocol */
    "IDPR-CMTP",  /* 38 IDPR Control Message Transport Proto */
    "TP++",  /* 39 TP++ Transport Protocol */
    "IL",  /* 40 IL Transport Protocol */
    "IPv6",  /* 41 IPv6 encapsulation */
    "SDRP",  /* 42 Source Demand Routing Protocol */
    "IPv6-Route",  /* 43 Routing Header for IPv6 */
    "IPv6-Frag",  /* 44 Fragment Header for IPv6 */
    "IDRP",  /* 45 Inter-Domain Routing Protocol */
    "RSVP",  /* 46 Reservation Protocol */
    "GRE",  /* 47 General Routing Encapsulation */
    "DSR",  /* 48 Dynamic Source Routing Protocol */
    "BNA",  /* 49 BNA */
    "ESP",  /* 50 Encap Security Payload */
    "AH",  /* 51 Authentication Header */
    "I-NLSP",  /* 52 Integrated Net Layer Security  TUBA */
    "SWIPE",  /* 53 IP with Encryption */
    "NARP",  /* 54 NBMA Address Resolution Protocol */
    "MOBILE",  /* 55 IP Mobility */
    "TLSP",  /* 56 Transport Layer Security Protocol using Kryptonet key management */
    "SKIP",  /* 57 SKIP */
    "IPv6-ICMP",  /* 58 ICMP for IPv6 */
    "IPv6-NoNxt",  /* 59 No Next Header for IPv6 */
    "IPv6-Opts",  /* 60 Destination Options for IPv6 */
    "",  /* 61 any host internal protocol */
    "CFTP",  /* 62 CFTP */
    "",  /* 63 any local network */
    "SAT-EXPAK",  /* 64 SATNET and Backroom EXPAK */
    "KRYPTOLAN",  /* 65 Kryptolan */
    "RVD",  /* 66 MIT Remote Virtual Disk Protocol */
    "IPPC",  /* 67 Internet Pluribus Packet Core */
    "",  /* 68 any distributed file system */
    "SAT-MON",  /* 69 SATNET Monitoring */
    "VISA",  /* 70 VISA Protocol */
    "IPCV",  /* 71 Internet Packet Core Utility */
    "CPNX",  /* 72 Computer Protocol Network Executive */
    "CPHB",  /* 73 Computer Protocol Heart Beat */
    "WSN",  /* 74 Wang Span Network */
    "PVP",  /* 75 Packet Video Protocol */
    "BR-SAT-MON",  /* 76 Backroom SATNET Monitoring */
    "SUN-ND",  /* 77 SUN ND PROTOCOL-Temporary */
    "WB-MON",  /* 78 WIDEBAND Monitoring */
    "WB-EXPAK",  /* 79 WIDEBAND EXPAK */
    "ISO-IP",  /* 80 ISO Internet Protocol */
    "VMTP",  /* 81 VMTP */
    "SECURE-VMTP",  /* 82 SECURE-VMTP */
    "VINES",  /* 83 VINES */
    "TTP/IPTM",  /* 84 TTP / Protocol Internet Protocol Traffic Manager */
    "NSFNET-IGP",  /* 85 NSFNET-IGP */
    "DGP",  /* 86 Dissimilar Gateway Protocol */
    "TCF",  /* 87 TCF */
    "EIGRP",  /* 88 EIGRP */
    "OSPFIGP",  /* 89 OSPFIGP */
    "Sprite-RPC",  /* 90 Sprite RPC Protocol */
    "LARP",  /* 91 Locus Address Resolution Protocol */
    "MTP",  /* 92 Multicast Transport Protocol */
    "AX.25",  /* 93 AX.25 Frames */
    "IPIP",  /* 94 IP-within-IP Encapsulation Protocol */
    "MICP",  /* 95 Mobile Internetworking Control Pro. */
    "SCC-SP",  /* 96 Semaphore Communications Sec. Pro. */
    "ETHERIP",  /* 97 Ethernet-within-IP Encapsulation */
    "ENCAP",  /* 98 Encapsulation Header */
    "",  /* 99 any private encryption scheme */
    "GMTP",  /* 100 GMTP */
    "IFMP",  /* 101 Ipsilon Flow Management Protocol */
    "PNNI",  /* 102 PNNI over IP */
    "PIM",  /* 103 Protocol Independent Multicast */
    "ARIS",  /* 104 ARIS */
    "SCPS",  /* 105 SCPS */
    "QNX",  /* 106 QNX */
    "A/N",  /* 107 Active Networks */
    "IPComp",  /* 108 IP Payload Compression Protocol */
    "SNP",  /* 109 Sitara Networks Protocol */
    "Compaq-Peer",  /* 110 Compaq Peer Protocol */
    "IPX-in-IP",  /* 111 IPX in IP */
    "VRRP",  /* 112 Virtual Router Redundancy Protocol */
    "PGM",  /* 113 PGM Reliable Transport Protocol */
    "",  /* 114 any 0-hop protocol */
    "L2TP",  /* 115 Layer Two Tunneling Protocol */
    "DDX",  /* 116 D-II Data Exchange (DDX) */
    "IATP",  /* 117 Interactive Agent Transfer Protocol */
    "STP",  /* 118 Schedule Transfer Protocol */
    "SRP",  /* 119 SpectraLink Radio Protocol */
    "UTI",  /* 120 UTI */
    "SMP",  /* 121 Simple Message Protocol */
    "SM",  /* 122 SM */
    "PTP",  /* 123 Performance Transparency Protocol */
    "ISIS over IPv4",  /* 124 */
    "FIRE",  /* 125 */
    "CRTP",  /* 126 Combat Radio Transport Protocol */
    "CRUDP",  /* 127 Combat Radio User Datagram */
    "SSCOPMCE",  /* 128 */
    "IPLT",  /* 129 */
    "SPS",  /* 130 Secure Packet Shield */
    "PIPE",  /* 131 Private IP Encapsulation within IP */
    "SCTP",  /* 132 Stream Control Transmission Protocol */
    "FC",  /* 133 Fibre Channel */
    "RSVP-E2E-IGNORE",  /* 134 */
    "Mobility Header",  /* 135 */
    "UDPLite",  /* 136 */
    "MPLS-in-IP",  /* 137 */
    "manet",  /* 138 MANET Protocols */
    "HIP",  /* 139 Host Identity Protocol */
    "Shim6",  /* 140 Shim6 Protocol */
    "WESP",  /* 141 Wrapped Encapsulating Security Payload */
    "ROHC",  /* 142 Robust Header Compression */
    /* 143-252 Unassigned */
};  /* 255 Reserved */
