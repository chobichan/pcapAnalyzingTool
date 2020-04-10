/* ----------------------------------------
    TCP/IP and ETHERNET HEADER
---------------------------------------- */
#ifndef  __TCPIP_HEADER__
#define  __TCPIP_HEADER__

#include  <string>

#define  TYPE_ETHER2_IPV4            0x0800
#define  TYPE_ETHER2_ARP             0x0806
#define  TYPE_ETHER2_Apple_Talk      0x809B
#define  TYPE_ETHER2_IEEE802_1q      0x8100
#define  TYPE_ETHER2_IPX             0x8137
#define  TYPE_ETHER2_IPV6            0x86DD
#define  TYPE_ETHER2_Realtek_Layer2  0x8899


#define  PROTOCOL_ICMP  1
#define  PROTOCOL_IGMP  2
#define  PROTOCOL_IPV4  4
#define  PROTOCOL_TCP   6
#define  PROTOCOL_EGP   8
#define  PROTOCOL_IGP   9
#define  PROTOCOL_UDP   17
#define  PROTOCOL_IPV6  41
#define  PROTOCOL_RSVP  46
#define  PROTOCOL_GRE   47
#define  PROTOCOL_EIGRP 88
#define  PROTOCOL_OSPF  89
#define  PROTOCOL_PIM   103
#define  PROTOCOL_VRRP  112
#define  PROTOCOL_L2TP  115


#define  SERVICE_ECHO      7
#define  SERVICE_DISCARD   9
#define  SERVICE_DAYTIME   13
#define  SERVICE_FTP_20    20
#define  SERVICE_FTP_21    21
#define  SERVICE_TELNET    23
#define  SERVICE_SMTP      25
#define  SERVICE_WHOIS     43
#define  SERVICE_DNS       53
#define  SERVICE_DHCP_67   67
#define  SERVICE_DHCP_68    68
#define  SERVICE_TFTP      69
#define  SERVICE_GOPHER    70
#define  SERVICE_HTTP      80
#define  SERVICE_POP3      110
#define  SERVICE_AUTH      113
#define  SERVICE_SFTP      115
#define  SERVICE_NTP       123
#define  SERVICE_SNMP      161
#define  SERVICE_PTP_319   319
#define  SERVICE_PTP_320   320
#define  SERVICE_HTTPS     443


/* pcap header */
typedef struct T_PCAP_HEADER
{
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} t_pcap_header;

/* packet header */
typedef struct T_PACKET_HEADER
{
  uint32_t ts_sec;    /* タイムスタンプ秒 */
  uint32_t ts_usec;   /* タイムスタンプマイクロ秒 */
  uint32_t incl_len;  /* ファイルに保存されたパケットのオクテット数 */
  uint32_t orig_len;  /* パケットの実際の長さ */
} t_packet_header;


/* ethernet frame */
typedef struct T_ETHERNET_FRAME
{
  byte     dst[6];   /* destination mac address */
  byte     src[6];   /* source mac address */
  byte     type[2];   /* type or length */
} t_ether_frame;

/* ipv4 frame */
typedef struct T_IPV4_FRAME
{
  byte     version;       /* ipv4 version and header length */
  byte     TOS;           /* type of service */
  byte     totalLength[2];   /* total packet length */
  byte     id[2];         /* identification */
  byte     fragmentationg[2];  /* fragmentation */
  byte     TOL;           /* time of live */
  byte     protocol;      /* protocol */
  byte     checksum[2];   /* check sum */
  byte     ipSource[4];      /* source ip address */
  byte     ipDestination[4]; /* destination ip address */
} t_ipv4_frame;


/* udp frame */
typedef struct T_UDP_FRAME
{
  byte     sPort[2];   /* source port */
  byte     dPort[2];   /* destination port */
  byte     length[2];  /* segment length */
  byte     checksum[2];  /* check sum */
} t_udp_frame;


/* tcp frame */
typedef struct T_TCP_FRAME
{
  byte     sPort[2];   /* source port */
  byte     dPort[2];   /* destination port */
  byte     seq[4];     /* sequence number */
  byte     ack[4];     /* acknowledgement number */
  byte     offsetAndFlag[2];     /* data offset and flag */
  byte     window[2];  /* window */
  byte     checksum[2];  /* check sum */
  byte     urgent[2];  /* urgent pointer */
} t_tcp_frame;


#define  ETHER_HEADER_SIZE  sizeof(T_ETHERNET_FRAME)
#define  IPV4_HEADER_SIZE   sizeof(T_IPV4_FRAME)
#define  UDP_HEADER_SIZE    sizeof(T_UDP_FRAME)
#define  TCP_HEADER_SIZE    sizeof(T_TCP_FRAME)


/* ----------------------------------------
    prototypes 
---------------------------------------- */

/* ----------------------------------------
    instances or global valiables
---------------------------------------- */

#endif  /* __TCPIP_HEADER__ */

