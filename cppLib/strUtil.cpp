/* ----------------------------------------
  string utiliies

  Reading and writing binary files C ++
  http://gurigumi.s349.xrea.com/programming/binary.html

  How to specify format like printf with std :: string (C ++ 11 version)
  http://pyopyopyo.hatenablog.com/entry/2019/02/08/102456

  C ++ floating point display method
  https://qiita.com/ryu136/items/1cbeb860d4a2f056358a

  How to get part of string with substr function
  https://www.sejuku.net/blog/58892

  How to convert from character string to numeric value
  https://www.sejuku.net/blog/49199
---------------------------------------- */
#include  "strUtil.h"

//using namespace std;

/* ----------------------------------------
    prototypes 
---------------------------------------- */

/* ----------------------------------------
    instances or global valiables
---------------------------------------- */


/* ------------------------------------------------------
    byte dump
------------------------------------------------------ */
void STR_UTIL::byteDump( const byte *data, DWORD size )
{
  uint32_t count = 0;

  while( size )
  {
    string lineHEX = "    ";
    string lineASC = "    ";
    lineHEX += dword2HexString( count ) + " : ";

    for( int col = 0; col < 16; col++ )
    {
      if( size > 0 )
      {
        lineHEX += byte2HexString( *data ) + ",";
        lineASC += isprint(*data) ? (char)*data : '.';
        size--;
      }
      else
      {
        lineHEX += "   ";
      }

      if( col == 7 )
      {
        lineHEX += " ";
        lineASC += " ";
      }
      data++;
    }
    cout << lineHEX << lineASC << endl;
    count += 16;
  }
}


/* ------------------------------------------------------
    hexdecimal to binary
------------------------------------------------------ */
byte STR_UTIL::hex02bin( const char *hex )
{
  unsigned char bin;

  bin = ( (hex[0] & 0xDF) >= 'A' ) ? (hex[0] & 0xDF) - ('A' - 10) : hex[0] - '0';
  bin *= 16;
  bin += ( (hex[1] & 0xDF) >= 'A' ) ? (hex[1] & 0xDF) - ('A' - 10) : hex[1] - '0';
  return bin;
}


/* ------------------------------------------------------
    byte to hexdecimal string
------------------------------------------------------ */
string STR_UTIL::byte2HexString( byte bin )
{
  char buf[4];
  sprintf( buf, "%02X", bin );

  return (string)buf;
}

/* ------------------------------------------------------
    word to hexdecimal string
------------------------------------------------------ */
string STR_UTIL::word2HexString( uint16_t bin )
{
  char buf[8];
  sprintf( buf, "%04X", bin );

  return (string)buf;
}

/* ------------------------------------------------------
    double word to hexdecimal string
------------------------------------------------------ */
string STR_UTIL::dword2HexString( uint32_t bin )
{
  char buf[12];
  sprintf( buf, "%08X", bin );

  return (string)buf;
}


/* ----------------------------------------
    swap WORD
---------------------------------------- */
uint16_t STR_UTIL::swapWord( const byte *data )
{
  uint16_t tempU = *data++ << 8;
  uint16_t tempL = *data;

  return tempU | tempL;
}

/* ----------------------------------------
    swap DWORD
---------------------------------------- */
uint32_t STR_UTIL::swapDWord( const byte *data )
{
  uint32_t tempUU = *data++ << 24;
  uint32_t tempUL = *data++ << 16;
  uint32_t tempLU = *data++ << 8;
  uint32_t tempLL = *data << 0;

  return tempUU | tempUL | tempLU | tempLL;
}


/* ----------------------------------------
    2 byte convert to WORD
---------------------------------------- */
uint16_t STR_UTIL::byte2Word( const byte *data )
{
  uint16_t tempL = *data++ << 0;
  uint16_t tempU = *data << 8;

  return tempU | tempL;
}


/* ----------------------------------------
    4 byte convert to DWORD
---------------------------------------- */
uint32_t STR_UTIL::byte2DWord( const byte *data )
{
  uint32_t tempLL = *data++ << 0;
  uint32_t tempLU = *data++ << 8;
  uint32_t tempUL = *data++ << 16;
  uint32_t tempUU = *data << 24;

  return tempUU | tempUL | tempLU | tempLL;
}


/* ------------------------------------------------------
    mac addree convert hexdecimal string
------------------------------------------------------ */
string STR_UTIL::mac2String( const byte *mac )
{
  char str[32];
  sprintf( str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5] );
  return str;
}


/* ------------------------------------------------------
    ipv4 convert integer string
------------------------------------------------------ */
string STR_UTIL::ipv42String( const byte *ip )
{
  char str[32];
  sprintf( str, "%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3] );
  return str;
}


/* ------------------------------------------------------
    ether2 type string
------------------------------------------------------ */
string STR_UTIL::ether2TypeString( uint16_t type )
{
  string str;

  if( type <= 1500 ) str = "IEEE802.3";
  else if( type == TYPE_ETHER2_IPV4 ) str = "ETHER2 IPV4";
  else if( type == TYPE_ETHER2_ARP ) str = "ETHER2 ARP";
  else if( type == TYPE_ETHER2_Apple_Talk ) str = "ETHER2 Apple Talk";
  else if( type == TYPE_ETHER2_IEEE802_1q ) str = "ETHER2 IEEE802.1q";
  else if( type == TYPE_ETHER2_IPX ) str = "ETHER2 IPX";
  else if( type == TYPE_ETHER2_IPV6 ) str = "ETHER2 IPV6";
  else if( type == TYPE_ETHER2_Realtek_Layer2 ) str = "ETHER2 Realtek Layer 2";
  else str = "ETHER2 UNKNOWN";

  return str;
}


/* ------------------------------------------------------
    ip protocol type string
------------------------------------------------------ */
string STR_UTIL::ipProtocolString( byte prot )
{
  string str;

  if( prot == PROTOCOL_ICMP ) str = "ICMP";
  else if( prot == PROTOCOL_IGMP ) str = "IGMP";
  else if( prot == PROTOCOL_IPV4 ) str = "IPV4";
  else if( prot == PROTOCOL_TCP ) str = "TCP";
  else if( prot == PROTOCOL_EGP ) str = "EGP";
  else if( prot == PROTOCOL_IGP ) str = "IGP";
  else if( prot == PROTOCOL_UDP ) str = "UDP";
  else if( prot == PROTOCOL_IPV6 ) str = "IPV6";
  else if( prot == PROTOCOL_RSVP ) str = "RSVP";
  else if( prot == PROTOCOL_GRE ) str = "GRE";
  else if( prot == PROTOCOL_EIGRP ) str = "EIGRP";
  else if( prot == PROTOCOL_OSPF ) str = "OSPF";
  else if( prot == PROTOCOL_PIM ) str = "PIM";
  else if( prot == PROTOCOL_VRRP ) str = "VRRP";
  else if( prot == PROTOCOL_L2TP ) str = "L2TP";
  else str = "PROTOCO UNKNOWN";

  return str;
}


/* ------------------------------------------------------
    service type string
------------------------------------------------------ */
string STR_UTIL::serviceString( uint16_t service )
{
  string str;

  if( service == SERVICE_ECHO ) str = "ECHO";
  else if( service == SERVICE_DISCARD ) str = "DISCARD";
  else if( service == SERVICE_DAYTIME ) str = "DAYTIME";
  else if( service == SERVICE_FTP_20 ) str = "FTP";
  else if( service == SERVICE_FTP_21 ) str = "FTP";
  else if( service == SERVICE_TELNET ) str = "TELNET";
  else if( service == SERVICE_SMTP ) str = "SMTP";
  else if( service == SERVICE_WHOIS ) str = "WHOIS";
  else if( service == SERVICE_DNS ) str = "DNS";
  else if( service == SERVICE_DHCP_67 ) str = "DHCP";
  else if( service == SERVICE_DHCP_68 ) str = "DHCP";
  else if( service == SERVICE_TFTP ) str = "TFTP";
  else if( service == SERVICE_GOPHER ) str = "GOPHER";
  else if( service == SERVICE_HTTP ) str = "HTTP";
  else if( service == SERVICE_POP3 ) str = "POP3";
  else if( service == SERVICE_AUTH ) str = "AUTH";
  else if( service == SERVICE_SFTP ) str = "SFTP";
  else if( service == SERVICE_NTP ) str = "NTP";
  else if( service == SERVICE_SNMP ) str = "SNMP";
  else if( service == SERVICE_PTP_319 ) str = "PTP";
  else if( service == SERVICE_PTP_320 ) str = "PTP";
  else if( service == SERVICE_HTTPS ) str = "HTTPS";
  else str = "";

  return str;
}


/* ------------------------------------------------------
    tcpflags string
------------------------------------------------------ */
string STR_UTIL::tcpFlagString( uint16_t flg )
{
  string str = "";
  str += (flg & 0x0100) ? "N" : ".";  // NS
  str += (flg & 0x0080) ? "C" : ".";  // CWR
  str += (flg & 0x0040) ? "E" : ".";  // ECE
  str += (flg & 0x0020) ? "U" : ".";  // URG
  str += (flg & 0x0010) ? "A" : ".";  // ACK
  str += (flg & 0x0008) ? "P" : ".";  // PSH
  str += (flg & 0x0004) ? "R" : ".";  // RST
  str += (flg & 0x0002) ? "S" : ".";  // SYN
  str += (flg & 0x0001) ? "F" : ".";  // FIN
  return str;
}


/* ------------------------------------------------------
    date and time string
------------------------------------------------------ */
string STR_UTIL::dateTimeString( time_t sec )
{
  struct tm *Tm = localtime( &sec );
  string dateTime = formatString( "%d/%d/%d %d:%d:%d",
     Tm->tm_year + 1900 ,
     Tm->tm_mon + 1,
     Tm->tm_mday,
     Tm->tm_hour,
     Tm->tm_min,
     Tm->tm_sec
  );

  return dateTime;
}

string STR_UTIL::dateTimeString( double sec )
{
  time_t intSec = (time_t)sec;
  struct tm *Tm = localtime( &intSec );

  string dateTime = formatString( "%d/%d/%d %d:%d:%f",
     Tm->tm_year + 1900 ,
     Tm->tm_mon + 1,
     Tm->tm_mday,
     Tm->tm_hour,
     Tm->tm_min,
     (double)Tm->tm_sec + (sec - (double)intSec)
  );

  return dateTime;
}

string STR_UTIL::dateTimeString( struct tm *Tm )
{
  string dateTime = formatString( "%d/%d/%d %d:%d:%d",
     Tm->tm_year + 1900,
     Tm->tm_mon + 1,
     Tm->tm_mday,
     Tm->tm_hour,
     Tm->tm_min,
     Tm->tm_sec
  );

  return dateTime;
}

string STR_UTIL::dateString( struct tm *Tm )
{
  string dateTime = formatString( "%d/%d/%d",
     Tm->tm_year + 1900,
     Tm->tm_mon + 1,
     Tm->tm_mday
  );

  return dateTime;
}

string STR_UTIL::dateMinuteString( struct tm *Tm )
{
  string dateTime = formatString( "%d/%d/%d %d:%d",
     Tm->tm_year + 1900,
     Tm->tm_mon + 1,
     Tm->tm_mday,
     Tm->tm_hour,
     Tm->tm_min
  );

  return dateTime;
}


/* ------------------------------------------------------
    Formatted string conversion
------------------------------------------------------ */
#if 0
template <typename ... Args>
std::string formatString( const std::string& fmt, Args ... args )
{
  size_t len = std::snprintf( nullptr, 0, fmt.c_str(), args ... );
  std::vector<char> buf(len + 1);
  std::snprintf(&buf[0], len + 1, fmt.c_str(), args ... );

  return std::string(&buf[0], &buf[0] + len);
}
#else
string STR_UTIL::formatString( const char *fmt, ... )
{
  char buf[ 1024 ];
  va_list args;
  va_start( args, fmt );
  vsnprintf( buf, sizeof(buf), fmt, args );
  va_end( args );

  return (string)buf;
}
#endif


/* ----------------------------------------
    split
---------------------------------------- */
std::vector<std::string> STR_UTIL::split( std::string str, char del )
{
  int first = 0;
  int last = str.find_first_of(del);

  std::vector<std::string> result;
  while( first < str.size() )
  {
    std::string subStr( str, first, last - first );
    result.push_back( subStr );
    first = last + 1;
    last = str.find_first_of( del, first );
    if( last == std::string::npos )
    {
      last = str.size();
    }
  }

  return result;
}

