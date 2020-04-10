/* ----------------------------------------
    Analyze PCAP format capture data

  reference
  I checked a little about pcap files
  http://sorenuts.hatenablog.com/entry/2018/06/07/195209

  Introduction to Wireshark analysis function
  http://pa.hebikuzure.com/Files/Wireshark_4.pdf

  Transmission Control Protocol wikipedia
  https://ja.wikipedia.org/wiki/Transmission_Control_Protocol

  TCP header format
  https://milestone-of-se.nesuke.com/nw-basic/tcp-udp/tcp-format/
---------------------------------------- */
#include  "pcapReader.h"
#include  "parser.h"

using namespace std;

/* ----------------------------------------
    prototypes 
---------------------------------------- */
void outputEtherFrame( t_ether_frame eth, int index, int type, double nowCapTim, double preCapTim, int len );
void outputIpv4Frame( t_ipv4_frame ipv4, const byte *sIP, const byte *dIP );
void outputUdpFrame( t_udp_frame udp );
void outputTcpFrame( t_tcp_frame tcp, byte *option, uint16_t size );

/* ----------------------------------------
    instances or global valiables
---------------------------------------- */
byte serverIP[4] = {0,0,0,0};  // Explicit zero clear
uint16_t serverPort = 0;  // Explicit zero clear
int protocolTypeNumber = 0;  // Explicit zero clear

PARSER par;
bool silentMode = false;

/* ----------------------------------------
    program main
---------------------------------------- */
int main( int argc, char *argv[] )  /* pcapReader PCAP_FILE 192.168.100.1 OUTPUT_FILE */
{
  int packetIndex = 1;

  cout << "BUILD : " << __DATE__ << " " << __TIME__ << endl;

  if( argc != 4 && argc != 5 )
  {
    cout << "USAGE is : pcapReader TCP PCAP_FILE SERVER_IP:SERVER_PORT > OUTPUT_FILE" << endl;
    cout << "or" << endl;
    cout << "USAGE is : pcapReader UDP PCAP_FILE SERVER_IP:SERVER_PORT > OUTPUT_FILE" << endl;
    cout << "or" << endl;
    cout << "USAGE is : pcapReader UDP PCAP_FILE SERVER_IP:SERVER_PORT -S > OUTPUT_FILE" << endl;

    cout << endl << "    OPTION SWITCHIES" << endl
         << "    : -S : SILENT MODE"
         << endl << endl;

    exit( 1 );
  }

  /* ----------------------------------------------
    is this mode silent mode or verbose mode ?
  ---------------------------------------------- */
  if( argc == 5 )
  {
    string opt = argv[ OPTION_SWITCH ];
    if( opt == "-S" || opt == "-s" ) silentMode = true;
  }

  /* ----------------------------------------------
    pcap file open.
  ---------------------------------------------- */
  std::cout << "PCAP FILE is " << argv[ PCAP_FILE ];
  ifstream pcapFile( argv[ PCAP_FILE ], ios::in | ios::binary );
  if( !pcapFile )
  {
    cout << " file open error." << endl;
    exit( 1 );
  }

  /* ----------------------------------------------
    what protocol type ?
  ---------------------------------------------- */
  if( (string)argv[ POROTOCOL_TYPE ] == "UDP" ) protocolTypeNumber = PROTOCOL_UDP;
  else if( (string)argv[ POROTOCOL_TYPE ] == "TCP" ) protocolTypeNumber = PROTOCOL_TCP;
  else
  {
    cout << "PROTOCOL TYPE is not CORRECT." << endl;
    exit(1);
  }

  /* ----------------------------------------------
    ipv4 address to byte data.
  ---------------------------------------------- */
  string str = argv[ SERVER_IP ];
  int colonIndex = str.find_first_of( ':' );
  if( colonIndex == string::npos )
  {
    cout << endl << "FORMAT is SERVER IP ADDRESS:PORT NUMBER." << endl;
    exit(1);
  }
  else
  {
    string ipStr = str.substr( 0, colonIndex );
    string portStr = str.substr( colonIndex + 1, str.length() - 1 );
    char del = '.';
    int i = 0;
    for( const auto subStr : par.split( str, del ) )
    {
      serverIP[ i++ ] = atoi( subStr.c_str() );
    }
    serverPort = atoi( portStr.c_str() );
    cout << " " << par.ipProtocolString( protocolTypeNumber ) << " server ip = " << par.ipv42String( serverIP ) << ":" << serverPort;
  }
  cout << endl;

  /* ----------------------------------------------
    read pcap file header.
  ---------------------------------------------- */
  t_pcap_header pcapHeader;
  pcapFile.read( (char *)&pcapHeader, sizeof(pcapHeader) );

#if 0
  printf( "    magicNumber = 0x%08X major ver = %d minor ver = %d\n",
    pcapHeader.magic_number,
    pcapHeader.version_major,
    pcapHeader.version_minor
  );
  printf( "    thisZone = %d sigfigs = %d snaplen = %d network = %d\n",
    pcapHeader.thiszone,
    pcapHeader.sigfigs,        /* accuracy of timestamps */
    pcapHeader.snaplen,        /* max length of captured packets, in octets */
    pcapHeader.network        /* data link type */
  );
#endif
  if( pcapHeader.magic_number != 0xA1B2C3D4 )
  {
    cout << endl << "this file was not pcap formated." << endl;
    exit( 1 );
  }
  cout << endl << endl;

  double captureTimeBySec = 0.0;
  double previousCaptureTimeBySec;
  while( !pcapFile.eof() )
  {
    /* ----------------------------------------------
      read packet header.
    ---------------------------------------------- */
    t_packet_header packetHeader;
    pcapFile.read( (char *)&packetHeader, sizeof(packetHeader) );

    captureTimeBySec = packetHeader.ts_sec + (packetHeader.ts_usec / 1000000.0); // Timestamp seconds + microseconds
    time_t unixTime = packetHeader.ts_sec;
    struct tm *capTm = localtime( &unixTime );

    /* ----------------------------------------------
      read whole ethernet frame.
    ---------------------------------------------- */
    byte *payload = new byte[ packetHeader.incl_len ];
    pcapFile.read( (char *)payload, packetHeader.incl_len );
    uint32_t payloadRemainSize = packetHeader.incl_len;
    uint32_t offset = 0;

    /* ----------------------------------------------
      ethernet frame analizing.
    ---------------------------------------------- */
    t_ether_frame etherFrame;
    memcpy( &etherFrame, payload + offset, ETHER_HEADER_SIZE );
    offset += ETHER_HEADER_SIZE;
    payloadRemainSize -= ETHER_HEADER_SIZE;

    uint16_t etherFrameType = par.swapWord( etherFrame.type );
    if( etherFrameType == TYPE_ETHER2_IPV4 )
    {
      /* ----------------------------------------------
        ipv4 frame analizing.
      ---------------------------------------------- */
      t_ipv4_frame ipv4Frame;
      byte sIP[ 4 ];
      byte dIP[ 4 ];

      memcpy( &ipv4Frame, payload + offset, IPV4_HEADER_SIZE );
      uint16_t ipFrameLength = (ipv4Frame.version & 0x0F) * 4;
      offset += ipFrameLength;
      payloadRemainSize = par.swapWord( ipv4Frame.totalLength );
      payloadRemainSize -= ipFrameLength;

      memcpy( sIP, ipv4Frame.ipSource, sizeof(sIP) );
      memcpy( dIP, ipv4Frame.ipDestination, sizeof(dIP) );

      /* tcp or udp frame */
      t_udp_frame udpFrame;
      t_tcp_frame tcpFrame;
      uint16_t sPort = 0;
      uint16_t dPort = 0;
      uint16_t dataOffset = 0;
      byte *tcpOption = nullptr;

      if( ipv4Frame.protocol == PROTOCOL_UDP )  /* UDP */
      {
        memcpy( &udpFrame, payload + offset, UDP_HEADER_SIZE );
        offset += UDP_HEADER_SIZE;
        payloadRemainSize -= UDP_HEADER_SIZE;

        sPort = par.swapWord( udpFrame.sPort );
        dPort = par.swapWord( udpFrame.dPort );
      }
      else if( ipv4Frame.protocol == PROTOCOL_TCP )  /* TCP */
      {
        memcpy( &tcpFrame, payload + offset, TCP_HEADER_SIZE );
        offset += TCP_HEADER_SIZE;
        payloadRemainSize -= TCP_HEADER_SIZE;

        sPort = par.swapWord( tcpFrame.sPort );
        dPort = par.swapWord( tcpFrame.dPort );

        dataOffset = (par.swapWord( tcpFrame.offsetAndFlag ) >> 12) * 4;
        dataOffset -= TCP_HEADER_SIZE;
        tcpOption = new byte[ dataOffset ];
        memcpy( tcpOption, payload + offset, dataOffset );
        offset += dataOffset;
        payloadRemainSize -= dataOffset;
      }

      if( ipv4Frame.protocol == protocolTypeNumber )
      {
        if(
             (ipv4Frame.protocol == PROTOCOL_UDP && memcmp( serverIP, sIP, sizeof(serverIP) ) == 0 && serverPort == sPort)
          || (ipv4Frame.protocol == PROTOCOL_UDP && memcmp( serverIP, dIP, sizeof(serverIP) ) == 0 && serverPort == dPort)
          || (ipv4Frame.protocol == PROTOCOL_TCP && memcmp( serverIP, sIP, sizeof(serverIP) ) == 0 && serverPort == sPort)
          || (ipv4Frame.protocol == PROTOCOL_TCP && memcmp( serverIP, dIP, sizeof(serverIP) ) == 0 && serverPort == dPort)
        )
        {
          /* output informations */
          /* ethernet frame */
          outputEtherFrame(
            etherFrame, packetIndex, etherFrameType, 
            captureTimeBySec, previousCaptureTimeBySec, packetHeader.orig_len );

          /* ipv4 frame */
          outputIpv4Frame( ipv4Frame, (const byte *)sIP, (const byte *)dIP );

          /* tcp or udp frame */
          if( ipv4Frame.protocol == PROTOCOL_UDP )  /* UDP */
          {
            outputUdpFrame( udpFrame );
          }
          else if( ipv4Frame.protocol == PROTOCOL_TCP )  /* TCP */
          {
            outputTcpFrame( tcpFrame, tcpOption, dataOffset );
          }

          /* ----------------------------------------------
            packet dump.
          ---------------------------------------------- */
         if( payloadRemainSize > 0 )
         {
            cout << endl;
            cout << "    PAYLOAD> size:" << payloadRemainSize << "byte" << endl;
            par.parser( ipv4Frame.protocol,
              (const byte *)payload + offset, payloadRemainSize,
              (const byte *)sIP, (const byte *)dIP, sPort, dPort,
              captureTimeBySec );

          }

          cout << endl;
          previousCaptureTimeBySec = captureTimeBySec;

          /* ----------------------------------------------
            packet index increment.
          ---------------------------------------------- */
          packetIndex++;
        }
      }
      if( tcpOption != nullptr ) delete[] tcpOption;
    }
    delete [] payload;
  }

  pcapFile.close();
  return 0;
}


/* ------------------------------------------------------
    output ethernet frame
------------------------------------------------------ */
void outputEtherFrame( t_ether_frame eth, int index, int type,
  double nowCapTim, double preCapTim, int len )
{
  if( !silentMode )
  {
    cout << endl;
    cout << "packet" << std::fixed << par.formatString( "%08d", index ) << endl;
    cout << "    ETHERNET>"
         << " source:" << par.mac2String( eth.src )
         << " destination:" << par.mac2String( eth.dst )
         << " frame type:" << par.ether2TypeString( type )
         << endl;
    cout << "    time stamp:" << std::fixed << std::setprecision(6) << nowCapTim << " "
         << par.dateTimeString( nowCapTim ) << "(JST)"
         << " delay:" << std::fixed << std::setprecision(6) << nowCapTim - preCapTim << "s"
         << endl;
    cout << "    packet size:"
         << len << "byte"  // The actual length of the packet
         << endl;
  }
}


/* ------------------------------------------------------
    output ipv4 frame
------------------------------------------------------ */
void outputIpv4Frame( t_ipv4_frame ipv4, const byte *sIP, const byte *dIP )
{
  if( !silentMode )
  {
    cout << endl;
    cout << "    IPV4>"
         << " source:" << par.ipv42String( sIP )
         << " destination:" <<  par.ipv42String( dIP )
         << " type:" << par.ipProtocolString( ipv4.protocol )
         << endl;

    cout << "    ver:" << (ipv4.version >> 4)
         << " header size:" << (ipv4.version & 0x0F) * 4
         << " TOS:" << (int)ipv4.TOS
         << " packet len:" << par.swapWord( ipv4.totalLength )
         << " id:" << par.swapWord( ipv4.id )
         << " fragment:" << par.word2HexString( par.swapWord( ipv4.fragmentationg ) )
         << " TOL:" << (int)ipv4.TOL
         << " check sum:" << par.word2HexString( par.swapWord( ipv4.checksum ) )
         << endl;
  }
}


/* ------------------------------------------------------
    output udp frame
------------------------------------------------------ */
void outputUdpFrame( t_udp_frame udp )
{
  if( !silentMode )
  {
    uint16_t sPort = par.swapWord( udp.sPort );
    uint16_t dPort = par.swapWord( udp.dPort );
    uint16_t segmentLength = par.swapWord( udp.length );
    uint16_t udpChecksum = par.swapWord( udp.checksum );

    cout << endl;
    cout << "    UDP>"
         << " source port:" << sPort << "(" << par.serviceString( sPort ) << ")"
         << " destination port:" << dPort << "(" << par.serviceString( dPort ) << ")"
         << " segment len:" << segmentLength
         << " check sum:" << par.word2HexString( udpChecksum )
         << endl;
  }
}


/* ------------------------------------------------------
    output tcp frame
------------------------------------------------------ */
void outputTcpFrame( t_tcp_frame tcp, byte *option, uint16_t size )
{
  if( !silentMode )
  {
    uint16_t flags = par.swapWord( tcp.offsetAndFlag );
    uint16_t dataOffset = (flags >> 12) * 4;
    uint16_t sPort = par.swapWord( tcp.sPort );
    uint16_t dPort = par.swapWord( tcp.dPort );
    uint32_t seq = par.swapDWord( tcp.seq );
    uint32_t ack = par.swapDWord( tcp.ack );
    uint16_t window = par.swapWord( tcp.window );
    uint16_t tcpChecksum = par.swapWord( tcp.checksum );
    uint16_t urgent = par.swapWord( tcp.urgent );

    cout << endl;
    cout << "    TCP>"
         << " source:" << sPort << "(" << par.serviceString( sPort ) << ")"
         << " destination:" << dPort << "(" << par.serviceString( dPort ) << ")"
         << " seq:" << seq << "(0x" << par.dword2HexString( seq ) << ")"
         << " ack:" << ack << "(0x" << par.dword2HexString( ack ) << ")"
         << endl;
    cout << "    flag:" << par.tcpFlagString( flags )
         << " offset:" << dataOffset
         << " window:" << window
         << " urgent:" << urgent
         << " check sum:" << par.word2HexString( tcpChecksum )
         << endl;

    if( size > 0 )
    {
      cout << "    OPTION DUMP" << endl;
      par.byteDump( (const byte *)option, size );
    }
  }
}


/* ------------------------------------------------------
    rom file open
------------------------------------------------------ */
HANDLE fileOpen( const char *fileName )
{
  HANDLE fil;
  /* ----------------------------------------------
  Create / Open File
  ---------------------------------------------- */
  // Returns the file handler of the created file
  fil = CreateFile( fileName,   //
                  GENERIC_READ,
                  0,
                  0,
                  OPEN_EXISTING,
                  0,
                  0 ); 
  if( fil == INVALID_HANDLE_VALUE )
  {
    std::cout << fileName << " open error." << std::endl;
    return NULL;
  }

  return fil;
}


