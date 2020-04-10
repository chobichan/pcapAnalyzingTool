/* ----------------------------------------
 string utility header

---------------------------------------- */
#ifndef  __STRING_UTILITY__
#define  __STRING_UTILITY__

#include  <windows.h>
#include  <stdio.h>
#include  <stdlib>
#include  <string>
#include  <iostream>
#include  <vector>

#include  "tcpip.h"

using namespace std;
/* ----------------------------------------
    prototypes 
---------------------------------------- */

/* ----------------------------------------
    instances or global valiables
---------------------------------------- */

class STR_UTIL  // : public hoge_class
{
public:
  string formatString( const char *fmt, ... );
  vector<string> split( std::string str, char del );

  void byteDump( const byte *data, DWORD size );

  uint16_t swapWord( const byte *data );
  uint32_t swapDWord( const byte *data );
  uint16_t byte2Word( const byte *data );
  uint32_t byte2DWord( const byte *data );

  byte hex02bin( const char *hex );

  string byte2HexString( byte bin );
  string word2HexString( uint16_t bin );
  string dword2HexString( uint32_t bin );

  string mac2String( const byte *mac );
  string ipv42String( const byte *ip );
  string ether2TypeString( uint16_t type );
  string ipProtocolString( byte prot );
  string tcpFlagString( uint16_t flg );
  string serviceString( uint16_t service );

  string dateTimeString( time_t sec );
  string dateTimeString( double sec );
  string dateTimeString( struct tm *Tm );
  string dateString( struct tm *Tm );
  string dateMinuteString( struct tm *Tm );

private:
};


#endif  /* __STRING_UTILITY__ */

