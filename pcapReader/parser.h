/* ----------------------------------------
 capture data parser header
---------------------------------------- */
#ifndef  __CAPTURE_PARSER__
#define  __CAPTURE_PARSER__

#include  <windows.h>
#include  <stdio.h>
#include  <stdlib>
#include  <string>
#include  <iostream>

#include  "..\cppLib\strUtil.h"

using namespace std;
/* ----------------------------------------
    prototypes 
---------------------------------------- */
//void parser( const unsigned char *data, DWORD size, const byte *sIP, const byte *dIP, uint16_t sPort, uint16_t dPort );
//void byteDump( const unsigned char *data, DWORD size );

/* ----------------------------------------
    instances or global valiables
---------------------------------------- */

class PARSER : public STR_UTIL
{
public:
  PARSER( double gmt = 0.0 );

  void parser(
    byte protocol,
    const unsigned char *data, DWORD size, const byte *sIP, const byte *dIP, uint16_t sPort, uint16_t dPort,
    double timeStamp );

private:
  double prevCapTimBySec;
  uint32_t dataCount;
};


#endif  /* __CAPTURE_PARSER__ */

