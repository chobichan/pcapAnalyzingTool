/* ----------------------------------------
 capture data dump
---------------------------------------- */
#include  "..\pcapReader\parser.h"

/* ----------------------------------------
    prototypes 
---------------------------------------- */

/* ----------------------------------------
    instances or global valiables
---------------------------------------- */

/* ----------------------------------------
    constructor and destructor
---------------------------------------- */
PARSER::PARSER( double gmt )
{
  prevCapTimBySec = gmt;
  dataCount = 1;
}

/* ------------------------------------------------------
    parser
------------------------------------------------------ */
void PARSER::parser(
  byte protocol,
  const byte *data, DWORD size,
  const byte *sIP, const byte *dIP, uint16_t sPort, uint16_t dPort,
  double timeStamp )
{
  cout << "    from " << ipv42String( sIP )
       << ":" << sPort << " to " << ipv42String( dIP ) << ":" << dPort
       << " time stamp:" << dateTimeString( timeStamp ) << "(JST)"
       << " delay:" << timeStamp - prevCapTimBySec << "s"
       << endl;
  cout << "    DATA No. " << dataCount++
       << endl;

  byteDump( data, size );
  prevCapTimBySec = timeStamp;
}

