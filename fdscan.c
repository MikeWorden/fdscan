
#include "./fdscan.h"
#include <pcap.h>










int  main (int argc, char **argv)
{

  Options CmdLine_Options;
  Options *cOptions = &CmdLine_Options;

  if (Get_Options(argc, argv, cOptions) != 0 ) {
    return 1;
  }
  if (cOptions->file) {
    Open_File(cOptions);
  }
  if (cOptions->interface) {
    Open_Interface(cOptions);

  }
  //Print_Options(cOptions);


  return 0;
}


