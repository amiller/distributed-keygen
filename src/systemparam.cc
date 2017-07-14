//  Distributed Key Generator
//  Copyright 2012 Aniket Kate <aniket@mpi-sws.org>, Andy Huang <y226huan@uwaterloo.ca>, Ian Goldberg <iang@uwaterloo.ca>
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of version 3 of the GNU General Public License as
//  published by the Free Software Foundation.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  There is a copy of the GNU General Public License in the COPYING file
//  packaged with this plugin; if you cannot find it, write to the Free
//  Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
//  MA 02110-1301 USA



#include "systemparam.h"

// Read one line (until \n or EOF) from f, allocating memory as
// necessary.

/*static char *readline(FILE *f)
{
    size_t alloced = 0;
    size_t used = 0;
    const size_t inc = 100;
    char *buf = NULL;
    while(1) {
	if (alloced - used <= 1) {  // Allow for NUL at end
	    // Allocate more memory
	    char *newbuf = (char *)realloc(buf, alloced + inc);
	    if (!newbuf) {
		// Badness.
		free(buf);
		return NULL;
	    }
	    buf = newbuf;
	    alloced += inc;
	}
	// Read the next chunk, until \n, EOF, or we've read a whole chunk
	fgets(buf + used, alloced - used, f);
	// Did we see a nl?  If so, chomp it and return
	char *nl = strchr(buf + used, '\n');
	if (nl) {
	    *nl = '\0';
	    return buf;
	}
	// If we hit EOF, return
	if (feof(f)) {
	    return buf;
	}
	// Otherwise, update used and keep going
	used += strlen(buf + used);
    }
}*/

SystemParam::SystemParam(const char *pairingParamFileStr, 
						 const char *sysParamFileStr)
  :e(fopen(pairingParamFileStr,"r")), U(G1(e,true)),n(0),t(0),f(0)
  {
  string typeStr;
  /*  char typeStr[6];
  while (fscanf(sysParamFile, "%s", typeStr) == 1) {
	if(typeStr == "n") {
	  fscanf(sysParamFile, "%u", &n);
	  cerr<<"n is "<<n<<endl;
	  continue;
	}
	if(typeStr == "t") {
	  fscanf(sysParamFile, "%u", &t);
	  cerr<<"t is "<<t<<endl;
	  continue;}
	if(typeStr == "U") {
	  unsigned char* strU = (unsigned char *)readline(sysParamFile);
	  printf("U-str is %s", strU );
	  fflush(stdout);
	  U = G1(e, strU, strlen((char *)strU), false, 10);
	  //U.dump(stderr,"U is",10);
	  free(strU);
	  continue;
	}
	}*/
  fstream sysParamFStream (sysParamFileStr,ios::in);
  while(sysParamFStream >> typeStr)
  	{
	  if(typeStr == "n") {sysParamFStream >> n;continue;}
	  if(typeStr == "t") {sysParamFStream >> t;continue;}
	  if(typeStr == "f") {sysParamFStream >> f;continue;}	  
	  if(typeStr == "U") {
		string strU;
		sysParamFStream >> strU;
		U = G1(e, (unsigned char *)strU.data(), strU.size(), false, 10);
		continue;
      }
	  if(typeStr == "phaseDuration") {
		sysParamFStream>>phaseDuration;continue;
	  }
    }
    if(n < 3*t + 2*f +1) 
    	throw InvalidSystemParamFileException("n,t and f does not follow n >= 3t+ 2f +1");
  sysParamFStream.close();
}
