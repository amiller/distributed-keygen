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



#ifndef __SYSTEM_PARAM_H__
#define __SYSTEM_PARAM_H__

#include "PBC/PBC.h"
#include "exceptions.h"

#include <fstream>
#include <string>
#include <iostream>

using namespace std;

typedef unsigned short NodeID;
typedef unsigned short NodeIDSize;
#define NODEID_NONE 0xffff
typedef unsigned int Phase;


class SystemParam{
public:
  SystemParam(const char* pairingParamFileStr = "pairing.param",
			  const char* sysParamFileStr = "system.param");
  //SystemParam(FILE *pairingParamFile = fopen("pairing.param", "r"),
  //	  FILE* sysParamFile = fopen("system.param", "r"));
  ~SystemParam(){};
  NodeID get_n () const {return n; }
  void set_n(NodeID nodeCount){ n= nodeCount; }
  NodeID get_t () const{ return t; }
  void set_t(NodeID threshold){ t = threshold; }
  NodeID get_f () const{ return f; }
  void set_f(NodeID threshold){ f = threshold; }
  const G1& get_U () const{return U;}
  const Pairing& get_Pairing () const{return e;}

private:    
  // Prevent copying
  SystemParam(const SystemParam &s);
  SystemParam &operator=(const SystemParam &rhs);

  const Pairing e;
  G1 U;//Generator used
  NodeID n; //Number of Nodes
  NodeID t; //Byzantine Threshold
  NodeID f; //Crash-Recovery and Link Failure Threshold 
  float phaseDuration; //in minutes
  //Map_to_point has is directly used from the PBC library's
  //element_from_hash()
};

#endif
