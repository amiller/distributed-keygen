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



#ifndef __APPLICATION_H__
#define __APPLICATION_H__

#include <netinet/in.h>
#include <sys/time.h>
#include <map>
#include <vector>
#include "systemparam.h"
#include "buddyset.h"
#include "message.h"
#include "io.h"

using namespace std;

#define ID_BULLETIN 0
#define PHASE_DURATION 3600000

class Application {
    protected:
	SystemType systemtype;
	SystemParam sysparams;
	BuddySet buddyset;
    	vector<NodeID> activeNodes;
	Phase ph;

	int userfd, listenfd;

	Message *get_next_message(BuddyID& buddyID, BuddyID selfID);
	//for network messages, buddy returns the sender of the message 

  Application(SystemType systemtype, 
				const char *pairingparamfile,
				const char *sysparamfile, in_addr_t listen_addr, 
				in_port_t listen_port, const char *certfile, 
				const char *keyfile,const char *contactlistfile, 
				Phase phase);
	unsigned long get_time_diff(int t, unsigned long incre);
    private:
	struct timeval start_time;
	int timeout_times;
	int first_timeout;
	int last_timeout;

    public:
	void measure_init();
	void measure_now();
};



/*
struct vectoridentifier{
  CommitmentType cType;
  NodeID vectorID;
  Phase phase;
};
typedef struct vectoridentifier VectorIdentifier;

struct vectorIdentifierCmp {
    bool operator()( VectorIdentifier v1, VectorIdentifier v2 ) const {
	  if (v1.cType < v2.cType) return 0;
	  if (v1.cType > v2.cType) return 1;
	  if (v1.vectorID < v2.vectorID) return 0;
	  if (v1.vectorID > v2.vectorID) return 1;
	  if (v1.phase < v2.phase) return 0;
	  if (v1.phase > v2.phase) return 1;
	  return 0;
    }
  };

class SignatureShares {
 public:
  Phase phase;
  map <NodeID, G1> signatureShares;
  G1 privkey;

  SignatureShares() {phase =0;}

  SignatureShares(Phase phase, const map <NodeID, G1>& signatureShares)
	: phase(phase), signatureShares(signatureShares){}

  // ~KeyShares(){}//clear();}

  void dump(FILE *f, unsigned int indent = 0) const {
	bool has_key;
      fprintf(f, "%*s[ SignatureShares:\n", indent, "");
      fprintf(f, "%*s  phase = %d\n", indent, "", phase);
      fprintf(f, "%*s  signatureShares =\n", indent, "");
      for (map<NodeID, G1>::const_iterator iter = signatureShares.begin();
	      iter != signatureShares.end(); ++iter) {
		fprintf(f, "%*s    %d => ", indent, "", iter->first);
		(iter->second).dump(f,NULL,10);
		fprintf(f, "\n");
      }
	  has_key = privkey.isElementPresent();
      fprintf(f, "%*s  has_key = %d\n", indent, "", has_key);
      if (has_key) {
	  fprintf(f, "%*s  ", indent, "");
	  privkey.dump(f,NULL,10);
      }
      fprintf(f, "%*s]\n", indent, "");
  }
};
*/
#endif
