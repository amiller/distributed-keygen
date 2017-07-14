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



#ifndef __COMMITMENT_MATRIX_H__
#define __COMMITMENT_MATRIX_H__

#include <map>
#include <vector>
#include "systemparam.h"
#include "bipolynomial.h"

class CommitmentMatrix{

  //NodeID dealerID;
  //Phase phase;   //TO DO:  U, t may be removed
  //unsigned short t;
  //G1 U;
  
  //unsigned short echo, ready;//Echo and ready message counter
  vector < vector<G1> > entries;//Matrix Entries
  //map <NodeID, Zr> A_Echo;//Shares received from various members during Echo messages 
  //map <NodeID, Zr> A_Ready;//Shares received from various members during Ready messages


public:
  CommitmentMatrix(){}//:SendReceived(false) {}
  
  CommitmentMatrix(const SystemParam& sys);//Initialize with identity Entries
  
  CommitmentMatrix(const SystemParam& sys, const BiPolynomial& fxy);
  
  	// Copy constructor
	CommitmentMatrix(const CommitmentMatrix &mat);
	CommitmentMatrix& operator=(const CommitmentMatrix &rhs);
    
  CommitmentMatrix(const SystemParam& sys, const unsigned char *&buf, size_t& len);//Deserialization

  ~CommitmentMatrix(){}

  string toString() const;

  //With Echo and Ready messages, we add points 
  //void addEchoMsg(NodeID sender, const Zr& alpha){A_Echo.insert(make_pair(sender, alpha));}
  //void addReadyMsg(NodeID sender, const Zr& alpha){A_Ready.insert(make_pair(sender, alpha));}
 
  
  //unsigned short getEchoMsgCnt() const {return (unsigned short)A_Echo.size();}
  //unsigned short getReadyMsgCnt() const {return (unsigned short)A_Ready.size();}
    
  unsigned short getRowCnt() const {return (unsigned short)entries.size();}
  unsigned short getRowWidth(unsigned short rowIndex) const {return (unsigned short)entries[rowIndex].size();}
   
	const G1 getEntry(unsigned short i, unsigned short j) const;

	bool operator==(const CommitmentMatrix &rhs) const;
	
	CommitmentMatrix& operator*=(const CommitmentMatrix &rhs);
	//Here each entry is multiplied with corresponding entry in rhs.
	//This is not normal matrix mutliplication
	const CommitmentMatrix operator*(const CommitmentMatrix &rhs) const{
    	return CommitmentMatrix(*this) *= rhs;
	}
		 
	bool verifyPoly(const SystemParam& sys, NodeID verifierID, const Polynomial& poly) const;

	bool verifyPoint(const SystemParam& sys, NodeID senderID, 
				   NodeID verifierID, const Zr& point) const;
				   
	const G1 publicKeyShare(const SystemParam& sys, 
					NodeID nodeID) const;// If nodes share is s, then this g^s
				   
	const vector<Zr> interpolate(const SystemParam& sys, bool EchoOrReady, 
								  const vector<NodeID> activeList) const;
	
  void dump(FILE *f, unsigned int indent = 0) const; 

};

//Usage: multimap<NodeID dealerID, CommitmentMatrix matrix> commitment;
#endif
