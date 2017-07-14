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



#ifndef __COMMITMENT_VECTOR_H__
#define __COMMITMENT_VECTOR_H__

#include <map>
#include <vector>
#include "systemparam.h"
#include "bipolynomial.h"

class CommitmentVector{

  //NodeID dealerID;
  //Phase phase;   //TO DO:  U, t may be removed
  //unsigned short t;
  //G1 U;
  
  //unsigned short echo, ready;//Echo and ready message counter
  vector <NodeID> indices;
  vector <G1> shares;//Vector Entries [0] row
  vector <G1> subshares;//Vector Entries [i] the row
  vector <string> hashes;//hash of vectors
  
public:
  CommitmentVector(){} 
  
  CommitmentVector(const SystemParam& sys, const vector <NodeID>& activeNodes);//Initialize with identity Entries
  
  CommitmentVector(const SystemParam& sys, const vector <NodeID>& activeNodes, const BiPolynomial& fxy);
  
  // Copy constructor
  CommitmentVector(const CommitmentVector &vec);
  CommitmentVector& operator=(const CommitmentVector &vec);
    
  CommitmentVector(const SystemParam& sys, const unsigned char *&buf, size_t& len);//Deserialization

  ~CommitmentVector(){}

  string toString(bool includeSubshares = true) const;

  //unsigned short getHashesCnt() const {return (unsigned short)hashes.size();}
  //unsigned short getElementsCnt() const {return (unsigned short)shares.size();}
    
	const G1 getShare(unsigned short i) const {return shares[i];}
	const G1 getSubshare(unsigned short i) const {return subshares[i];}
	string getHash(unsigned short i) const {return hashes[i];}

	const vector <NodeID> getIndices() const {return indices;}	
	const vector <G1> getShares() const {return shares;}
	const vector <string> getHashes() const {return hashes;}
	const vector <G1> getSubshares() const {return subshares;}
	
	void setSubshares(const vector <G1>& subshares);
	void setSubshares(const SystemParam& sys,const vector <Zr>& values);
	bool operator==(const CommitmentVector &vec) const;
	
	CommitmentVector& operator*=(const CommitmentVector &rhs);
	//Here each entry is multiplied with corresponding entry in rhs.
	//This is not normal Vector mutliplication
	
	const CommitmentVector operator*(const CommitmentVector &rhs) const{
    	return CommitmentVector(*this) *= rhs;
	}
		 
	bool verifyPoly(const SystemParam& sys, NodeID verifierID, 
				  const Polynomial& poly);

	bool verifyPoint(const SystemParam& sys, NodeID senderID, 
				   NodeID verifierID,const Zr& point) const;

  	void dump(FILE *f, unsigned int indent = 0) const; 
  	
  	private:
  	bool checkPoly(NodeID verifierID) const;
};
#endif
