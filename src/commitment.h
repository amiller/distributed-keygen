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



#ifndef __COMMITMENT_H__
#define __COMMITMENT_H__

#include <map>
#include <vector>
#include "commitmentvector.h"
#include "commitmentmatrix.h"


typedef enum {Feldman_Matrix, Feldman_Vector} CommitmentType;

class Commitment{

private:
	CommitmentVector hashedVector;
	CommitmentMatrix matrix;
	CommitmentType type;
		
	map <NodeID, Zr> A_Echo;//Shares received from various members during Echo messages
	map <NodeID, Zr> A_Ready;//Shares received from various members during Ready messages
		
public:
	Commitment(){}
	  
	Commitment(const SystemParam& sys, const vector <NodeID> & activeNodes, CommitmentType type);
	//Initialize with identity Entries
	  
	Commitment(const SystemParam& sys, const vector <NodeID>& activeNodes, 
				const BiPolynomial& fxy, CommitmentType type);
	  
	// Copy constructor
	Commitment(const Commitment &vec);
	Commitment& operator=(const Commitment &vec);
	    
	Commitment(const SystemParam& sys, const unsigned char *&buf, size_t& len);//Deserialization
	
   ~Commitment(){}
	
	string toString(bool includeSubshares = true) const;
	
	//With Echo and Ready messages, we add points 
	bool addEchoMsg(NodeID sender, const Zr& alpha){
		map <NodeID, Zr>::iterator it;
		for (it = A_Echo.begin(); it != A_Echo.end(); ++it) {
			if (it->first == sender)
				return false;
		}
		A_Echo.insert(make_pair(sender, alpha));
		return true;}
	bool addReadyMsg(NodeID sender, const Zr& alpha){
		map <NodeID, Zr>::iterator it;
		for (it = A_Ready.begin(); it != A_Ready.end(); ++it) {
			if (it->first == sender)
				return false;
		}
		A_Ready.insert(make_pair(sender, alpha));
		return true;}
		  
	unsigned short getEchoMsgCnt() const {return (unsigned short)A_Echo.size();}
	unsigned short getReadyMsgCnt() const {return (unsigned short)A_Ready.size();}
	  
	bool operator==(const Commitment &rhs) const;
	
	CommitmentType get_Type() const {return type;}
	const CommitmentMatrix get_Matrix() const {return matrix;}
	const CommitmentVector get_Vector() const {return hashedVector;}
	
	void setSubshares(const SystemParam& sys, const vector <Zr>& values) {hashedVector.setSubshares(sys, values);}
		
	Commitment& operator*=(const Commitment &rhs);
	//Here each entry is multiplied with corresponding entry in rhs.
	//This is not normal matrix mutliplication
	const Commitment operator*(const Commitment &rhs) const{
	   	return Commitment(*this) *= rhs;
	}
		 
	bool verifyPoly(const SystemParam& sys, NodeID verifierID, const Polynomial& poly);
	
	bool verifyPoint(const SystemParam& sys, NodeID senderID,NodeID verifierID, const Zr& point) const;

	const G1 publicKeyShare(const SystemParam& sys, NodeID nodeID) const;// If nodes share is s, then this g^s
					   
	const vector<Zr> interpolate(const SystemParam& sys, bool EchoOrReady, const vector<NodeID>& activeList) const;
		
	void dump(FILE *f, unsigned int indent = 0) const; 
  
};
#endif
