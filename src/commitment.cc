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



#include "commitment.h"
#include "io.h"
#include "lagrange.h"

Commitment::Commitment(const SystemParam& sys, const vector <NodeID>& activeNodes, CommitmentType type)
:hashedVector(sys,activeNodes), matrix(sys),type(type){}
	  
Commitment::Commitment(const SystemParam& sys, const vector <NodeID>& activeNodes,const BiPolynomial& fxy,CommitmentType type)
:hashedVector(sys,activeNodes, fxy),matrix(sys, fxy),type(type){}
/*	
{	if(type == Feldman_Matrix) 
		matrix= CommitmentMatrix(sys, fxy);
	else 
		hashedVector = CommitmentVector(sys,activeNodes, fxy);
}		*/


// Copy constructor
Commitment::Commitment(const Commitment &rhs)
:hashedVector(rhs.hashedVector),matrix(rhs.matrix),type(rhs.get_Type()){}
	//I might copy mechanism for echo and ready here


Commitment& Commitment:: operator=(const Commitment &rhs){
	if (this == &rhs) return *this;
	
	type = rhs.get_Type();
	hashedVector = rhs.get_Vector();
	matrix = rhs.get_Matrix();
	return *this;
}
	    
Commitment::Commitment(const SystemParam& sys, const unsigned char *&buf, size_t& len){
	unsigned char commType; read_byte(buf,len,commType); type = (CommitmentType)commType;
	if (type == Feldman_Matrix) {
		matrix = CommitmentMatrix(sys, buf,len);
    }
	else {
		hashedVector = CommitmentVector(sys,buf,len);
    }
}
	
string Commitment::toString(bool includeSubshares) const{
	string str;
	write_byte(str,type);
	if (type == Feldman_Matrix) 
		str.append(matrix.toString());
	else 
		str.append(hashedVector.toString(includeSubshares));
	return str;
}
	
bool Commitment::operator==(const Commitment &rhs) const{
	if (type != rhs.get_Type()) return false;
	if (type == Feldman_Matrix) 
		return (matrix == rhs.get_Matrix());
	else 
		return (hashedVector == rhs.get_Vector());
}
		
Commitment& Commitment::operator*=(const Commitment &rhs){
	if (type == Feldman_Matrix) 
		matrix*=rhs.get_Matrix();
	else 
		hashedVector*=rhs.get_Vector();
	return *this;
}
		 
bool Commitment::verifyPoly(const SystemParam& sys, NodeID verifierID, const Polynomial& poly){
	if (type == Feldman_Matrix) 
		return matrix.verifyPoly(sys,verifierID,poly);
	else 
		return hashedVector.verifyPoly(sys,verifierID,poly);
}

const G1 Commitment::publicKeyShare(const SystemParam& sys, NodeID nodeID) const{
	if (type == Feldman_Matrix)
		return matrix.publicKeyShare(sys,nodeID);
	else
		return hashedVector.getShare(nodeID);
}

bool Commitment::verifyPoint(const SystemParam& sys, NodeID senderID,NodeID verifierID, const Zr& point) const{
	if (type == Feldman_Matrix)
		return matrix.verifyPoint(sys,senderID,verifierID,point);
	else
		return hashedVector.verifyPoint(sys,senderID,verifierID,point);
}					   

const vector<Zr> Commitment::
interpolate(const SystemParam& sys, bool EchoOrReady, const vector<NodeID>& activeList) const{
	vector <Zr> indices, evals;
	Zr alpha;
	vector<Zr> subshares;
	
	const map <NodeID, Zr> &A_C = (EchoOrReady? A_Ready : A_Echo);
	
	//Make an array of the indices
	map<NodeID, Zr>::const_iterator Zr_it;
	for(Zr_it = A_C.begin(); Zr_it != A_C.end(); ++Zr_it){
	//Note that any t+1 are sufficient
		indices.push_back(Zr(sys.get_Pairing(),(signed long)Zr_it->first));
		evals.push_back(Zr_it->second);
	}
	//pushing evaluation at zero
	alpha = Zr(sys.get_Pairing(),(long)0);
	vector<Zr> coeffs = lagrange_coeffs(indices, alpha);
	subshares.push_back(lagrange_apply(coeffs, evals));
	
	vector<NodeID>::const_iterator ID_it;	
	for(ID_it = activeList.begin();ID_it != activeList.end(); ++ID_it){
		if(A_C.find(*ID_it) == A_C.end()){//Haven't received share from *(ID_it)
			alpha = Zr(sys.get_Pairing(),(long)*ID_it);
			vector<Zr> coeffs = lagrange_coeffs(indices, alpha);
			subshares.push_back(lagrange_apply(coeffs, evals));
		} 
		else subshares.push_back(A_C.find(*(ID_it))->second);		
	}	
	return 	subshares;
}	
void Commitment::dump(FILE *f, unsigned int indent) const{
	if (type == Feldman_Matrix){ 
		fprintf(f, "%*s  Feldman Matrix\n", indent,"");
		matrix.dump(f,indent);
	}
	else{ 
		fprintf(f, "%*s  Feldman Vector\n", indent, "");
		hashedVector.dump(f,indent);
	}
  fprintf(f, "%*s  echo message count = %lu\n", indent, "", A_Echo.size());
  fprintf(f, "%*s  ready message count = %lu\n", indent, "", A_Ready.size());
}
