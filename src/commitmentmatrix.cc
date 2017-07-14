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



#include "commitmentmatrix.h"
#include "io.h"

CommitmentMatrix::CommitmentMatrix(const SystemParam& sys){
  unsigned short t = sys.get_t();  
  for (unsigned int i=0; i<=t; ++i){
  	vector<G1> row(t+1,G1(sys.get_Pairing(),true));
	entries.push_back(row);
  }
}

CommitmentMatrix::CommitmentMatrix(const SystemParam& sys, 
								  const BiPolynomial& fxy){
  unsigned short t = fxy.degree();
  G1 U = sys.get_U();

  for (unsigned int i=0; i<=t; ++i){
	vector<G1> row;
	for (unsigned int j=0; j<=t; ++j){
	  G1 entry  = U^fxy.getCoeff(i,j);
	  row.push_back(entry);
    }
	entries.push_back(row);
  }
}

// Copy constructor
CommitmentMatrix::CommitmentMatrix(const CommitmentMatrix &mat){
  for (unsigned int i=0; i< mat.getRowCnt(); ++i){
	vector<G1> row;
	for (unsigned int j=0; j< mat.getRowWidth(i); ++j){
	  G1 entry(mat.getEntry(i,j));
	  row.push_back(entry);
    }
	entries.push_back(row);
  }
   //SendReceived = mat.isSendReceived();
}

CommitmentMatrix& CommitmentMatrix::operator=(const CommitmentMatrix &rhs){	
  if (this == &rhs) return *this;
  entries.clear();
  for (unsigned int i=0; i< rhs.getRowCnt(); ++i){
	vector<G1> row;
	for (unsigned int j=0; j< rhs.getRowWidth(i); ++j){
	  G1 entry(rhs.getEntry(i,j),true);
	  entry = rhs.getEntry(i,j);
	  row.push_back(entry);	  
    }
	entries.push_back(row);
  } return *this;
}

//Deserialize
CommitmentMatrix::
CommitmentMatrix(const SystemParam& sys, const unsigned char *&buf, 
				 size_t& len){
  G1 U = sys.get_U();
  unsigned short rowcnt; read_us(buf, len, rowcnt);
  for(unsigned short i = 0; i<rowcnt; ++i){
	vector<G1> row;
	unsigned short colcnt; read_us(buf, len, colcnt);
	for(unsigned short j = 0; j<colcnt; ++j){
	  G1 entry;
	  read_G1(buf, len, entry, sys.get_Pairing());
	  row.push_back(entry);
    }
	entries.push_back(row);	     
  }
}

//Serialize a CommitmentMatrix
string CommitmentMatrix:: toString() const {
  string returnStr;
  vector< vector<G1> >::const_iterator iter2d;
  vector<G1>::const_iterator iter1d;

  write_us(returnStr,(unsigned short)entries.size());
  //For each CommitmentEntry do following
  for(iter2d = entries.begin(); iter2d != entries.end(); ++iter2d){
	  write_us(returnStr,(unsigned short)iter2d->size());
	  for(iter1d = iter2d->begin(); iter1d != iter2d->end(); ++iter1d)
		write_G1(returnStr,*iter1d);
  }
  return returnStr;
}

const G1 CommitmentMatrix::getEntry(unsigned short i, unsigned short j) const{
  if (i < entries.size())
	if (j < entries[i].size())	  
	  return entries[i][j];
  G1 tmp;
  return tmp;	//Returning an unintialized element  
}

bool CommitmentMatrix::operator==(const CommitmentMatrix &rhs) const{
  for (unsigned int i = 0; i < entries.size(); ++i)
	for (unsigned int j = 0; j < entries[i].size(); ++j){
	  if (!(entries[i][j] == rhs.getEntry(i,j))) return false;
	}
  return true;
}

CommitmentMatrix& CommitmentMatrix::operator*=(const CommitmentMatrix &rhs){
//Here each entry is multiplied with corresponding entry in rhs.
//This is not normal matrix mutliplication
//It is assumed that rhs is of the same size as that of lhs
	for (unsigned int i = 0; i < entries.size(); ++i)
		for (unsigned int j = 0; j < entries[i].size(); ++j)	
		  entries[i][j] = entries[i][j]* rhs.getEntry(i,j);
	return *this;	  	
}

bool CommitmentMatrix::verifyPoly(const SystemParam& sys, NodeID verifierID, 
								  const Polynomial& poly) const {
  Zr i(poly.getCoeff(0),(long int)verifierID);
  G1 U = sys.get_U();
  for(int l = 0; l <= poly.degree(); ++l){
	G1 lhs(U,true);
	G1 rhs(U,true);
	lhs = U^poly.getCoeff(l);
	//using Horner's rule
	size_t jj = entries.size();
    while(jj > 0){
	  --jj;
	  rhs^=i;
	  rhs*=entries[jj][l];	  
	}
	if (!(lhs == rhs)) return false;
  }
  return true;
}

bool CommitmentMatrix::verifyPoint(const SystemParam& sys, NodeID senderID,
								   NodeID verifierID, const Zr& point) const{
  Zr m(point,(long int)senderID);
  Zr i(point,(long int)verifierID);
  G1 U = sys.get_U();
  G1 lhs(U,true);
  G1 rhs(U,true);
  lhs = U^point;
  //using Horner's rule
  size_t jj = entries.size();
  while(jj > 0){
	--jj;
	rhs^=m;
	size_t ll = entries.size();
	G1 row(U,true);
	while(ll > 0){
	  --ll;
	  row^=i;
	  row*=entries[jj][ll];
	  //row.dump(stderr,"row is");
	}
	rhs*=row;
  }
//lhs.dump(stderr,"LHS is");
//rhs.dump(stderr,"RHS is");  
  return lhs == rhs; 
}

const G1 CommitmentMatrix::publicKeyShare(const SystemParam& sys, NodeID nodeID) const{
  Zr m(sys.get_Pairing(),(long int)nodeID);
  Zr i(sys.get_Pairing(),(long int)0);
  G1 U = sys.get_U();
  G1 publicKeyShare(U,true);  
  //using Horner's rule
  size_t jj = entries.size();
  while(jj > 0){
	--jj;
	publicKeyShare^=m;
	size_t ll = entries.size();
	G1 row(U,true);
	while(ll > 0){
	  --ll;
	  row^=i;
	  row*=entries[jj][ll];
	  //row.dump(stderr,"row is");
	}
	publicKeyShare*=row;
  }
  return publicKeyShare;			  
}


void CommitmentMatrix::dump(FILE *f, unsigned int indent) const{
  vector< vector<G1> >::const_iterator iter2d;
  vector<G1>::const_iterator iter1d;
  fprintf(f, "%*s[ CommitmentMatrix:\n", indent, "");

  for(iter2d = entries.begin(); iter2d != entries.end(); ++iter2d){
	for(iter1d = iter2d->begin(); iter1d != iter2d->end(); ++iter1d)
	  iter1d->dump(f,(char*)"",10);
	 fprintf(f, "\n");
  }
  fprintf(f, "%*s]\n", indent, "");
}

/*
int main(int argc, char **argv)
{
	string sysParamFileStr = "system.param";
	string pairingParamFileStr = "pairing.param";
    const SystemParam param((char*)pairingParamFileStr.data(), 
					  (char*)sysParamFileStr.data());
	const Pairing &e = param.get_Pairing();

	Zr five(e,(long int)5);
	Zr six(e,(long int)6);
	Zr one(e,(long int)1);
	Zr zero(e,(long int)0);


	BiPolynomial fxy(param,3,six);
	Polynomial poly = fxy(five);
	Zr val = poly(one);

	//CommitmentMatrix id(param);
	//id.dump(stdout, 5);
	CommitmentMatrix cm(param,fxy);
	cm.dump(stdout, 10);
	//cm *= id;
	//cm.dump(stdout, 15);
	string str= cm.toString();
	const unsigned char* ptr =  (const unsigned char*)str.data();
	CommitmentMatrix tmp(param, ptr, str.length());
	tmp.addEchoMsg(6, val);
	tmp.addReadyMsg(6, val);
	cout<<"cm Echo count"<<tmp.getEchoMsgCnt()<<endl;
	cout<<"tmp Ready count"<<tmp.getReadyMsgCnt()<<endl;

	if(tmp==cm) cout<<"Same to same"<<endl;
	else cout<<"Error in Equality checking"<<endl;

	if (cm.verifyPoly(param, 5,poly))
	  cout<<"Polynomial Verified"<<endl;
	else
	  cout<<"Error in Polynomial Verification"<<endl;

	if (cm.verifyPoint(param,5,1,val))
	//	if (cm.verifyPoint(param, 5,0,val)): Doesn't work for zero
	  cout<<"Point Verified"<<endl;
	else
	  cout<<"Error in Point Verification"<<endl;
}*/
