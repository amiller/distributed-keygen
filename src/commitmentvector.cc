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



#include "commitmentvector.h"
#include "io.h"

#define HashSize 32

CommitmentVector::CommitmentVector(const SystemParam& sys, const vector <NodeID>& activeNodes){
	
	indices.push_back(0);
	indices.insert(indices.end(),activeNodes.begin(),activeNodes.end());
   
  	for(vector <NodeID>:: const_iterator it = indices.begin();it != indices.end();++it)
  		shares.push_back(G1(sys.get_Pairing(),true));
	  
}

CommitmentVector::CommitmentVector(const SystemParam& sys, const vector <NodeID>& activeNodes, const BiPolynomial& fxy){
  
 	indices.push_back(0);
	indices.insert(indices.end(),activeNodes.begin(),activeNodes.end()); 
  //Generate shares
    G1 U = sys.get_U();
    
    string strShares;
    vector <NodeID>:: const_iterator it2d; 	
 	for(it2d = indices.begin(); it2d != indices.end();++it2d){    
       	G1 entry  = U^(fxy.apply(Zr(sys.get_Pairing(),(long)*it2d))(Zr(sys.get_Pairing(),(long)0)));       	
       	shares.push_back(entry); 
  		write_G1(strShares,entry);//For hash
 	}
 	unsigned char hashbuf[HashSize]; 
 	gcry_md_hash_buffer(GCRY_MD_SHA256, hashbuf, strShares.data(), strShares.length());
	//hashbuf[HashSize]= 0;
	hashes.push_back(string((const char*)hashbuf,HashSize));
 	
 	it2d = indices.begin();++it2d;   		 
	for(;it2d != indices.end();++it2d){
		string strSubshares;  		  
  		for (vector <NodeID>:: const_iterator it1d = indices.begin();it1d != indices.end();++it1d){  			
   			G1 entry  = U^(fxy.apply(Zr(sys.get_Pairing(),(long)*it2d))(Zr(sys.get_Pairing(),(long)*it1d)));
   			write_G1(strSubshares,entry);//For hash
   		}		
   		unsigned char hashbuf[HashSize];   		
  		gcry_md_hash_buffer(GCRY_MD_SHA256, hashbuf, strSubshares.data(), strSubshares.length());
  		//hashbuf[HashSize]= 0;
		hashes.push_back(string((const char*)hashbuf,HashSize));		
	}
}

// Copy constructor
CommitmentVector::CommitmentVector(const CommitmentVector &vec):indices(vec.getIndices()){	
	vector <G1>::iterator it;
	vector <string>::iterator itstr;
	vector <G1> shV = vec.getShares();		
	vector <G1> subshV = vec.getSubshares();
	vector <string> strV = vec.getHashes();
  	for (it = shV.begin(); it != shV.end(); ++it) {G1 entry(*it); shares.push_back(entry);}	
  	for (it = subshV.begin(); it != subshV.end(); ++it){G1 entry(*it);subshares.push_back(entry);}   	  	
  	for (itstr = strV.begin(); itstr != strV.end(); ++itstr){string str(*itstr);hashes.push_back(str);}
}
	
CommitmentVector& CommitmentVector::operator=(const CommitmentVector &vec){
	if (this == &vec) return *this;	
	vector <G1>::iterator it;
	vector <string>::iterator itstr;
	
	indices.clear();shares.clear();hashes.clear();subshares.clear();
	indices = vec.getIndices();
	vector <G1> shV = vec.getShares();		
	vector <G1> subshV = vec.getSubshares();
	vector <string> strV = vec.getHashes();
  	for (it = shV.begin(); it != shV.end(); ++it) {G1 entry = G1(*it); shares.push_back(entry);}
  	for (it = subshV.begin(); it != subshV.end(); ++it){G1 entry= G1(*it);subshares.push_back(entry);}
  	for (itstr = strV.begin(); itstr != strV.end();++itstr){string str = *itstr;hashes.push_back(str);}  	
  			
	return *this;
}

//Deserialize
CommitmentVector::
CommitmentVector(const SystemParam& sys, const unsigned char *&buf, size_t& len){
	
	G1 U = sys.get_U();
	indices.clear(); shares.clear();hashes.clear();subshares.clear();	
	//indices.push_back(0); indices.insert(indices.end(),activeNodes.begin(),activeNodes.end());

	//read indices
	NodeIDSize indexcnt; read_us(buf, len, indexcnt);
	for(NodeIDSize j = 0; j<indexcnt; ++j){
		NodeID index; read_us(buf, len, index);
		indices.push_back(index);
    }
    
	//read shares
	NodeIDSize sharecnt; read_us(buf, len, sharecnt);
	for(NodeIDSize j = 0; j<sharecnt; ++j){
		G1 entry; read_G1(buf, len, entry, sys.get_Pairing());
		shares.push_back(entry);
    }

    //read hashes
   	NodeIDSize hashcnt; read_us(buf, len, hashcnt);
	for(NodeIDSize j = 0; j<hashcnt; ++j){
		string hash; read_str(buf, len, hash, HashSize);
		hashes.push_back(hash);
    }

	//read subshares
	NodeIDSize subsharecnt; read_us(buf, len, subsharecnt);
	if (!(subsharecnt)) return;
	for(NodeIDSize j = 0; j<subsharecnt; ++j){
		G1 entry;read_G1(buf, len, entry, sys.get_Pairing());
		subshares.push_back(entry);
    }
}

//Serialize a CommitmentVector
string CommitmentVector:: toString(bool includeSubshares) const{
  string returnStr;
  vector<G1>::const_iterator iterG1;
  vector<string>::const_iterator iterHash;
  vector<NodeID>::const_iterator iter;
  
  	write_us(returnStr,(unsigned short)indices.size());
	for(iter = indices.begin(); iter != indices.end(); ++iter)
		write_us(returnStr,*iter);
		
	write_us(returnStr,(unsigned short)shares.size());
	for(iterG1 = shares.begin(); iterG1 != shares.end(); ++iterG1)
		write_G1(returnStr,*iterG1);

	write_us(returnStr,(unsigned short)hashes.size());	
	for(iterHash = hashes.begin(); iterHash != hashes.end(); ++iterHash)
		write_str(returnStr,*iterHash, HashSize);

	if(includeSubshares){
	write_us(returnStr,(unsigned short)subshares.size());
	for(iterG1 = subshares.begin(); iterG1 != subshares.end(); ++iterG1)
		write_G1(returnStr,*iterG1);
	} else write_us(returnStr,(unsigned short)0);
	return returnStr;
}

bool CommitmentVector::operator==(const CommitmentVector &rhs) const{  
  /* map<NodeID, G1>::const_iterator iterG1;
	for (NodeIDSize i = 0; i < shares.size(); ++i)
		if (!(shares[i] == rhs.getShare(i))) 
			return false;
	for (NodeIDSize i = 0; i < hashes.size(); ++i)
		if (!(hashes[i] == rhs.getHash(i))) 
		return false;*/
	if (indices != rhs.indices)	return false;
	if (shares != rhs.shares) return false;
	if (hashes != rhs.hashes) return false;
	return true;
}

void CommitmentVector::setSubshares(const vector <G1>& subshares){
	this->subshares.clear();
	for (vector <G1>::const_iterator it = subshares.begin(); it != subshares.end(); ++it){
		G1 entry(*it);
		this->subshares.push_back(entry);
		//entry.dump(stderr);
	}
}

void CommitmentVector::setSubshares(const SystemParam& sys,const vector <Zr>& values){
	G1 U = sys.get_U();	 
	subshares.clear();
	 for(vector <Zr>::const_iterator it = values.begin(); it != values.end();++it){   
       	G1 entry = U^(*it);
		//entry.dump(stderr);
       	subshares.push_back(entry);
 	}
}

CommitmentVector& CommitmentVector::operator*=(const CommitmentVector &rhs){
//Here each entry is multiplied with corresponding entry in rhs.
//This is not normal Vector mutliplication
//It is assumed that rhs is of the same size as that of lhs
	for (unsigned int i = 0; i < shares.size(); ++i)
		  shares[i] *= rhs.getShare(i);
	return *this;	  	
	//hashes.clear();
	//subshares.clear();
}

bool CommitmentVector::checkPoly(NodeID verifierID) const{
	if (!(subshares[0] == shares[verifierID])){cerr<<"Error with share comparison\n"; 
		return false;}
	
	string strSubshares;
	for(vector <G1> :: const_iterator it = subshares.begin(); it != subshares.end(); ++it)
		write_G1(strSubshares,*it);//For hash		
	unsigned char hashbuf[HashSize];
	
	gcry_md_hash_buffer(GCRY_MD_SHA256, hashbuf, strSubshares.data(), strSubshares.length());
	//hashbuf[HashSize]= 0;
	if (string((const char*)hashbuf, HashSize) != hashes[verifierID])	{
		cerr<< "Created hash: "<<hashbuf<< " Received hash: "<<hashes[verifierID];
		return false;
	}	
	return true;		
}


bool CommitmentVector::verifyPoly(const SystemParam& sys, NodeID verifierID, 
								  const Polynomial& poly) {
	vector <NodeID>:: const_iterator it2d; 
	G1 U = sys.get_U();
	subshares.clear();
 	for(it2d = indices.begin(); it2d != indices.end();++it2d){    
       	G1 entry  = U^(poly(Zr(sys.get_Pairing(),(long)*it2d)));
       	subshares.push_back(entry);
 	}
 	if (checkPoly(verifierID)) return true;
 	else {subshares.clear();return false;}
}

bool CommitmentVector::verifyPoint(const SystemParam& sys, NodeID senderID,
								   NodeID verifierID, const Zr& point) const{
	G1 U = sys.get_U();
	if (!(subshares[verifierID] == (U^point))) {
		cerr<<"Error with share verification for "<<verifierID<<"\n";
		for (vector <G1>::const_iterator it = subshares.begin(); it != subshares.end(); ++it) it->dump(stderr);
		subshares[verifierID].dump(stderr);
		(U^point).dump(stderr);
		return false;
	}
	 	
	if (!checkPoly(senderID)) {cerr<<"Error with CheckPoly\n";return false;}
	return true;
}


void CommitmentVector::dump(FILE *f, unsigned int indent) const{
  
  vector<G1>::const_iterator iter1d;
  fprintf(f, "%*s[ CommitmentVector:\n", indent, "");

  for(iter1d = shares.begin(); iter1d != shares.end(); ++iter1d){	
	  iter1d->dump(f,(char*)"",10);	 
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

	Zr three(e,(long int)3);
	Zr six(e,(long int)6);
	Zr one(e,(long int)1);
	Zr zero(e,(long int)0);


	BiPolynomial fxy(param,3,six);
	Polynomial poly = fxy(three);
	Zr val = poly(one);
	NodeID i[] = {1,2,3,4};
  	vector<NodeID> vec (i, i + sizeof(i) / sizeof(NodeID) );

	//CommitmentVector id(param);
	//id.dump(stdout, 5);
	CommitmentVector cm(param,vec,fxy);
	cm.dump(stdout, 10);
	//cm *= id;
	//cm.dump(stdout, 15);
	string str= cm.toString();
	const unsigned char* ptr =  (const unsigned char*)str.data();
	size_t len = str.length();
	CommitmentVector tmp(param, ptr, len );
	//tmp.addEchoMsg(6, val);
	//tmp.addReadyMsg(6, val);
	//cout<<"cm Echo count"<<tmp.getEchoMsgCnt()<<endl;
	//cout<<"tmp Ready count"<<tmp.getReadyMsgCnt()<<endl;

	if(tmp==cm) cout<<"Same to same"<<endl;
	else cout<<"Error in Equality checking"<<endl;

	if (cm.verifyPoly(param, 3,poly))
	  cout<<"Polynomial Verified"<<endl;
	else
	  cout<<"Error in Polynomial Verification"<<endl;

	if (cm.verifyPoint(param,3,1,val))
	//	if (cm.verifyPoint(param, 5,0,val)): Doesn't work for zero
	  cout<<"Point Verified"<<endl;
	else
	  cout<<"Error in Point Verification"<<endl;
}
*/
