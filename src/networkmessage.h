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



#ifndef __NETWORK_MESSAGE_H__
#define __NETWORK_MESSAGE_H__

#include <netinet/in.h>
#include "message.h"
#include "buddyset.h"
#include "commitment.h"
#include <set>

typedef enum {
  NET_MSG_NONE, NET_MSG_PING, NET_MSG_PONG,
  VSS_SEND, VSS_ECHO, VSS_READY, VSS_SHARED, VSS_HELP,
  DKG_SEND, DKG_ECHO, DKG_READY, DKG_HELP, LEADER_CHANGE, 
  RECONSTRUCT_SHARE, PUBLIC_KEY_EXCHANGE, BLS_SIGNATURE_REQUEST, 
  BLS_SIGNATURE_RESPONSE, WRONG_BLS_SIGNATURES, VERIFIED_BLS_SIGNATURES
    } NetworkMessageType;


//class for network messages in the system
class NetworkMessage: public Message {
    public:
	NetworkMessage() {message_class = NETWORK; }
	
	NetworkMessage(const NetworkMessage& msg): netMsgStr(msg.get_netMsgStr()){message_class = NETWORK;}
	
	static NetworkMessage* read_message(SystemType systemtype, const Buddy *buddy);

	//const string& getNetMsgStr() const {return netMsgStr;}
	NetworkMessageType get_message_type() const {
	    return NetworkMessageType(netMsgStr.size() > 0 ? netMsgStr[0] : 0);
	}
    //const Buddy *get_buddy() const{ return buddy; }
    const string& get_netMsgStr() const {return netMsgStr;}

	// Assignment operators: be sure to test for self-assignment 
	NetworkMessage& operator=(const NetworkMessage &rhs);
	static const unsigned short headerLength = 5;
	static const unsigned short msgIDLength = 4;
	
    private:
	string netMsgStr;
	
    protected:
	static int g_recv_ID;
	NetworkMessage(/*const Buddy *buddy,*/  string str):
	     //buddy(buddy), 
	     netMsgStr(str){ message_class = NETWORK; }

	void set_netMsgStr(const string &body) {
	    size_t len = body.size();
	    netMsgStr.clear();
	    netMsgStr.reserve(len);
	    netMsgStr.append(body, 0, len);
	}

	//const Buddy *buddy;
};

class PingNetworkMessage : public NetworkMessage
{
public:
  PingNetworkMessage(const BuddySet &buddyset, unsigned int t);
  PingNetworkMessage(const Buddy *buddy, const string &str, int g_recv_ID);
  string toString() const;
  unsigned int t;
  string DSA;
  string strMsg;
  bool msgValid;
};

class VSSSendMessage : public NetworkMessage
{
public:
  VSSSendMessage(Phase ph, const Commitment& commitment, const Polynomial& a);
  VSSSendMessage(const Buddy *buddy, const string &str, int g_recv_ID);

  Phase ph;
  Commitment C;
  Polynomial a;
};

class VSSEchoMessage : public NetworkMessage
{
public:
  VSSEchoMessage(NodeID dealer, Phase ph, const Commitment& commitment, const Zr& alpha);
  VSSEchoMessage(const Buddy *buddy, const string &str, int g_recv_ID);

  NodeID dealer;
  Phase ph;
  Commitment C;
  Zr alpha;
};

class VSSReadyMessage : public NetworkMessage
{
public:
  VSSReadyMessage(){}
  VSSReadyMessage(const BuddySet& buddyset, NodeID dealer, Phase ph,
				  const Commitment& commitment, const Zr& alpha, 
				  bool includeSignature = true);
  VSSReadyMessage(const Buddy *buddy, const string &str, int g_recv_ID = 0);

  string toString() const;

  NodeID dealer;
  Phase ph;
  Commitment C;
  Zr alpha;
  string DSA;
  bool msgValid;
  string strMsg;
};

struct VSSReadyMessageCmp {
    bool operator()(VSSReadyMessage m1, VSSReadyMessage m2 ) const {
		if (m1.ph < m2.ph) return 0;    	
		if (m1.ph > m2.ph) return 1;
		if (m1.dealer < m2.dealer) return 0;    	
		if (m1.dealer > m2.dealer) return 1;
		if (m1.C.toString(false) < m2.C.toString(false)) return 0;    	
		if (m1.C.toString(false) > m2.C.toString(false)) return 1;
	  	return 0;
    }
};

class VSSSharedMessage : public NetworkMessage 
{
public:
VSSSharedMessage(Phase ph, NodeID dealer,
				 const VSSReadyMessage &readyMsg, const map <NodeID, string> &msgDSAs);
VSSSharedMessage(const Buddy *buddy, const string &str, int g_recv_ID);

//VSSSharedMessage(const VSSSharedMessage& msg);

  	Phase ph;
    NodeID dealer;  	
  	VSSReadyMessage readyMsg; //Ready Message string 
  	map <NodeID, string> msgDSAs;//map <NodeID, string> represents signer and signature
  	bool msgValid;
};

class VSSHelpMessage : public NetworkMessage
{
public:
  VSSHelpMessage(const BuddySet &buddyset, Phase ph);
  VSSHelpMessage(const Buddy *buddy, const string &str, int g_recv_ID);

  Phase ph; 
};

class ReconstructShareMessage : public NetworkMessage
{
public:
  ReconstructShareMessage(const BuddySet &buddyset, Phase ph);
  ReconstructShareMessage(const Buddy *buddy, const string &str);

  Phase ph;
  Commitment C;
  Zr share;
};



class DKGEchoOrReadyMessage : public NetworkMessage
{
public:
  DKGEchoOrReadyMessage(){}
  DKGEchoOrReadyMessage(const BuddySet &buddyset, NetworkMessageType type, NodeID leader, Phase ph,
				 const set <NodeID> & DecidedVSSs, bool includeSignature = true);
  DKGEchoOrReadyMessage(const Buddy *buddy, NetworkMessageType type, const string &str, int g_recv_ID = 0);
  string toString(NetworkMessageType type) const;
  
  //NetworkMessageType type;
  NodeID leader;
  Phase ph;
  //map <NodeID, LeaderChangeMessage> leadChgMsg;
  //map <NodeID, map <NodeID, VSSReadyMessage> > readyMsg;
  set <NodeID> DecidedVSSs;
  string strMsg;
  string DSA;   
  bool msgValid;
};



struct DKGEchoOrReadyMessageCmp {
    bool operator()(DKGEchoOrReadyMessage m1, DKGEchoOrReadyMessage m2 ) const {
 		if (m1.strMsg[0] < m2.strMsg[0]) return 0;    	
		if (m1.strMsg[0] > m2.strMsg[0]) return 1;   	
		if (m1.ph < m2.ph) return 0;    	
		if (m1.ph > m2.ph) return 1;
		if (m1.leader < m2.leader) return 0;    	
		if (m1.leader > m2.leader) return 1;	
		if (m1.DecidedVSSs < m2.DecidedVSSs) return 0;    	
		if (m1.DecidedVSSs > m2.DecidedVSSs) return 1;
		return 0;
    }
};

class LeaderChangeMessage : public NetworkMessage
{
public:
  LeaderChangeMessage(){}
  LeaderChangeMessage(const BuddySet &buddyset, Phase ph, NodeID nextLeader,
				 	const map <VSSReadyMessage, map <NodeID, string>, VSSReadyMessageCmp> & vssReadyMsg, bool includeSignature = true);
  LeaderChangeMessage(const BuddySet &buddyset, Phase ph, NodeID nextLeader, 
  					NetworkMessageType msgType, const DKGEchoOrReadyMessage &dkgEchoOrReadyMsg, 
  					const map <NodeID, string>& dkgEchoOrReadyMsgDSAs, bool includeSignature = true);
  LeaderChangeMessage(const BuddySet &buddyset, /*Phase ph,*/ NodeID nextLeader, bool includeSignature = true);
  					 					
  LeaderChangeMessage(const Buddy *buddy, const string &str, int g_recv_ID = 0);
  string toString() const;
  
  
  Phase ph;
  NodeID nextLeader;
  NetworkMessageType msgType; 
  map <VSSReadyMessage, map <NodeID, string>, VSSReadyMessageCmp> vssReadyMsg;//VSSReadyMessage for t+1 VSS:
  														//map <NodeID, string> represents signer and signature
  DKGEchoOrReadyMessage dkgEchoOrReadyMsg; //DKGEchoOrReadyMessage for t+1 VSS
  map <NodeID, string> dkgEchoOrReadyMsgDSAs;//map <NodeID, string> represents signer and signature
  string DSA;
  bool msgValid;
  string strMsg;
};


struct LeaderChangeMessageCmp {
    bool operator()(LeaderChangeMessage  lc1, LeaderChangeMessage lc2 ) const {
		if (lc1.ph < lc2.ph) return 0;    	
		if (lc1.ph > lc2.ph) return 1;
		if (lc1.nextLeader < lc2.nextLeader) return 0;    	
		if (lc1.nextLeader > lc2.nextLeader) return 1;
	  	return 0;
    }
};

class DKGSendMessage : public NetworkMessage
{
public:
  //DKGSendMessage(Phase ph, const map <VSSReadyMessage, map <NodeID, string>, VSSReadyMessageCmp>& vssReadyMsg);	
  DKGSendMessage(Phase ph, const LeaderChangeMessage& leadChgMsg, const map<NodeID, string>& leadChgMsgDSAs,
				 const map <VSSReadyMessage, map <NodeID, string>, VSSReadyMessageCmp>& vssReadyMsg);				 
  DKGSendMessage(Phase ph, const LeaderChangeMessage& leadChgMsg, const map<NodeID, string> &leadChgMsgDSAs,
				 NetworkMessageType msgType, const DKGEchoOrReadyMessage &dkgEchoOrReadyMsg,
				 const map <NodeID, string> &dkgEchoOrReadyMsgDSAs);
  DKGSendMessage(const Buddy *buddy, const string &str, int g_recv_ID);

  Phase ph;
  LeaderChangeMessage leadChgMsg;
  map <NodeID, string> leadChgMsgDSAs;//map <NodeID, string> represents signer and signature
  
  NetworkMessageType msgType; 
  map <VSSReadyMessage, map <NodeID, string>, VSSReadyMessageCmp> vssReadyMsg;	//VSSReadyMessage for t+1 VSS:
  														   	//map <NodeID, string> represents signer and signature
  DKGEchoOrReadyMessage dkgEchoOrReadyMsg; 					//DKGEchoOrReadyMessage for t+1 VSS
  map <NodeID, string> dkgEchoOrReadyMsgDSAs;				//map <NodeID, string> represents signer and signature
  bool msgValid;
};

class DKGEchoMessage : public DKGEchoOrReadyMessage
{
public:
  DKGEchoMessage(const BuddySet &buddyset, NodeID leader, Phase ph,
				 const set <NodeID> &DecidedVSSs, bool includeSignature = true)
		:DKGEchoOrReadyMessage(buddyset,DKG_ECHO,leader,ph,DecidedVSSs,includeSignature){}
					 
  DKGEchoMessage(const Buddy *buddy, const string &str, int g_recv_ID = 0)
  		:DKGEchoOrReadyMessage(buddy,DKG_ECHO,str, g_recv_ID){}
};

class DKGReadyMessage : public DKGEchoOrReadyMessage
{
public:
  DKGReadyMessage(const BuddySet &buddyset, NodeID leader, Phase ph,
				 const set <NodeID>& DecidedVSSs, bool includeSignature = true)
		:DKGEchoOrReadyMessage(buddyset,DKG_READY,leader,ph,DecidedVSSs,includeSignature){}
					 
  DKGReadyMessage(const Buddy *buddy, const string &str, int g_recv_ID = 0)
  		:DKGEchoOrReadyMessage(buddy,DKG_READY,str, g_recv_ID){}
};

class DKGHelpMessage : public NetworkMessage
{
public:
  DKGHelpMessage(const BuddySet &buddyset,NodeID leader, Phase ph);
  DKGHelpMessage(const Buddy *buddy, const string &str, int g_recv_ID);
  
  NodeID leader;
  Phase ph;
};

class PublicKeyExchangeMessage: public NetworkMessage
//This is for BLS signature verification in DHT case
//As nodes know the public keys before at the signatures are generated
//Note that the public keys do not change here with the phase 
{
public:
  PublicKeyExchangeMessage(const BuddySet &buddyset, const G1& publicKey);
  PublicKeyExchangeMessage(const Buddy *buddy, const string &str, int g_recv_ID);
  
  G1 publicKey;
};


class BLSSignatureRequestMessage : public NetworkMessage
{
public:
  BLSSignatureRequestMessage(const BuddySet &buddyset, Phase ph, const string& msg, const G1& signature);
  BLSSignatureRequestMessage(const Buddy *buddy, const string &str, int g_recv_ID);
  
   Phase ph;    
   string msg;
   G1 signature;// Verification of the message/request
};

class BLSSignatureResponseMessage : public NetworkMessage
{
public:
  BLSSignatureResponseMessage(const BuddySet &buddyset, Phase ph, const G1& msgHash, const G1& signatureShare);
  BLSSignatureResponseMessage(const Buddy *buddy, const string &str, int g_recv_ID);
  
  Phase ph;   
  G1 msgHash;//as a request identifier
  G1 signatureShare;
};

class WrongBLSSignaturesMessage : public NetworkMessage
{
public:
  WrongBLSSignaturesMessage(const BuddySet &buddyset, Phase ph, const G1& msgHash, const map <NodeID, G1>& signatures);
  WrongBLSSignaturesMessage(const Buddy *buddy, const string &str, int g_recv_ID);
  
  Phase ph;
  G1 msgHash;
  map <NodeID, G1> signatures; 
  bool msgValid;
};

class VerifiedBLSSignaturesMessage : public NetworkMessage
{
public:
  VerifiedBLSSignaturesMessage(const BuddySet &buddyset, Phase ph, const G1& msgHash, const map <NodeID, G1>& signatures);
  VerifiedBLSSignaturesMessage(const Buddy *buddy, const string &str, int g_recv_ID);
  
  Phase ph;     
  G1 msgHash;
  map <NodeID, G1> signatures;
  bool msgValid;
};

#endif
