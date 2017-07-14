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



#include "networkmessage.h"
#include "io.h"

NetworkMessage& NetworkMessage::operator=(const NetworkMessage &rhs){
	if (this == &rhs) return *this; 
	message_class = NETWORK;
	netMsgStr = rhs.get_netMsgStr(); 
	return *this;
}

// Read the message from the socket associated with the given Buddy
NetworkMessage *NetworkMessage::read_message(SystemType systemtype, const Buddy *buddy)
{
  int msg_type;//Message type of one byte
  string msgStr;

  int res = buddy->read_messagestr(msgStr);
  if (res < 0) {
	 // cerr << "Something wrong here" << endl;
	  return NULL;
  }
  //msg_type = (int)msgStr[0];
  msg_type = (int)msgStr[4];

  int g_recv_ID = (msgStr[0] << 24) | (((msgStr[1]) << 16) & 0x00ffffff) |
		  (((msgStr[2]) << 8) & 0x0000ffff) | (msgStr[3] & 0x000000ff);
  msgStr = msgStr.substr(4);

  switch(systemtype){
  case NODE:
	switch(msg_type){
  	case NET_MSG_PING:
		return new PingNetworkMessage(buddy, msgStr, g_recv_ID);
  	case VSS_SEND: 
		return new VSSSendMessage(buddy, msgStr, g_recv_ID);
  	case VSS_ECHO: 
		return new VSSEchoMessage(buddy, msgStr, g_recv_ID);
  	case VSS_READY: 
		return new VSSReadyMessage(buddy, msgStr, g_recv_ID);
  	case VSS_SHARED: 
		return new VSSSharedMessage(buddy, msgStr, g_recv_ID);	
  	case VSS_HELP:
		return new VSSHelpMessage(buddy, msgStr, g_recv_ID);
  	case DKG_SEND: 
		return new DKGSendMessage(buddy, msgStr, g_recv_ID);
  	case DKG_ECHO: 
		return new DKGEchoMessage(buddy, msgStr, g_recv_ID);
  	case DKG_READY: 
		return new DKGReadyMessage(buddy, msgStr, g_recv_ID);
  	case DKG_HELP: 
		return new DKGHelpMessage(buddy, msgStr, g_recv_ID);
  	case LEADER_CHANGE:
		return new LeaderChangeMessage(buddy, msgStr, g_recv_ID);
	case PUBLIC_KEY_EXCHANGE:
	 	return new PublicKeyExchangeMessage(buddy, msgStr, g_recv_ID);
	case BLS_SIGNATURE_REQUEST: 	
		return new BLSSignatureRequestMessage(buddy, msgStr, g_recv_ID);
	case WRONG_BLS_SIGNATURES:
		return new WrongBLSSignaturesMessage(buddy, msgStr, g_recv_ID);		
  }    break;
  case BLS_CLIENT:
  	switch(msg_type){
 	case PUBLIC_KEY_EXCHANGE:
	 	return new PublicKeyExchangeMessage(buddy, msgStr, g_recv_ID);
	 case BLS_SIGNATURE_RESPONSE:
  		return new BLSSignatureResponseMessage(buddy, msgStr, g_recv_ID);
  	case VERIFIED_BLS_SIGNATURES:
  		return new VerifiedBLSSignaturesMessage(buddy, msgStr, g_recv_ID);
  	}    break;
  }
  return NULL;
}

PingNetworkMessage::PingNetworkMessage(const BuddySet &buddyset, unsigned int t): t(t) {
    string msgbody;
    //size_t signstart = msgbody.size();    
    write_ui(msgbody, t); 
    //size_t signend = msgbody.size();
    write_sig(buddyset, msgbody, toString());
    addMsgHeader(NET_MSG_PING, msgbody);
    addMsgID(msg_ID, msgbody);
    set_netMsgStr(msgbody);
}

PingNetworkMessage::PingNetworkMessage(const Buddy *buddy, const string &str, int g_recv_ID):
		NetworkMessage(str) {
    const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;     
    size_t bodylen = str.size() - headerLength;
    //const unsigned char *signstart = bodyptr;    
    read_ui(bodyptr, bodylen, t);
    //const unsigned char *signend = bodyptr;
    strMsg = toString();
    msgValid = read_sig(buddy, bodyptr, bodylen, (const unsigned char *)strMsg.data(),
    							(const unsigned char *)strMsg.data()+ strMsg.length());
    DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());
    msg_ID = g_recv_ID;
}

string PingNetworkMessage::toString() const{
	string msgStr;	
	write_ui(msgStr, t);
	addMsgHeader(NET_MSG_PING, msgStr);
	return msgStr;
}


VSSSendMessage::VSSSendMessage(Phase ph, const Commitment &C, const Polynomial &a)
	:ph(ph),C(C),a(a){
  string body;
  write_ui(body, ph);
  body.append(C.toString());
  write_Poly(body,a);
  addMsgHeader(VSS_SEND, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}

VSSSendMessage:: VSSSendMessage(const Buddy *buddy, const string &str, int g_recv_ID)
  : NetworkMessage(str){
    const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
    size_t bodylen = str.size() - headerLength;
	read_ui(bodyptr, bodylen, ph);
	C = Commitment(buddy->get_param(), bodyptr, bodylen);
	read_Poly(bodyptr, bodylen,a, buddy->get_param().get_Pairing());
	msg_ID = g_recv_ID;
}

VSSEchoMessage:: VSSEchoMessage(NodeID dealer,Phase ph,	const Commitment& C, const Zr& alpha)
  :dealer(dealer), ph(ph),C(C),alpha(alpha)
{
  string body;
  write_us(body,dealer);
  write_ui(body, ph);
  body.append(C.toString());
  write_Zr(body,alpha);
  addMsgHeader(VSS_ECHO, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}

VSSEchoMessage::VSSEchoMessage(const Buddy *buddy, const string &str, int g_recv_ID) 
  : NetworkMessage(str){
  const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
  unsigned int bodylen = str.size() - headerLength;
  read_us(bodyptr, bodylen, dealer);
  read_ui(bodyptr, bodylen, ph);
  C = Commitment(buddy->get_param(), bodyptr, bodylen);
  read_Zr(bodyptr, bodylen, alpha, buddy->get_param().get_Pairing());
  msg_ID = g_recv_ID;
}

VSSReadyMessage::VSSReadyMessage(const BuddySet &buddyset,NodeID dealer,Phase ph,
				const Commitment& C, const Zr& alpha, bool includeSignature)
		:dealer(dealer),ph(ph),C(C),alpha(alpha){
// Zr should be last element of the message and shouldn't be signed
  string body;  
  //size_t signstart = body.size(); 
  write_us(body,dealer);
  write_ui(body, ph);
  body.append(C.toString());
  //size_t signend = body.size();
  strMsg = toString();
  write_byte(body,includeSignature);  
  if(includeSignature){
	write_sig(buddyset, body, strMsg);
	DSA = body.substr(body.size() - buddyset.sig_size());
  }
  write_Zr(body,alpha);  
  addMsgHeader(VSS_READY, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}

VSSReadyMessage::VSSReadyMessage(const Buddy *buddy, const string &str, int g_recv_ID) 
  : NetworkMessage(str){
  const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
  size_t bodylen = str.size() - headerLength;
  msg_ID = g_recv_ID;

  //const unsigned char *signstart = bodyptr;
  
  read_us(bodyptr, bodylen, dealer);
  read_ui(bodyptr, bodylen, ph);
  C = Commitment(buddy->get_param(), bodyptr, bodylen); 
    
  if(bodylen == 0){
  	//This will happen for object generated from strMsg.
  	//They do not contain a signature or a Zr element
  	strMsg = str;
  	return;
  } else 
	//Signature and share are kep outside the message string
	strMsg = toString();

  //const unsigned char *signend = bodyptr;
  unsigned char includeSignature;
  read_byte(bodyptr,bodylen, includeSignature);
  if((bool)includeSignature){
	msgValid = read_sig(buddy, bodyptr, bodylen, (const unsigned char *)strMsg.data(),
							(const unsigned char *)strMsg.data() + strMsg.length());	
	DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());		
  } else msgValid = true;
  read_Zr(bodyptr, bodylen, alpha, buddy->get_param().get_Pairing());
}

string VSSReadyMessage::toString() const{
	string strMsg;
	write_us(strMsg,dealer);
	write_ui(strMsg, ph);
	strMsg.append(C.toString(false));
    addMsgHeader(VSS_READY,strMsg);
    return strMsg;	
}

VSSHelpMessage::VSSHelpMessage(const BuddySet &buddyset, Phase ph)
	: ph(ph) {
	string body;
	write_ui(body, ph);
	addMsgHeader(VSS_HELP, body); 
	addMsgID(msg_ID, body);
	set_netMsgStr(body);
}


VSSHelpMessage:: VSSHelpMessage(const Buddy *buddy, const string &str, int g_recv_ID)
  : NetworkMessage(str) {
  const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
  size_t bodylen = str.size() - headerLength;
  read_ui(bodyptr, bodylen, ph);
  msg_ID = g_recv_ID;
}

VSSSharedMessage::VSSSharedMessage(Phase ph, NodeID dealer,	const VSSReadyMessage& readyMsg, 
								const map <NodeID, string>& msgDSAs)
	:ph(ph), dealer(dealer), readyMsg(readyMsg), msgDSAs(msgDSAs){
	string body;
  	write_ui(body, ph);
  	write_us(body,dealer);
  	write_ui(body,readyMsg.strMsg.length());
  	body.append(readyMsg.strMsg);
  	write_us(body,(NodeID)msgDSAs.size());
	map <NodeID, string>::const_iterator iter1d;
	for(iter1d = msgDSAs.begin(); iter1d != msgDSAs.end(); ++iter1d){
	  write_us(body,iter1d->first);
	  //write_ui(body,iter1d->second.strMsg.length());
	  body.append(iter1d->second);
	}  	
}

VSSSharedMessage::VSSSharedMessage(const Buddy *buddy, const string &str, int g_recv_ID)
    : NetworkMessage(str){
  	const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
	size_t bodylen = str.size() - headerLength;
	 msg_ID = g_recv_ID;
	read_ui(bodyptr, bodylen, ph);
	read_us(bodyptr, bodylen,dealer);
	//Read ReadyMessage	
	size_t length; 
    	read_ui(bodyptr,bodylen,length);
	
	const unsigned char *signstart = bodyptr;
	readyMsg = VSSReadyMessage(buddy,str.substr(str.length() - bodylen, length));
	bodylen-= length; bodyptr+= length;
	const unsigned char *signend = bodyptr;
		
  	//Deserialize Signature on VSSReadyMessage
  	unsigned short size; read_us(bodyptr, bodylen, size);
  	if(size < 2*buddy->get_param().get_t() + 1) {msgValid = false; return;} 
  	for(unsigned short i = 0; i< size; ++i){
		NodeID sender; read_us(bodyptr, bodylen, sender);
		msgValid = read_sig(buddy->find_other_buddy(sender), bodyptr, bodylen, signstart, signend);
		if (!msgValid) return; 		
		string DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());		
		msgDSAs.insert(pair<NodeID,string>(sender,DSA));		
  	}
}
/*
DKGSendMessage::DKGSendMessage(Phase ph, const map <VSSReadyMessage, map <NodeID, string>, 
			VSSReadyMessageCmp>& vssReadyMsg):ph(ph), msgType(VSS_READY),vssReadyMsg(vssReadyMsg){
  	string body;
  	bool isLeaderChangePresent = false;
  	map <NodeID, string>::const_iterator iter1d;
  	write_ui(body, ph);
    write_byte(body,isLeaderChangePresent);
    
    write_byte(body,msgType); 
  	//Serialize VSSReady Messages
  	map <VSSReadyMessage, map <NodeID, string> >::const_iterator iter2dMsg;
	write_us(body,(NodeID)vssReadyMsg.size());
  	for(iter2dMsg = vssReadyMsg.begin(); iter2dMsg != vssReadyMsg.end(); ++iter2dMsg){
		write_ui(body,iter2dMsg->first.strMsg.length());
		body.append(iter2dMsg->first.strMsg);
		write_us(body,(NodeID)iter2dMsg->second.size());
		for(iter1d = iter2dMsg->second.begin(); iter1d != iter2dMsg->second.end();++iter1d){
	  		write_us(body,iter1d->first);
	  		body.append(iter1d->second);
		}
  	}
  	addMsgHeader(DKG_SEND, body); set_netMsgStr(body);
}
*/
DKGSendMessage::DKGSendMessage(Phase ph, const LeaderChangeMessage& leadChgMsg,const map<NodeID, string>& leadChgMsgDSAs,
							const map <VSSReadyMessage, map <NodeID, string>, VSSReadyMessageCmp >& vssReadyMsg)
  	:ph(ph), leadChgMsg(leadChgMsg),leadChgMsgDSAs(leadChgMsgDSAs), msgType(VSS_READY), vssReadyMsg(vssReadyMsg){
  	string body;
  	bool isLeaderChangePresent = true;
  	map <NodeID, string>::const_iterator iter1d;
  	write_ui(body, ph);
 	write_byte(body,isLeaderChangePresent);
 	
  	//Serialize LeaderChange Messages
  	//map <LeaderChangeMessage, map <NodeID, string> >::const_iterator iter2dLead;
  	//write_us(body,(NodeID)leadChgMsg.size());
  	//for(iter2dLead = leadChgMsg.begin(); iter2dLead != leadChgMsg.end(); ++iter2dLead){
	write_ui(body,leadChgMsg.strMsg.length());
	body.append(leadChgMsg.strMsg);
	write_us(body,(NodeIDSize)leadChgMsgDSAs.size());
	for(iter1d = leadChgMsgDSAs.begin(); iter1d != leadChgMsgDSAs.end(); ++iter1d){
		write_us(body,iter1d->first);		
		body.append(iter1d->second);	
	}
	write_byte(body,msgType);
	
  	//Serialize VSSReady Messages
  	map <VSSReadyMessage, map <NodeID, string> >::const_iterator iter2dMsg;
	write_us(body,(NodeID)vssReadyMsg.size());
  	for(iter2dMsg = vssReadyMsg.begin(); iter2dMsg != vssReadyMsg.end(); ++iter2dMsg){
		write_ui(body,iter2dMsg->first.strMsg.length());
		body.append(iter2dMsg->first.strMsg);
		write_us(body,(NodeID)iter2dMsg->second.size());
		for(iter1d = iter2dMsg->second.begin(); iter1d != iter2dMsg->second.end();++iter1d){
	  		write_us(body,iter1d->first);
	  		body.append(iter1d->second);
		}
  	}
  	addMsgHeader(DKG_SEND, body);
  	addMsgID(msg_ID, body);
  	set_netMsgStr(body);
}

DKGSendMessage::DKGSendMessage(Phase ph, const LeaderChangeMessage& leadChgMsg,const map<NodeID, string>& leadChgMsgDSAs,
				 NetworkMessageType msgType, const DKGEchoOrReadyMessage& dkgEchoOrReadyMsg,const map <NodeID, string>& dkgEchoOrReadyMsgDSAs)	
  	:ph(ph),leadChgMsg(leadChgMsg),leadChgMsgDSAs(leadChgMsgDSAs),msgType(msgType),dkgEchoOrReadyMsg(dkgEchoOrReadyMsg),
  	dkgEchoOrReadyMsgDSAs(dkgEchoOrReadyMsgDSAs){
  	string body;
  	bool isLeaderChangePresent = true;
  	map <NodeID, string>::const_iterator iter1d;
  	write_ui(body, ph);
  	write_byte(body,isLeaderChangePresent);
 	
 	
  	//Serialize LeaderChange Messages
  	//map <LeaderChangeMessage, map <NodeID, string> >::const_iterator iter2dLead;
  	//write_us(body,(NodeID)leadChgMsg.size());
  	//for(iter2dLead = leadChgMsg.begin(); iter2dLead != leadChgMsg.end(); ++iter2dLead){
	write_ui(body,leadChgMsg.strMsg.length());
	body.append(leadChgMsg.strMsg);
	write_us(body,(NodeIDSize)leadChgMsgDSAs.size());
	for(iter1d = leadChgMsgDSAs.begin(); iter1d != leadChgMsgDSAs.end(); ++iter1d){
		write_us(body,iter1d->first);		
		body.append(iter1d->second);	
	}
	
	write_byte(body,msgType);	
  	//Serialize DKGEchoOrReady Message
  	//map <DKGEchoOrReadyMessage, map <NodeID, string> >::const_iterator iter2dMsg;
	//write_us(body,(NodeID)dkgEchoOrReadyMsg.size());
  	//for(iter2dMsg = dkgEchoOrReadyMsg.begin(); iter2dMsg != dkgEchoOrReadyMsg.end(); ++iter2dMsg){
	write_ui(body,dkgEchoOrReadyMsg.strMsg.length());
	body.append(dkgEchoOrReadyMsg.strMsg);
	write_us(body,dkgEchoOrReadyMsgDSAs.size());
	for(iter1d = dkgEchoOrReadyMsgDSAs.begin(); iter1d != dkgEchoOrReadyMsgDSAs.end();++iter1d){
  		write_us(body,iter1d->first);
  		body.append(iter1d->second);
	} 	
  	addMsgHeader(DKG_SEND, body);
  	addMsgID(msg_ID, body);
  	set_netMsgStr(body);
}


DKGSendMessage::DKGSendMessage(const Buddy *buddy, const string &str, int g_recv_ID)
  : NetworkMessage(str) {
  	NodeIDSize t = buddy->get_param().get_t();
	const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
	size_t bodylen = str.size() - headerLength;
	read_ui(bodyptr, bodylen, ph);
	 msg_ID = g_recv_ID;
	
	unsigned char charLeaderChangePresent; read_byte(bodyptr, bodylen, charLeaderChangePresent);
	bool isLeaderChangePresent = (bool)charLeaderChangePresent;
	
	if (isLeaderChangePresent){
	//Deserialize LeaderChange Messages
		unsigned length = 0; read_ui(bodyptr,bodylen,length);
		const unsigned char *signstart = bodyptr;
		leadChgMsg = LeaderChangeMessage(buddy, str.substr(str.length() - bodylen, length)); 
		bodylen-= length; bodyptr+= length;
		const unsigned char *signend = bodyptr;	
		NodeIDSize size1d; read_us(bodyptr, bodylen, size1d);
		if(size1d < 2*t + 1) {cerr<<"Not enough lc signs\n"; msgValid = false; return;}	
		for(NodeIDSize j = 0; j< size1d; ++j){
			NodeID sender; read_us(bodyptr, bodylen, sender);
			msgValid = read_sig(buddy->find_other_buddy(sender), bodyptr, bodylen, signstart, signend);	
			if (!msgValid) {cerr<<"Invalid lc Signature from sender "<<sender<<" "<<buddy->find_other_buddy(sender)->get_id()<<endl;return;}//Invalid Signature Signature
			string DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());
			leadChgMsgDSAs.insert(make_pair(sender,DSA));  		
		}
	}
	//Deserialize SignedMessage
	unsigned short size2d;
	unsigned char type; read_byte(bodyptr,bodylen, type);
	msgType = (NetworkMessageType)type;
	
	switch (msgType){
	case VSS_READY:{		
		read_us(bodyptr, bodylen, size2d);
  		if(size2d < t + 1) {cerr<<"Not enough VSSs included\n";msgValid = false; return;}
  		for(unsigned short i = 0; i<  size2d; ++i){  	
  			unsigned int length; read_ui(bodyptr,bodylen,length);
			const unsigned char *signstart = bodyptr;
			string strMsg = str.substr(str.length() - bodylen, length);
			VSSReadyMessage msg(buddy,strMsg);
			bodylen-= length; bodyptr+= length;
			const unsigned char *signend = bodyptr;
  			unsigned short size1d; read_us(bodyptr, bodylen, size1d);
			if(size1d < 2*t + 1) {cerr<<"Not enough VSS signs\n";msgValid = false; return;}
		  	map <NodeID, string> DSAMap;
  			for(unsigned short j = 0; j< size1d; ++j){
  				NodeID sender; read_us(bodyptr, bodylen, sender);
  				msgValid = read_sig(buddy->find_other_buddy(sender), bodyptr, bodylen, signstart, signend);
  				if (!msgValid) {cerr<<"Invalid vss Signature for j="<<j<<endl;return;}//Invalid Signature Signature
  				string DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());
  				DSAMap.insert(make_pair(sender,DSA));
  			}
  			vssReadyMsg.insert(make_pair(msg,DSAMap));
  		}
	}break;
	case DKG_ECHO:{
		unsigned int length; read_ui(bodyptr,bodylen,length);
		const unsigned char *signstart = bodyptr;
		string strMsg = str.substr(str.length() - bodylen, length);
		dkgEchoOrReadyMsg = DKGEchoMessage(buddy,strMsg);
		bodylen-= length; bodyptr+= length;
		const unsigned char *signend = bodyptr;
  		unsigned short size1d; read_us(bodyptr, bodylen, size1d);
		if(size1d < 2*t + 1) {cerr<<"Not enough DKGEcho signs\n"; msgValid = false; return;}		
  		for(unsigned short j = 0; j< size1d; ++j){
  			NodeID sender; read_us(bodyptr, bodylen, sender);
  			msgValid = read_sig(buddy->find_other_buddy(sender), bodyptr, bodylen, signstart, signend);
  			if (!msgValid) return;//Invalid Signature Signature
  			string DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());
  			dkgEchoOrReadyMsgDSAs.insert(make_pair(sender,DSA));
  		}
	}break;
	case DKG_READY:{
		unsigned int length; read_ui(bodyptr,bodylen,length);
		const unsigned char *signstart = bodyptr;
		string strMsg = str.substr(str.length() - bodylen, length);
		dkgEchoOrReadyMsg = DKGReadyMessage(buddy,strMsg);
		bodylen-= length; bodyptr+= length;
		const unsigned char *signend = bodyptr;
  		unsigned short size1d; read_us(bodyptr, bodylen, size1d);
		if(size1d < t + 1) {cerr<<"Not enough DKGReady signs\n"; msgValid = false; return;}		
  		for(unsigned short j = 0; j< size1d; ++j){
  			NodeID sender; read_us(bodyptr, bodylen, sender);
  			msgValid = read_sig(buddy->find_other_buddy(sender), bodyptr, bodylen, signstart, signend);
  			if (!msgValid) return;//Invalid Signature Signature
  			string DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());
  			dkgEchoOrReadyMsgDSAs.insert(make_pair(sender,DSA));
  		}
	}break;	
  	default:{cerr<<"Wrong message type\n"; msgValid = false; return;}
	}
}

DKGEchoOrReadyMessage::DKGEchoOrReadyMessage(const BuddySet &buddyset,NetworkMessageType type,NodeID leader,Phase ph,
				   const set <NodeID> &DecidedVSSs, bool includeSignature)
  :leader(leader), ph(ph), DecidedVSSs(DecidedVSSs){
  string body;
  //size_t signstart = body.size();
  write_us(body, leader);
  write_ui(body, ph); 
  
  set<NodeID>::const_iterator iter;
  write_us(body,(NodeID)DecidedVSSs.size());
  //For each CommitmentEntry do following
  for(iter = DecidedVSSs.begin(); iter != DecidedVSSs.end(); ++iter)
	write_us(body,*iter);	
  //size_t signend = body.size();
  strMsg = toString(type);
  write_byte(body,includeSignature);
  if(includeSignature){
	write_sig(buddyset, body, strMsg);
	DSA = body.substr(body.size() - buddyset.sig_size());
  }
  addMsgHeader(type,body);
  addMsgID(msg_ID,body);
  set_netMsgStr(body);
}

DKGEchoOrReadyMessage::DKGEchoOrReadyMessage(const Buddy *buddy, NetworkMessageType type, const string &str, int g_recv_ID)
  : NetworkMessage(str){
  const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
  size_t bodylen = str.size() - headerLength;
  
  //const unsigned char *signstart = bodyptr;
  read_us(bodyptr, bodylen, leader);
  read_ui(bodyptr, bodylen, ph);

  NodeID size; read_us(bodyptr, bodylen, size);
  for(NodeID i = 0; i< size; ++i){
	NodeID sender; read_us(bodyptr, bodylen, sender);
	DecidedVSSs.insert(sender);
  }
  //const unsigned char *signend = bodyptr;
  if (bodylen == 0){
  	strMsg = str; return;
  } else strMsg = toString(type); 
  
  unsigned char includeSignature;
  read_byte(bodyptr,bodylen, includeSignature);
  if((bool)includeSignature){
	msgValid = read_sig(buddy, bodyptr, bodylen, (const unsigned char *)strMsg.data(),
			(const unsigned char *)strMsg.data() + strMsg.length());	
	DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());
  } else msgValid = true;
  msg_ID = g_recv_ID;
}

string DKGEchoOrReadyMessage::toString(NetworkMessageType type) const{
	string body;

	write_us(body, leader);
	write_ui(body, ph);  

	set<NodeID>::const_iterator iter;
	write_us(body,(NodeID)DecidedVSSs.size());
	//For each CommitmentEntry do following
	for(iter = DecidedVSSs.begin(); iter != DecidedVSSs.end(); ++iter)
		write_us(body,*iter);	
	addMsgHeader(type,body);
	return body;
}

DKGHelpMessage::
DKGHelpMessage(const BuddySet &buddyset, NodeID leader, Phase ph)
:leader(leader), ph(ph){
  string body;
  write_us(body,leader);
  write_ui(body, ph);
  addMsgHeader(DKG_HELP, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}

DKGHelpMessage::
DKGHelpMessage(const Buddy *buddy, const string &str, int g_recv_ID)
: NetworkMessage(str){
  const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
  size_t bodylen = str.size() - headerLength;
  read_us(bodyptr, bodylen, leader);
  read_ui(bodyptr, bodylen, ph);
  msg_ID = g_recv_ID;
}

 LeaderChangeMessage::LeaderChangeMessage(const BuddySet &buddyset, Phase ph, NodeID nextLeader,
		const map <VSSReadyMessage, map <NodeID, string> , VSSReadyMessageCmp> &vssReadyMsg, bool includeSignature)
	:ph(ph), nextLeader(nextLeader),msgType(VSS_READY),vssReadyMsg(vssReadyMsg){
	string body;
	map <NodeID, string>::const_iterator iter1d;
	write_ui(body, ph);
	write_us(body,nextLeader);
	write_byte(body,msgType);
	
  	//Serialize VSSReady Messages
  	map <VSSReadyMessage, map <NodeID, string>, VSSReadyMessageCmp>::const_iterator iter2dMsg;
	write_us(body,(NodeID)vssReadyMsg.size());
  	for(iter2dMsg = vssReadyMsg.begin(); iter2dMsg != vssReadyMsg.end(); ++iter2dMsg){
		write_ui(body,iter2dMsg->first.strMsg.length());
		body.append(iter2dMsg->first.strMsg);
		write_us(body,(NodeID)iter2dMsg->second.size());
		for(iter1d = iter2dMsg->second.begin(); iter1d != iter2dMsg->second.end();++iter1d){
	  		write_us(body,iter1d->first);
	  		body.append(iter1d->second);
		}
  	}	
	strMsg = toString();
	write_byte(body,includeSignature);
	if(includeSignature){
		write_sig(buddyset, body, strMsg);
		DSA = body.substr(body.size() - buddyset.sig_size());
	}
	addMsgHeader(LEADER_CHANGE, body);
	addMsgID(msg_ID, body);
	set_netMsgStr(body);
}

LeaderChangeMessage::LeaderChangeMessage(const BuddySet &buddyset, Phase ph,NodeID nextLeader,
					NetworkMessageType msgType,const DKGEchoOrReadyMessage& dkgEchoOrReadyMsg,const map <NodeID, string>& DSAs,
  					bool includeSignature)
  :ph(ph), nextLeader(nextLeader),msgType(msgType),dkgEchoOrReadyMsg(dkgEchoOrReadyMsg),dkgEchoOrReadyMsgDSAs(DSAs){
  string body;
  //size_t signstart = body.size();
  write_ui(body, ph);
  write_us(body,nextLeader);
  write_byte(body,msgType);
  
  write_ui(body,dkgEchoOrReadyMsg.strMsg.length());
  body.append(dkgEchoOrReadyMsg.strMsg);

  map <NodeID, string>::const_iterator iter;
  write_us(body,(NodeID)DSAs.size());  
  for(iter = DSAs.begin(); iter != DSAs.end(); ++iter){   
	  write_us(body,iter->first);
	  body.append(iter->second);
  }
  //size_t signend = body.size();
  strMsg = toString();
  write_byte(body,includeSignature);
  if(includeSignature){
	write_sig(buddyset, body, strMsg);
	DSA = body.substr(body.size() - buddyset.sig_size());
  }
  addMsgHeader(LEADER_CHANGE, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}

LeaderChangeMessage::LeaderChangeMessage(const BuddySet &buddyset,/* Phase ph,*/ NodeID nextLeader, bool includeSignature)
  :ph(0), nextLeader(nextLeader),msgType(NET_MSG_NONE){
	//cout << "3. msg_ctr = " << msg_ctr << endl;

  string body;
  //size_t signstart = body.size();
  write_ui(body, ph);
  write_us(body,nextLeader);  
  //size_t signend = body.size();  
  
  write_byte(body,msgType);
  
  strMsg = toString();
  write_byte(body,includeSignature);
  if(includeSignature){
	write_sig(buddyset, body, strMsg);
	DSA = body.substr(body.size() - buddyset.sig_size());
  }
  addMsgHeader(LEADER_CHANGE, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}


LeaderChangeMessage::LeaderChangeMessage(const Buddy *buddy, const string &str, int g_recv_ID)
  :NetworkMessage(str){
	NodeIDSize t = buddy->get_param().get_t();
  const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
  size_t bodylen = str.size() - headerLength;
  msg_ID = g_recv_ID;

  //const unsigned char *signstart = bodyptr;
  read_ui(bodyptr, bodylen, ph);
  read_us(bodyptr, bodylen, nextLeader);
  //const unsigned char *signend = bodyptr;
  if (bodylen == 0){
  	strMsg = str; return;
  } else strMsg = toString();
  
  unsigned char typeChar; read_byte(bodyptr,bodylen,typeChar);
  msgType = (NetworkMessageType) typeChar;
  
	if (msgType == VSS_READY){
		NodeID size2d;
		read_us(bodyptr, bodylen, size2d);
  		if(size2d < t + 1) {msgValid = false; return;}
  		for(unsigned short i = 0; i< size2d; ++i){  	
  			unsigned int length; read_ui(bodyptr,bodylen,length);
			const unsigned char *signstart = bodyptr;
			string strMsg = str.substr(str.length() - bodylen, length);
			VSSReadyMessage msg(buddy,strMsg);
			bodylen-= length; bodyptr+= length;
			const unsigned char *signend = bodyptr;
  			unsigned short size1d; read_us(bodyptr, bodylen, size1d);
			if(size1d < 2*t + 1) {msgValid = false; return;}
		  	map <NodeID, string> DSAMap;
  			for(unsigned short j = 0; j< size1d; ++j){
  				NodeID sender; read_us(bodyptr, bodylen, sender);
  				msgValid = read_sig(buddy->find_other_buddy(sender), bodyptr, bodylen, signstart, signend);
  				if (!msgValid) return;//Invalid Signature Signature
  				string DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());
  				DSAMap.insert(make_pair(sender,DSA));
  			}
  			vssReadyMsg.insert(make_pair(msg,DSAMap));
  		}
	} else if ((msgType == DKG_ECHO)||(msgType == DKG_READY)){
	  //Read DKGEchoOrReadyMessage
	  unsigned int length; read_ui(bodyptr,bodylen,length);
	  if (length) dkgEchoOrReadyMsg = DKGEchoOrReadyMessage(buddy,NET_MSG_NONE,str.substr(str.length() - bodylen, length));
	  bodylen -= length; bodyptr += length;
	
	  //Deserialize Signature on VSSReadyMessage
	  NodeID size;
	  const unsigned char *start = (const unsigned char *)dkgEchoOrReadyMsg.strMsg.data();
	  const unsigned char *end = (const unsigned char *)dkgEchoOrReadyMsg.strMsg.data() 
	  								+ dkgEchoOrReadyMsg.strMsg.length();
	  read_us(bodyptr, bodylen, size);
	  switch (dkgEchoOrReadyMsg.strMsg[0]){
	  	case DKG_ECHO:if(size < 2*t + 1) {msgValid = false; return;}
	  	case DKG_READY:if(size < t + 1) {msgValid = false; return;}
	  }
	  for(NodeID i = 0; i< size; ++i){
		NodeID sender; read_us(bodyptr, bodylen, sender);
		if (!read_sig(buddy->find_other_buddy(sender), bodyptr, bodylen,start,end)){
			msgValid = false; return;}
		string DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());
		dkgEchoOrReadyMsgDSAs.insert(pair<NodeID,string>(sender,DSA));
	  }
	} else if (msgType == NET_MSG_NONE){
		if (ph) {msgValid = false;return;}
	} else {msgValid = false; return;}
	unsigned char includeSignature;
	read_byte(bodyptr,bodylen, includeSignature);
	if((bool)includeSignature){		
		msgValid = read_sig(buddy, bodyptr, bodylen,(const unsigned char *)strMsg.data(),
			(const unsigned char *)strMsg.data() + strMsg.length());			
		DSA = str.substr(str.size()-bodylen- buddy->sig_size(), buddy->sig_size());
	} else msgValid = true; 	
}

string LeaderChangeMessage::toString() const{
	string body;
	write_ui(body, ph);
	write_us(body,nextLeader);
	addMsgHeader(LEADER_CHANGE, body);
	return body;  
}

PublicKeyExchangeMessage::PublicKeyExchangeMessage(const BuddySet &buddyset, const G1& publicKey)
:publicKey(publicKey){
  string body;
  write_G1(body,publicKey);
  addMsgHeader(PUBLIC_KEY_EXCHANGE, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}

PublicKeyExchangeMessage::PublicKeyExchangeMessage(const Buddy *buddy, const string &str, int g_recv_ID)
:NetworkMessage(str){
	const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
    size_t bodylen = str.size() - headerLength;	
	read_G1(bodyptr, bodylen, publicKey, buddy->get_param().get_Pairing());	
	 msg_ID = g_recv_ID;
}

BLSSignatureRequestMessage::BLSSignatureRequestMessage(const BuddySet &buddyset, Phase ph, const string& msg,
const G1& signature)
	:ph(ph),msg(msg),signature(signature){
  string body;
  write_ui(body, ph);
  write_ui(body,msg.length()); body.append(msg);
  write_G1(body,signature);
  addMsgHeader(BLS_SIGNATURE_REQUEST, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}

BLSSignatureRequestMessage::BLSSignatureRequestMessage(const Buddy *buddy, const string &str, int g_recv_ID)
	:NetworkMessage(str){
	const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
    size_t bodylen = str.size() - headerLength;
	read_ui(bodyptr, bodylen, ph);
	unsigned int length; read_ui(bodyptr, bodylen, length);
	msg = str.substr(str.size()-bodylen,length);
	bodylen -= length; bodyptr += length;
	read_G1(bodyptr, bodylen, signature, buddy->get_param().get_Pairing());
	 msg_ID = g_recv_ID;
}

BLSSignatureResponseMessage::BLSSignatureResponseMessage(const BuddySet &buddyset, Phase ph, const G1& msgHash, 
const G1& signatureShare):ph(ph),msgHash(msgHash),signatureShare(signatureShare){
  string body;
  write_ui(body, ph);
  write_G1(body,msgHash);
  write_G1(body,signatureShare);
  addMsgHeader(BLS_SIGNATURE_RESPONSE, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}

BLSSignatureResponseMessage::BLSSignatureResponseMessage(const Buddy *buddy, const string &str, int g_recv_ID):NetworkMessage(str){
	const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
    size_t bodylen = str.size() - headerLength;
	read_ui(bodyptr, bodylen, ph);
	read_G1(bodyptr, bodylen, msgHash, buddy->get_param().get_Pairing());
	read_G1(bodyptr, bodylen, signatureShare, buddy->get_param().get_Pairing());
}
  
WrongBLSSignaturesMessage::WrongBLSSignaturesMessage(const BuddySet &buddyset, Phase ph, const G1& msgHash, 
const map <NodeID, G1>& signatures):ph(ph),msgHash(msgHash),signatures(signatures){
  string body;
  write_ui(body, ph);
  write_G1(body,msgHash);
  //Serialize signature shares
  map <NodeID, G1>::const_iterator iter;
  write_us(body,(NodeID)signatures.size());
  for(iter = signatures.begin(); iter != signatures.end(); ++iter){
	write_us(body,iter->first);
	write_G1(body,iter->second);
  }	
  addMsgHeader(WRONG_BLS_SIGNATURES, body);
  addMsgID(msg_ID, body);
  set_netMsgStr(body);
}

WrongBLSSignaturesMessage::WrongBLSSignaturesMessage(const Buddy *buddy, const string &str, int g_recv_ID)
:NetworkMessage(str){
	const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
    size_t bodylen = str.size() - headerLength;
	read_ui(bodyptr, bodylen, ph);
	read_G1(bodyptr, bodylen, msgHash, buddy->get_param().get_Pairing());
	unsigned short size; read_us(bodyptr, bodylen, size);
	NodeIDSize t = buddy->get_param().get_t();
	if(size < 2* t + 1) {msgValid = false; return;}
	for(NodeID i = 0; i< size; ++i){
		NodeID sender; read_us(bodyptr, bodylen, sender);
		G1 signatureShare; read_G1(bodyptr, bodylen, signatureShare, buddy->get_param().get_Pairing());
		signatures.insert(pair<NodeID,G1>(sender,signatureShare));
	}
    msgValid = true;
    msg_ID = g_recv_ID;
}

VerifiedBLSSignaturesMessage::VerifiedBLSSignaturesMessage(const BuddySet &buddyset, Phase ph, const G1& msgHash, 
const map <NodeID, G1>& signatures):ph(ph),msgHash(msgHash),signatures(signatures){
	string body;
	write_ui(body, ph);
	write_G1(body,msgHash);
  	//Serialize signature shares
  	map <NodeID, G1>::const_iterator iter;
  	write_us(body,(NodeID)signatures.size());
  	for(iter = signatures.begin(); iter != signatures.end(); ++iter){
		write_us(body,iter->first);
		write_G1(body,iter->second);
  	}	
	addMsgHeader(VERIFIED_BLS_SIGNATURES,body);
	addMsgID(msg_ID,body);
	set_netMsgStr(body);
}

VerifiedBLSSignaturesMessage::VerifiedBLSSignaturesMessage(const Buddy *buddy, const string &str, int g_recv_ID)
:NetworkMessage(str){
	const unsigned char *bodyptr = (const unsigned char *)str.data() + headerLength;
    	size_t bodylen = str.size() - headerLength;
	read_ui(bodyptr, bodylen, ph);
	read_G1(bodyptr, bodylen, msgHash, buddy->get_param().get_Pairing());
	unsigned short size; read_us(bodyptr, bodylen, size);
	NodeIDSize t = buddy->get_param().get_t();
	if(size < t + 1) {msgValid = false; return;}
	for(NodeID i = 0; i< size; ++i){
		NodeID sender; read_us(bodyptr, bodylen, sender);
		G1 signatureShare; read_G1(bodyptr, bodylen, signatureShare, buddy->get_param().get_Pairing());
		signatures.insert(pair<NodeID,G1>(sender,signatureShare));
	}
    msgValid = true;
}
