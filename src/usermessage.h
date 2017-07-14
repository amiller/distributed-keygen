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



#ifndef __USERMESSAGE_H__
#define __USERMESSAGE_H__

#include "message.h"
#include "io.h"
#include "commitment.h"
#include <set>

typedef enum {IN, OUT} IOType;

typedef enum {
    USER_MSG_NONE,
	SHARE, CONFIRM_LEADER, SHARED, RECOVER, RECONSTRUCT, DKG_COMPLETE, 
	STATE_INFORMATION, SIGN, USER_MSG_PING
} UserMessageType;

//class for network messages in the system
class UserMessage: public Message {
 public:
  static UserMessage* read_message();
  UserMessage() { message_class = USER; msgtype = USER_MSG_NONE; }
  UserMessageType get_type() const { return msgtype; }
 protected:
  UserMessageType msgtype;
};

class PingUserMessage : public UserMessage {
public:
  PingUserMessage(int who) : who(who) { msgtype = USER_MSG_PING; }
  int get_who() const { return who; }
private:
  int who;
};


class ShareMessage : public UserMessage {
public:
  ShareMessage(){ msgtype = SHARE; }
  //Phase getPhase() const { return ph;}
  //const Zr getSecret() const { return secret;}
  //Phase ph; As you share new value only for phase 0
  //private:
  //Zr secret; As pairing parameters are not available here
};

class ConfirmLeaderMessage : public UserMessage {
public:
  ConfirmLeaderMessage(){ msgtype = CONFIRM_LEADER; }
};
class UserSharedMessage : public UserMessage {
	public:
  	UserSharedMessage(Phase ph, NodeID dealer, const Commitment& C, const Zr& share) 
		: ph(ph), dealer(dealer),C(C), share(share){ msgtype = SHARED; }
  	Phase getPhase() const { return ph;}
  	NodeID getDealer() const {return dealer;}
 	const Commitment getCommitment() const {return C;}
  	const Zr getShare() const {return share;}
  	void dump(FILE *f, unsigned int indent = 0) const;
  	
	private:		
  	Phase ph;
  	NodeID dealer;
    Commitment C;
   	Zr share;
};

class DKGCompleteMessage : public UserMessage {
	public:
  	DKGCompleteMessage(Phase ph, NodeID leader, set <NodeID> DecidedVSSs, const Commitment& C, const Zr& share) 
		: ph(ph), leader(leader), DecidedVSSs(DecidedVSSs), C(C), share(share){ msgtype = DKG_COMPLETE; }
  	Phase getPhase() const {return ph;}
  	NodeID getLeader() const {return leader;}
 	const Commitment getCommitment() const {return C;}
  	const Zr getShare() const {return share;}
  	void dump(FILE *f, unsigned int indent = 0) const;
  	
	private:		
  	Phase ph;
  	NodeID leader;
  	set <NodeID> DecidedVSSs;
    Commitment C;
   	Zr share;
};

class RecoverMessage : public UserMessage {
public:
  RecoverMessage(const string& str) { 
	msgtype = RECOVER;   
	char* data = (char*) str.data();
	//char charType[20];
	sscanf(data,"%u",(unsigned int*)&ph);
  }
  //  Phase getPhase() const { return ph;}
  //private:
  Phase ph;
};

class ReconstructMessage : public UserMessage {
public:
  ReconstructMessage(){ msgtype = RECONSTRUCT; }
  //  Phase getPhase() const { return ph;}
private:
  //  Phase ph;
};

typedef enum{
  NONE,
  ID,
  N,
  T,
  U,
  F,
  STATE,
  PHASE,
  LEADER,
  COMMITMENT,
  MYSHARE,
  ACTIVE_NODES} StateInformationType;

class StateInformationMessage: public UserMessage {
public:
  StateInformationMessage(){
	msgtype = STATE_INFORMATION;
	type = NONE;
  }
  StateInformationMessage(const string& str);
//private:
  StateInformationType type; 
  //NodeID vectorID;
};

class BLSSignatureRequestUserMessage: public UserMessage {
public:
	BLSSignatureRequestUserMessage() {msgtype = SIGN;}
	BLSSignatureRequestUserMessage(const string& str){msgtype = SIGN; msg = str;}
		
	string msg;
};
#endif
