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



#include <iostream>
#include "usermessage.h"
//#include "variousmessages.h"

using namespace std;

// Read a user command from stdin
UserMessage *UserMessage::read_message()
{
    string command;
    getline(cin, command);

    if (cin.eof()) {
	return NULL;
    }

    //cerr << "Got user command ``" << command << "''\n";
    const char *cmdstr = command.data();
    if (!strncmp(cmdstr, "ping ", 5)) {
	int who = atoi(cmdstr+5);
	return new PingUserMessage(who);
    }
    //if (!strncmp(cmdstr, "eop",3)) {
	//  return new BBEndOfPhaseMessage();
    //}
	if (!strncmp(cmdstr, "print ",6)) {
	  string paramStr = command.substr(6);
	  //cerr<<"parameter is "<<paramStr;
	  return new StateInformationMessage(paramStr);
    } 	
	if (!strncmp(cmdstr, "recover ",8)) {
	  string paramStr = command.substr(8);
	  return new RecoverMessage(paramStr);
    } 	
	if (!strncmp(cmdstr, "share",5)) {
	  //Note that pairing parameters are not available here
	  return new ShareMessage();
    }
    if (!strncmp(cmdstr, "confirmLeader",5)) {
	  
	  return new ConfirmLeaderMessage();
    }    
    if (!strncmp(cmdstr, "sign ",5)) {
	  string paramStr = command.substr(5);
	  return new BLSSignatureRequestUserMessage(paramStr);
    }
    return new UserMessage();
}

void UserSharedMessage::dump(FILE *f, unsigned int indent) const{
  fprintf(f,"Shared Message\n");
  fprintf(f,"Phase: %u\n Dealer: %u\n",ph,dealer);  
  C.dump(f,indent);
  share.dump(f,NULL,indent);
}

void DKGCompleteMessage::dump(FILE *f, unsigned int indent) const{
	fprintf(f,"DKGCompleted Message\n");
	fprintf(f,"Phase: %u\n Leader: %u\n",ph,leader);
	fprintf(f,"Decided Nodes are [");
	for(set <NodeID>::const_iterator it = DecidedVSSs.begin(); it !=DecidedVSSs.end();++it)		
		fprintf(f," %u ",*it);
	fprintf(f,"]\n");
	C.dump(f,indent);
  	share.dump(f,NULL,indent);
  	fprintf(f,"DKG is Completed :)\n");
}

StateInformationMessage::StateInformationMessage(const string& str){
  msgtype = STATE_INFORMATION;
  char* data = (char*) str.data();
  char charType[20];
  sscanf(data,"%s",charType);
  string strType(charType);	
  if(strType == "id")
	type = ID;
  else if(strType == "n")
	type = N;
  else if(strType == "t")
	type = T;  
  else if(strType == "f")
	type = F;
  else if(strType == "U")
	type = U;
  else if(strType == "state")
	type = STATE;
  else if(strType == "phase")
	type = PHASE;  
  else if(strType == "leader")
	type = LEADER;
  else if(strType == "commitment")
	type = COMMITMENT;
  else if(strType == "share")
	type = MYSHARE;
  else if(strType == "activeNodes")
	type = ACTIVE_NODES;
}
