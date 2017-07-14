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



#include "application.h"
#include "usermessage.h"
#include "networkmessage.h"
#include "timer.h"
#include "exceptions.h"
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <sys/time.h>
#include <fstream>

typedef enum {LEADER_UNCONFIRMED, UNDER_RECOVERY, FUNCTIONAL, AGREEMENT_STARTED, AGREEMENT_COMPLETED, LEADER_CHANGE_STARTED, DKG_COMPLETED} NodeState;

struct commitmentandshare{
	Commitment C;
	Zr share;
};

typedef struct commitmentandshare CommitmentAndShare;

class Node : public Application {
public:
  Node(const char *pairingfile, const char *sysparamfile, in_addr_t listen_addr, in_port_t listen_port,
  	   const char *certfile, const char *keyfile, const char *contactlistfile, Phase ph, CommitmentType commType =  Feldman_Matrix, int nrln = 0):
	Application(NODE, pairingfile, sysparamfile, listen_addr, listen_port, certfile, keyfile, contactlistfile, ph),msgLog("message.log",ios::out), timeoutLog("timeout.log",ios::out){
//  		 Application(NODE, pairingfile, sysparamfile, listen_addr, listen_port, certfile, keyfile, contactlistfile, ph){

	selfID  = NodeID(buddyset.get_my_id());
	non_responsive_leader_number = nrln;

	//For ph >0, the node is under recovery
	//For ph=0, the leader is LEADER_UNCONFIRMED
	nodeState = (ph == 0)?FUNCTIONAL:UNDER_RECOVERY; if (selfID == buddyset.get_leader()) nodeState = LEADER_UNCONFIRMED;
	
	this->commType = commType;
	result.C = Commitment(sysparams, activeNodes, commType);
	result.share = Zr(sysparams.get_Pairing(),(long int) 0);
	nextSmallestLeader = buddyset.get_previous_leader();
	validLeaderChangeMsgCnt = 0;
	leaderChangeTimerID=0;
}
  int run();
  
private:
	NodeID selfID;
	NodeState nodeState;
	set <NodeID> SendReceived;//This keeps track whether send message is received from a node
	CommitmentType commType;
	multimap <NodeID, Commitment> C; //Commitments received
	map <NodeID, CommitmentAndShare> C_final; //DealerIDs and commitment+shares completed
	set <NodeID> DecidedVSSs;//DealerIDs for the dealer set (size = t+1) finalized for the node  
	CommitmentAndShare result; //Final Commitment and Share 
	
	NodeID nextSmallestLeader;// L++ used during LeaderChange
	map <LeaderChangeMessage, map<NodeID, string>, LeaderChangeMessageCmp > leaderChangeMsg;// LeaderChange message received
	size_t validLeaderChangeMsgCnt;
	
	map <VSSReadyMessage, map<NodeID, string>, VSSReadyMessageCmp> vssReadyMsg; //Q and R received
	map <VSSReadyMessage, map<NodeID, string>, VSSReadyMessageCmp> vssReadyMsgSelected; //This contains Q_cap and R_cap

	//This contains Q and M all the Echo and Ready messages received by the node
	map <DKGEchoOrReadyMessage, map<NodeID, string>, DKGEchoOrReadyMessageCmp> dkgEchoOrReadyMsgReceived;
		
	//Echo or ready certificate from the previous leader
	DKGEchoOrReadyMessage dkgReadyValidityMsg;
	map <NodeID, string> dkgReadyValidityMsgDSAs;
	//This contains Q_bar and M_bar

	TimerID leaderChangeTimerID;
	
	fstream msgLog;
	fstream timeoutLog;
	bool timer_set;
	
	map <NodeID, G1> clientPublicKeys;
	
	int non_responsive_leader_number;
	int incremental_change;
	
	void hybridVSSInit(const Zr& secret);// Share the secret using HybridVSS
	void startAgreement(); // Start DKG as t+1 VSSs have completed
	void completeDKG(); //(Try to) complete DKG of the DecidedVSSs set
	void sendLeaderChangeMessage(NodeID nextLeader);
	void changePhase();
};

int Node::run()
{	
  /*cerr<<"Node "<<selfID<< " is ";
  switch(nodeState){
  	case LEADER_UNCONFIRMED: cerr<<"not yet confirmed.";break;
  	case UNDER_RECOVERY: cerr<<"under recovery.";break;
  	case FUNCTIONAL: cerr<<"functional.";break;
	case AGREEMENT_STARTED: cerr<<"in state Agreement_Started.";break;
	case LEADER_CHANGE_STARTED: cerr<<"in state LeaderChange_Started.";break;
	case AGREEMENT_COMPLETED: cerr<<"in state Agreement_Completed.";break;
	case DKG_COMPLETED: cerr<<"in state DKG_Completed.";break;		  
  }
  cerr<<endl;*/
	msgLog << setfill('0');
	cout << setfill('0');
	timeoutLog << setfill('0');
	timer_set = false;

  // Initialize measurements
  timeval now;

  //first sleep for a small duration to get synchronization (will not be required once recovery mech. completes)
  gettimeofday (&now, NULL);
  cout << "-Run node " << selfID << " starting at " << now.tv_sec << "." << setw(6) <<
		  now.tv_usec << " with version 8.0" << endl;
  msgLog << "-Run node " << selfID << " starting at " << now.tv_sec << "." << setw(6) << now.tv_usec
		  << " with version 8.0" << endl;

  //if (selfID != buddyset.get_leader()) sleep (sysparams.get_n()/2);
  gettimeofday (&now, NULL);
  msgLog<< "-Function node " << selfID << " starting at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;

  fstream timeoutValueStream ("timeout.value", ios::in); 
  string line_indicator;
  int t_n, t_t, t_f;
  incremental_change = 0;
  while (timeoutValueStream >> line_indicator) {
	timeoutValueStream >> t_n;
	timeoutValueStream >> t_t;
	timeoutValueStream >> t_f;
	if (t_n == sysparams.get_n() && t_t == sysparams.get_t()
		&& t_f == sysparams.get_f()) {
		timeoutValueStream >> incremental_change;
		timeoutValueStream.close();
		break;
	} else {
		int temp;
		timeoutValueStream >> temp;
	}
  }

  timeoutLog << "==============================" << endl;
  timeoutLog << "Para: n = " << t_n << " t = " << t_t << " f = " << t_f << endl;
  timeoutLog << "Incremental Change = " << incremental_change << endl;
  timeoutLog << "==============================" << endl;

  if(!ph){//ph =0; Send LeaderChange to the leader, which it may use with the DKGSend
		//The leader now has wait for 2t+1 LeaderChange Message before starting the agreement
		measure_init();
		LeaderChangeMessage leadChg = LeaderChangeMessage(buddyset, buddyset.get_leader());
		buddyset.send_message(buddyset.get_leader(),leadChg);

		gettimeofday (&now, NULL);
		msgLog << "LEADER_CHANGE " << leadChg.get_ID() << " for " << "* SENT from " << selfID <<
				" to " << buddyset.get_leader() << " at " <<  now.tv_sec << "." << setw(6) <<
				now.tv_usec << " standard 1" << endl;

		if(selfID <= 2*sysparams.get_t()+1){
		//	if (selfID != buddyset.get_leader())
				//sleep(10);
			Zr secret(sysparams.get_Pairing(), true);//Start sharing
			//Initialize a HybribVSS with the above generated secret
			hybridVSSInit(secret);
		}			
		gettimeofday (&now, NULL);
		if (selfID == buddyset.get_leader()) {
			msgLog << "* I am ready to receive at " <<  now.tv_sec << "." << setw(6) <<
				now.tv_usec << endl;
		}

		// upon starting, send VSS_HELP messages to everyone in the system
		vector<NodeID>::iterator iter;
		for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
			if (*iter == selfID)
				continue;
			VSSHelpMessage vssHelp (buddyset, ph);
			buddyset.send_message(*iter,vssHelp);
			gettimeofday (&now, NULL);
			msgLog << "VSS_HELP " << vssHelp.get_ID() << " for " << "* SENT from " << selfID << " to " << *iter << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
		}
	}
   
  int first_time = 1;
  //sleep (60);
  while(1) {
  	NodeID buddyID = 0;//0 for timer and user messages
	if (first_time == 1 && selfID == buddyset.get_leader()) {
		gettimeofday (&now, NULL);
		msgLog << "* I started to receive at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
		first_time = 0;
	}
	// cout << "ready for next message" << endl;
  	Message *m = get_next_message(buddyID, selfID);
	gettimeofday(&now, NULL);
	// cout << "next message" << endl;
  switch(m->get_class()) {
  case USER:{
	  UserMessage *um = static_cast<UserMessage*>(m);
	  switch(um->get_type()) {
	  case USER_MSG_PING:{
		PingUserMessage *pum = static_cast<PingUserMessage*>(um);
		cerr << "Pinging " << pum->get_who() << "\n";
		PingNetworkMessage pnm(buddyset, time(0));
		buddyset.send_message(pum->get_who(), pnm);
	  }break;

	  case SHARE:{
		//ShareMessage *sm = static_cast<ShareMessage*>(um);
		if (ph != 0) {
		  cerr<<"Phase is greater than 0. Node cannot share a new value"<<endl;
		  break;
		}
		Zr secret(sysparams.get_Pairing(), true);
		//Initialize a HybribVSS with the above generated secret
		hybridVSSInit(secret);
	  }break;

	 case CONFIRM_LEADER:{
		if(!ph){//ph =0; Send LeaderChange to the leader, which it may use with the DKGSend
			LeaderChangeMessage leadChg = LeaderChangeMessage(buddyset, buddyset.get_leader());
			buddyset.send_message(buddyset.get_leader(),leadChg);
		}	 	
	 }break;

	  case STATE_INFORMATION:{
		StateInformationMessage *sim =static_cast<StateInformationMessage*>(um);
		switch(sim->type){
		case ID:
		  	cerr<<"ID for node is "<<selfID; break;
		case N:
		  	cerr<<"n is "<<sysparams.get_n(); break;
		case T:
		  	cerr<<"t is "<<sysparams.get_t(); break;
		case F:
		  	cerr<<"f is "<<sysparams.get_f(); break;
		case U:
		  	(sysparams.get_U()).dump(stderr,(char*)"U is ",10);break;
		case STATE:
		  	cerr<<"Node is ";
			  switch(nodeState){
			  	case LEADER_UNCONFIRMED: cerr<<"not yet confirmed.";break;
			  	case UNDER_RECOVERY: cerr<<"under recovery.";break;
			  	case FUNCTIONAL: cerr<<"functional.";break;
				case AGREEMENT_STARTED: cerr<<"in state Agreement_Started.";break;
				case LEADER_CHANGE_STARTED: cerr<<"in state LeaderChange_Started.";break;
				case AGREEMENT_COMPLETED: cerr<<"in state Agreement_Completed.";break;
				case DKG_COMPLETED: cerr<<"in state DKG_Completed.";break;		  
			  }		  	
		  	break;
		case PHASE:
		  	cerr<<"Phase is "<<ph;break;		
		case LEADER:
		  	cerr<<"Current leader is "<<buddyset.get_leader();break;
		case COMMITMENT:
			cerr<< "Commitment is"<<endl;
			result.C.dump(stderr);break;
		case MYSHARE:
		  	result.share.dump(stderr,(char*)"Share is ",10); 
		  break;
		case ACTIVE_NODES:
		  	cerr<<"Active Nodes are";
			for(unsigned short i=0; i< activeNodes.size();++i)
				cerr<<" "<<activeNodes[i];break;
		case NONE: default:
		  	cerr<<"State Information Request: Not Well-Formatted";break;
		}
		cerr<<endl;
	  }
		break;
	  case RECOVER:{
		//RecoverMessage *rm = static_cast<RecoverMessage*>(um);
		
		//TODO: Help messages has to be sent.
		//I have to confirm how to store and 
		//send messages from set B during the recovery
		//Also, I should think whether to start new VSS upon recovery 
	  }
	  	break;
	  default:
		{
		  cerr << "Unknown user command " << um->get_type() << endl;
		}
		break;
	  }
	}
	break;

	case NETWORK:
	{
		NetworkMessage *nm = static_cast<NetworkMessage*>(m);
		Buddy *buddy = buddyset.find_buddy_id(buddyID);

		int type = nm->get_message_type();

		switch(type) {
		case NET_MSG_PING:{
			PingNetworkMessage *pnm = static_cast<PingNetworkMessage*>(nm);
			const unsigned char *bodyptr = (const unsigned char *)pnm->DSA.data();
			size_t bodylen = pnm->DSA.length();
			bool valid = read_sig(buddy,bodyptr, bodylen, (const unsigned char *)pnm->strMsg.data(),(const unsigned char *)(pnm->strMsg).data()+ (pnm->strMsg).length());
			if (valid) {
			  cerr << "Ping from id " <<buddyID <<", timestamp = " << pnm->t << "\n";
			} else {
			  cerr<<"Received Invalid ping from id " <<buddyID <<", timestamp = " << pnm->t << "\n";
			}
		}
		break;
		case VSS_SEND:{
			VSSSendMessage *vssSend = static_cast<VSSSendMessage*>(nm);
			gettimeofday(&now, NULL);
			msgLog << "VSS_SEND " << vssSend -> get_ID() << " for " << "* RECEIVED from " << buddyID << " to " << selfID << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
			//if (selfID == buddyset.get_leader()) {
			//}
			if(ph > vssSend->ph) {
			//TODO: Actual system need not to display the following messages.
			  //cerr<<"Phase for VSSSend "<<vssSend->ph<<" is older than the current phase "<<ph<<endl;
			} else if(ph < vssSend->ph) {
				//TODO: Messages from the future phase should be stored. 
				//Do it when I make decision about the recovery set B  
			} else if ((nodeState != DKG_COMPLETED)&&
				//condition below make sure that if the DKG is complete, then VSS only for NodeID the decided set continue
				((nodeState != AGREEMENT_COMPLETED)||(find(DecidedVSSs.begin(), DecidedVSSs.end(),buddyID) != DecidedVSSs.end()))) {
				//Send message from the same phase
				if(vssSend->C.verifyPoly(sysparams,selfID,vssSend->a)){							
					//multimap<NodeID, Commitment>::iterator> ret;
					//bool commitmentAlreadyExists = false;
					//ret = C.equal_range(buddyID);
					//if(ret.first != ret.second) 
					//	commitmentAlreadyExists = true; 
					//Commitment Already Exists for this buddy. Do not send Echo again, too.
					//Do not add new one here. Note that you may add new Commitment after receiving Echo
					//Honest nodes sends just one Echo message.
					if (SendReceived.find(buddyID) == SendReceived.end()){
						SendReceived.insert(buddyID);
						//C is sent for the first time. Add it
						//multimap <NodeID, Commitment>::iterator it = 
						C.insert(pair<NodeID, Commitment>(buddyID,vssSend->C));
						
						//Send Echo messages for it
						// Note that Echos are not sent twice for a buddy

						vector<NodeID>::iterator iter;//For the active nodes list
						for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
  							Zr nodeZr = Zr(sysparams.get_Pairing(),(long int)*iter);
							Zr alpha = (vssSend->a)(nodeZr);												
							gettimeofday (&now, NULL);
							//if (*iter != selfID){
							VSSEchoMessage vssEcho(buddyID, ph,vssSend->C, alpha);
							buddyset.send_message(*iter, vssEcho);
							gettimeofday (&now, NULL);
							msgLog << "VSS_ECHO " << vssEcho.get_ID() << " for " << vssEcho.dealer << " SENT from " << selfID << " to " << *iter << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " standard 1" << endl;
  						}				
					} else {
						break;
						}// else{ cerr<<"BuddyID is "<<it->first<<" and not"<<buddyID<<endl; it->second.dump(stderr);}
					//for(it = C.begin(); it != C.end(); ++it){ cerr<<"BuddyID is"<<it->first<<endl; it->second.dump(stderr);} 
				} else cerr<<"Error with the VSSsend message received at "<<selfID<<" from "<<buddyID<<endl;
			}							  
		}
		break;
		case VSS_ECHO:{
			VSSEchoMessage *vssEcho = static_cast<VSSEchoMessage*>(nm);

			gettimeofday(&now, NULL);
			msgLog << "VSS_ECHO " << vssEcho->get_ID() << " for " << vssEcho -> dealer << " RECEIVED from " << buddyID << " to " << selfID << " at " << now.tv_sec << "." << setw(6) << now.tv_usec << endl;
			//vssEcho->alpha.dump(stderr,"Alpha received is");

			//if (selfID == buddyset.get_leader()) {
		//	}

			if(ph > vssEcho->ph) {
			//TODO: Actual system need not to display the following messages.
			  cerr<<"Phase for VSSEcho "<<vssEcho->ph<<" is older than the current phase "<<ph<<endl;			  
			} else if(ph < vssEcho->ph) {
				//TODO: Messages from the future phase should be stored. 
				//Do it when I make decision about the recovery set B  
			  	
			} else if((nodeState != DKG_COMPLETED)&&
				//condition below make sure that if the DKG is complete, then VSS only for NodeID the decided set continue
				((nodeState!=AGREEMENT_COMPLETED)||(find(DecidedVSSs.begin(),DecidedVSSs.end(),vssEcho->dealer)!= DecidedVSSs.end()))){
				if(vssEcho->C.verifyPoint(sysparams,buddyID,selfID,vssEcho->alpha)){
					//Echo message from the same phase and message verified
					multimap<NodeID, Commitment>::iterator it;
					pair<multimap<NodeID, Commitment>::iterator, multimap<NodeID, Commitment>::iterator> ret;					
					bool commitmentAlreadyExists = false;
					ret = C.equal_range(vssEcho->dealer);
					it = ret.first;
					
					while (it!=ret.second){	
						if (it->second == vssEcho->C){
							commitmentAlreadyExists = true;	//C already exists
							break;
						}++it;
					}
					if (!commitmentAlreadyExists) {//C is sent for the first time. Add it
						it = C.insert(make_pair(vssEcho->dealer, vssEcho->C));
					}

						//cerr<<vssEcho->dealer<<" inserted with Echo\n";
				
					//Add share and increase Echo count in commitment matrix 	
					if (!it->second.addEchoMsg(buddyID, vssEcho->alpha)) {
						// msgLog << "* Replicated Echo Message" << endl;
						break;
						// This is NOT the first echo message from sender for dealer
					}
				
					NodeIDSize echo_threshold = (NodeIDSize)ceil((sysparams.get_n() + sysparams.get_t() + 1.0)/2);
				//	cout << "Current Echo and ready count is "<< it->second.getEchoMsgCnt()<<" "<<it->second.getReadyMsgCnt()<<endl;
				//	cout << "Threshold = " << echo_threshold << endl;
					if((it->second.getEchoMsgCnt() == echo_threshold) && (it->second.getReadyMsgCnt() < sysparams.get_t() + 1)){
						bool EchoOrReady = false;//EchoOrReady = Echo					
						vector<Zr> subshares = it->second.interpolate(sysparams,EchoOrReady,activeNodes);
						if (commType == Feldman_Vector)		
							it->second.setSubshares(sysparams,subshares);

						msgLog << endl << endl << endl;
						msgLog << "============================================" << endl;
						msgLog << "*ENOUGH VSS_ECHO message for " << vssEcho ->dealer << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
						msgLog << "*Threshold : echo = " << echo_threshold << endl;
						msgLog << "*Received Echo Message Num = " << it->second.getEchoMsgCnt() << endl;
						msgLog << "*Ready messages are sending out..." << endl;
						msgLog << "============================================" << endl << endl;

						vector<NodeID>::const_iterator iter;//For the active nodes list					
						unsigned int index = 0;//Note that starting with zero as first the value is an evaluation at zero
						for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
							//if (*iter != selfID){
							++index;
							VSSReadyMessage vssReady(buddyset,it->first, ph, it->second, subshares[index]);	
							buddyset.send_message(*iter, vssReady);
							gettimeofday (&now, NULL);
							msgLog << "VSS_READY " << vssReady.get_ID() << " for " << vssReady.dealer << " SENT from " << selfID << " to " << *iter << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " standard 1" << endl;
						}
					}
				} else cerr<<"Error at "<<selfID<<" with the VSSEcho message received from "<<buddyID<<" for "<<vssEcho->dealer<<endl;
			}
		}
		break;
		case VSS_READY:{
			VSSReadyMessage *vssReady = static_cast<VSSReadyMessage*>(nm);
			gettimeofday(&now, NULL);
			msgLog << "VSS_READY " << vssReady ->get_ID() << " for " << vssReady -> dealer << " RECEIVED from " << buddyID << " to " << selfID
					<< " at " << now.tv_sec << "." << setw(6) << now.tv_usec << endl;

			//if (selfID == buddyset.get_leader()) {
		//	}

			//cerr<<"Ready Message received from "<<buddyID<<" for "<<vssReady->dealer<<endl;
			if(ph > vssReady->ph) {
			//TODO: Actual system need not to display the following messages.
			  cerr<<"Phase for VSSReady "<<vssReady->ph<<" is older than the current phase "<<ph<<endl;				  
			} else if(ph < vssReady->ph) {
				//TODO: Messages from the future phase should be stored. 
				//Do it when I make decision about the recovery set B  
			} else if((vssReady->msgValid)&&(nodeState!=DKG_COMPLETED)&&
				//condition below make sure that if the DKG is complete, then VSS only for NodeID the decided set continue
					((nodeState!=AGREEMENT_COMPLETED)||(find(DecidedVSSs.begin(),DecidedVSSs.end(),vssReady->dealer)!= DecidedVSSs.end()))){
				if(vssReady->C.verifyPoint(sysparams, buddyID, selfID, vssReady->alpha)){	
					multimap<NodeID, Commitment>::iterator it;
					pair<multimap<NodeID, Commitment>::iterator, multimap<NodeID, Commitment>::iterator> ret;					
					bool commitmentAlreadyExists = false;
					ret = C.equal_range(vssReady->dealer);
					it=ret.first;
					while (it != ret.second){
						if (it->second == vssReady->C){
							commitmentAlreadyExists = true;//C already exists 
							break;
						}++it;
					}
					if (!commitmentAlreadyExists)//C is sent for the first time. Add it
						it = C.insert(make_pair(vssReady->dealer, vssReady->C));
						//cerr<<vssReady->dealer<<" inserted with Ready\n";
					//Add ready share and increase ready count	
					if (!it->second.addReadyMsg(buddyID, vssReady->alpha)) {
						// msgLog << "* NOT first time seen the ready message" << endl;
						break;
					}
					// msgLog << " * ReadyMsg Number = " << it->second.getReadyMsgCnt() << endl;
		
					// Set the Ready Messages Set 'R'.
					VSSReadyMessage vssReady_SignRemoved = VSSReadyMessage(buddy, vssReady->strMsg);
					map <VSSReadyMessage, map <NodeID, string> >::iterator
									ready_it = vssReadyMsg.find(vssReady_SignRemoved);
					if(ready_it == vssReadyMsg.end()){//No entry for this dealer
						map <NodeID, string> signature;
						signature.insert(make_pair(buddyID,vssReady->DSA));
						ready_it = vssReadyMsg.insert(make_pair(vssReady_SignRemoved,signature)).first;
					}else//Entry for this dealer exists. Add signer and signature pair
						ready_it->second.insert(make_pair(buddyID,vssReady->DSA));			

					NodeIDSize echo_threshold = 
						(NodeIDSize)ceil((sysparams.get_n() + sysparams.get_t() + 1.0)/2);
					//cout << "Current Echo and ready count is "<< it->second.getEchoMsgCnt()<<" "<<it->second.getReadyMsgCnt()<<endl;	 
					if((it->second.getEchoMsgCnt() < echo_threshold)&&(it->second.getReadyMsgCnt() == sysparams.get_t() + 1)){
						bool EchoOrReady = true;//EchoOrReady = Ready					
						vector<Zr> subshares = it->second.interpolate(sysparams, EchoOrReady, activeNodes);					
						if (commType == Feldman_Vector)	it->second.setSubshares(sysparams,subshares);
					
						msgLog << endl << endl << endl;
						msgLog << "============================================" << endl;
						msgLog << "*1ENOUGH VSS_READY message for " << selfID << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
						msgLog << "*Threshold : Ready = " << sysparams.get_t() + 1 << endl;
						msgLog << "*Received Ready Message Num = " << it->second.getReadyMsgCnt() << endl;
						msgLog << "*Ready messages are sending out..." << endl;
						msgLog << "============================================" << endl << endl;


						vector<NodeID>::iterator iter;//For the active nodes list					
						unsigned short index = 0;//Note that starting with zero as first the value is an evaluation at zero
						for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
							//if (*iter != selfID){
							++index;
							VSSReadyMessage vssReady(buddyset,it->first, ph, it->second, subshares[index]);	
							buddyset.send_message(*iter, vssReady);
							gettimeofday (&now, NULL);
							msgLog << "VSS_READY " << vssReady.get_ID() << " for " << vssReady.dealer << " SENT from " << selfID << " to " << *iter << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " standard 1" << endl;
						}
					} else if(it->second.getReadyMsgCnt() == sysparams.get_n() - sysparams.get_t() - sysparams.get_f()){
						//2t+f+1 = n-t-f ready messages received -> VSS Share is complete

						vector <NodeID> zero; //zero.push_back(0);Zero is anyways computed
						bool EchoOrReady = true;//EchoOrReady = Ready
						vector<Zr> subshare = it->second.interpolate(sysparams, EchoOrReady, zero);
						
						//Add the commitment and the subshare to final set C_final
						CommitmentAndShare mns; mns.C = it->second; mns.share = subshare[0];
						//Note that I might like to remove ECHO and READY shares from Matrix object
						C_final.insert(make_pair(it->first, mns));
						
						bool changed = false;
						if(NodeIDSize(vssReadyMsgSelected.size()) < sysparams.get_t() + 1) {
							changed = true;
							vssReadyMsgSelected.insert(make_pair(ready_it->first,ready_it->second));					
						}
					
						//Send Shared Message to the user interface
						UserSharedMessage sharedMsg(ph,it->first,it->second, subshare[0]);
						//msgLog<<"VSS with dealer "<<it->first<< " completed at "<<selfID<<"\n";
						msgLog << endl << endl << endl;
						msgLog << "*============================================" << endl;
						msgLog << "*2ENOUGH VSS_READY message for " << selfID << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
						msgLog << "*Threshold : Ready = " << sysparams.get_n() - sysparams.get_t() - sysparams.get_f() << endl;
						msgLog << "*Received Ready Message Num = " << it->second.getReadyMsgCnt() << endl;
						msgLog << "*VSS Share is complete for dealer " << it->first << endl;
						msgLog << "============================================" << endl << endl;
						//sharedMsg.dump(stdout,0);
						
						//Send Shared Message to the leader (Optimization: To make the leader fast)
						//If the node is not a leader or if leader has already choosen the dealings 
						//to be considered
					if (nodeState != AGREEMENT_COMPLETED) {					
						if(selfID != buddyset.get_leader() && nodeState != AGREEMENT_STARTED){
							VSSSharedMessage vssShared(ph, it->first,ready_it->first,ready_it->second);
							buddyset.send_message(buddyset.get_leader(), vssShared);
							gettimeofday (&now, NULL);
							msgLog << "VSS_SHARED " << vssShared.get_ID() << " for " << vssShared.dealer << " SENT from " << selfID << " to " << buddyset.get_leader() << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " standard 1" << endl;
						}
						//I am not erasing entries from C here to avoid false SEND messages for (it->first = vss->dealer) later
						//C.erase(it->first); //delete all for the same dealer from C
										
						if (((NodeIDSize)vssReadyMsgSelected.size() == sysparams.get_t() + 1)
							&&(nodeState != AGREEMENT_STARTED)&&(nodeState != LEADER_CHANGE_STARTED)) {
							if (changed) {
								startAgreement();
							}
						}
					} else completeDKG();					
				}
				}else {
				 msgLog<<"Invalid VSSReady Message received at "<<selfID<<" from "<<buddyID<<" for "<<vssReady->dealer<<endl;
				}
			}
		}
		break;
		case VSS_HELP:{
			//cerr << "VSS_HELP message from" << buddyID << " to " << selfID << endl;
			gettimeofday(&now, NULL);
			msgLog << "VSS_HELP * for * RECEIVED from " << buddyID << " to " << selfID << " at " << now.tv_sec << "." << setw(6) << now.tv_usec << endl;
			// TODO
			buddy->help(msgLog);
		}
		break;		
		case VSS_SHARED:{
			VSSSharedMessage *vssShared = static_cast<VSSSharedMessage*>(nm);
			//cerr << "VSS_SHARED for " << vssShared->dealer << " RECEIVED from " << buddyID << " to " << selfID << endl;
			gettimeofday(&now, NULL);
			msgLog << "VSS_SHARED " << vssShared->get_ID() << " for " << vssShared -> dealer << " RECEIVED from " << buddyID << " to " << selfID
					<< " at " << now.tv_sec << "." << setw(6) << now.tv_usec << endl;
			if (selfID == buddyset.get_leader()) {
			}
			//cerr<<"Shared Message received from "<<buddyID<<endl;
			if(ph > vssShared->ph) {
				//TODO: Actual system need not to display the following messages.
			  cerr<<"Phase for VSSShared "<<vssShared->ph<<" is older than the current phase "<<ph<<endl;				  
			} else if(ph < vssShared->ph) {
				//TODO: Messages from the future phase should be stored. 
				//Do it when I make decision about the recovery set B  
			} else if(((nodeState == LEADER_UNCONFIRMED)||(nodeState == FUNCTIONAL)||(nodeState == UNDER_RECOVERY))
					&&(vssShared->msgValid))
			//&&(selfID == buddyset.get_leader())
			{//The node has not sent the DKG_SEND yet. Set the Ready Messages to Set 'R'
				map <VSSReadyMessage, map <NodeID, string> >::iterator ready_it = vssReadyMsg.find(vssShared->readyMsg);
				if (ready_it == vssReadyMsg.end())//No entry for this dealer
					vssReadyMsg.insert(make_pair(vssShared->readyMsg,vssShared->msgDSAs));					
				else//Entry for this dealer exists. add the received ready messages 
					ready_it->second.insert(vssShared->msgDSAs.begin(), vssShared->msgDSAs.end());
				
				if(NodeIDSize(vssReadyMsgSelected.size()) < sysparams.get_t() + 1){
					ready_it = vssReadyMsgSelected.find(vssShared->readyMsg);
					if (ready_it == vssReadyMsgSelected.end())//No entry for this dealer
						vssReadyMsgSelected.insert(make_pair(vssShared->readyMsg,vssShared->msgDSAs));					
					else//Entry for this dealer exists. add the received ready messages 
						ready_it->second.insert(vssShared->msgDSAs.begin(), vssShared->msgDSAs.end());
					if (NodeIDSize(vssReadyMsgSelected.size()) == sysparams.get_t() + 1) {
						startAgreement();
					}
				}					 
			}
		} break;
		
		case DKG_SEND:{
			DKGSendMessage *dkgSend = static_cast<DKGSendMessage*>(nm);
			//cerr << "DKG_SEND RECEIVED from " << buddyID << " to " << selfID << endl;
			gettimeofday(&now, NULL);
			msgLog << "DKG_SEND " << dkgSend->get_ID() << " for * RECEIVED from " << buddyID << " to " << selfID  << " at " <<
									now.tv_sec << "." << setw(6) << now.tv_usec << endl;
			//msgLog<<"DKGSend Message received from "<<buddyID<<endl;
			if(ph > dkgSend->ph) {
				//TODO: Actual system need not to display the following messages.
				//cerr<<"Phase for DKGSend "<<dkgSend->ph<<" is older  than the current phase "<<ph<<endl;				  
			} else if(ph < dkgSend->ph){
				//TODO: Messages from the future phase should be stored. 
				//Do it when I make decision about the recovery set B  
			} else if((nodeState != AGREEMENT_COMPLETED)&&(nodeState != DKG_COMPLETED)){
				if (buddyID != buddyset.get_leader()){
				 //Send Messages from a current non-leader. I might be slow 
				 //Store it for the probable future leader
				 //Note that the signature might be wrong for now.
				 //Might be signed with key that is futuristic to me
				} else if((dkgSend->msgValid)&&(nodeState != LEADER_CHANGE_STARTED)){
				//a valid DKGSend by the current leader and for the current phase					
					set <NodeID> Q; //Set of Decided Nodes				
					if (dkgSend->msgType == VSS_READY){
						map <VSSReadyMessage, map <NodeID, string> >::const_iterator it;
						for(it = dkgSend->vssReadyMsg.begin(); it != dkgSend->vssReadyMsg.end(); ++it)
							Q.insert(it->first.dealer);					
					}else if ((dkgSend->msgType == DKG_ECHO)||(dkgSend->msgType == DKG_READY))						
						Q = dkgSend->dkgEchoOrReadyMsg.DecidedVSSs;					
					if (dkgReadyValidityMsg.DecidedVSSs.empty() ||(dkgReadyValidityMsg.DecidedVSSs == Q)){
						// Q is equivalent to Ready message sent during last leader 
						// or no leader sent during last leader, so accept the valid set from the leader and send Echo
						vector<NodeID>::iterator iter;//For the active nodes list
						for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
							//if (*iter != selfID){
							DKGEchoMessage dkgEcho(buddyset, buddyset.get_leader(), ph, Q);
							buddyset.send_message(*iter, dkgEcho);
							gettimeofday (&now, NULL);
							msgLog << "DKG_ECHO " << dkgEcho.get_ID() << " for " << dkgEcho.leader << " SENT from " << selfID << " to " << *iter << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " standard 1" << endl;
						}
					}				
				} //else //DKGsend is invalid, send LeaderChangeMessage
				 //	sendLeaderChangeMessage(buddyset.get_next_leader());
			}				
		}
		break;
		case DKG_ECHO:{
			DKGEchoMessage *dkgEcho = static_cast<DKGEchoMessage*>(nm);
			gettimeofday(&now, NULL);
			msgLog << "DKG_ECHO " << dkgEcho->get_ID() << " for " << dkgEcho ->leader << " RECEIVED from " << buddyID << " to " << selfID << " at " << now.tv_sec << "." << setw(6) << now.tv_usec << endl;
			if(ph > dkgEcho->ph) {
				//TODO: Actual system need not to display the following messages.
			  cerr<<"Phase for DKGEcho "<<dkgEcho->ph<<" is older than the current phase "<<ph<<endl;				  
			} else if(ph < dkgEcho->ph) {
				//TODO: Messages from the future phase should be stored. 
				//Do it when I make decision about the recovery set B		
			} else if((dkgEcho->msgValid)&&(nodeState != AGREEMENT_COMPLETED)&&(nodeState != DKG_COMPLETED)){
				//a valid DKGEcho by the current leader and for the current phase					
				
				DKGEchoMessage dkgEcho_SignRemoved = DKGEchoMessage(buddy, dkgEcho->strMsg);
				map <DKGEchoOrReadyMessage, map <NodeID, string> >::iterator
					echo_it = dkgEchoOrReadyMsgReceived.find(dkgEcho_SignRemoved);
				if(echo_it == dkgEchoOrReadyMsgReceived.end()){//No entry for this dealer
					map <NodeID, string> signature;
					signature.insert(make_pair(buddyID,dkgEcho->DSA));					
					echo_it = dkgEchoOrReadyMsgReceived.insert(make_pair(dkgEcho_SignRemoved,signature)).first;
				}else//Entry for this dealer exists. Add signer and signature pair
					echo_it->second.insert(make_pair(buddyID,dkgEcho->DSA));
				
				//Check the DSA count for the corresponding DKGReadyMessage
				string readyMsgStr = dkgEcho->strMsg;
				readyMsgStr.replace(0,1,1,DKG_READY);
				//Above operation changes the first byte of the message string to derive the
				//corresponding DKGReadyMessage
				DKGReadyMessage dkgReady_SignRemoved = DKGReadyMessage(buddy, readyMsgStr);
				map <DKGEchoOrReadyMessage, map <NodeID, string> >::iterator
						ready_it = dkgEchoOrReadyMsgReceived.find(dkgReady_SignRemoved);
				NodeIDSize dkgReadyCnt;							
				if(ready_it == dkgEchoOrReadyMsgReceived.end())	
					dkgReadyCnt = 0;
				else 
					dkgReadyCnt = ready_it->second.size();				
				//cerr<<"Current Echo count is "<<echo_it->second.size()<<endl;
				//cerr<<"Current Ready count is "<<dkgReadyCnt<<endl;
				NodeIDSize echo_threshold = (NodeIDSize)ceil((sysparams.get_n() + sysparams.get_t() + 1.0)/2);				 
				if(((NodeIDSize)echo_it->second.size() == echo_threshold) && ( dkgReadyCnt < sysparams.get_t() + 1)){
					//Make Q_bar and M_bar messages, while DKGReady is sent by me
					dkgReadyValidityMsg = dkgEcho_SignRemoved;
					dkgReadyValidityMsgDSAs = echo_it->second;

					msgLog << endl << endl << endl;
					msgLog << "============================================" << endl;
					msgLog << "*ENOUGH DKG_ECHO message for " << selfID << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
					msgLog << "*Threshold : Echo = " << echo_threshold << endl;
					msgLog << "*Received Echo Message Num = " << (NodeIDSize)echo_it->second.size() << endl;
					msgLog << "*DKG_Readys are sent out..." << endl;
					msgLog << "============================================" << endl << endl;

										
					vector<NodeID>::iterator iter;//For the active nodes list					
					for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
						//if (*iter != selfID){
						DKGReadyMessage dkgReady(buddyset, buddyset.get_leader(),ph,dkgEcho->DecidedVSSs);
						buddyset.send_message(*iter, dkgReady);	
						//cerr<<"DKGReady message is sent to Node "<<*iter<<".\n";
						gettimeofday (&now, NULL);
						msgLog << "DKG_READY " << dkgReady.get_ID() << " for " << dkgReady.leader << " SENT from " << selfID << " to " << *iter << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " standard 1" << endl;
					}
				}			
			}else if (!dkgEcho->msgValid) {
				gettimeofday(&now, NULL);
				msgLog<<"Invalid DKGEcho for " << dkgEcho ->leader << " from "<<buddyID<<" to " <<selfID << " RECEIVED at " << now.tv_sec << "." << setw(6) << now.tv_usec <<"\n";
			}
		}break;
		case DKG_READY:{
			DKGReadyMessage *dkgReady = static_cast<DKGReadyMessage*>(nm);
			gettimeofday(&now, NULL);
			msgLog << "DKG_READY " << dkgReady->get_ID() << " for " << dkgReady ->leader << " RECEIVED from " << buddyID << " to " << selfID << " at " <<
																	now.tv_sec << "." << setw(6) << now.tv_usec << endl;
			//cerr<<"DKGReady Message received from "<<buddyID<<endl;
			if(ph > dkgReady->ph) {
				//TODO: Actual system need not to display the following messages.
			  cerr<<"Phase for DKGReady "<<dkgReady->ph<<" is older than the current phase "<<ph<<endl;				  
			} else if(ph < dkgReady->ph) {
				//TODO: Messages from the future phase should be stored. 
				//Do it when I make decision about the recovery set B		
			} else if((dkgReady->msgValid)&&(nodeState != AGREEMENT_COMPLETED)&&(nodeState != DKG_COMPLETED)){
				//a valid DKGReady by the current leader and for the current phase	
				DKGReadyMessage dkgReady_SignRemoved = DKGReadyMessage(buddy, dkgReady->strMsg);
				map <DKGEchoOrReadyMessage, map <NodeID, string> >::iterator
								ready_it = dkgEchoOrReadyMsgReceived.find(dkgReady_SignRemoved);
				if(ready_it == dkgEchoOrReadyMsgReceived.end()){//No entry for this dealer
					map <NodeID, string> signature;
					signature.insert(make_pair(buddyID,dkgReady->DSA));
					ready_it = dkgEchoOrReadyMsgReceived.insert(make_pair(dkgReady_SignRemoved,signature)).first;
				}else//Entry for this dealer exists. Add signer and signature pair
					ready_it->second.insert(make_pair(buddyID,dkgReady->DSA));
				
				//Check the DSA count for the corresponding DKGEchoMessage
				string echoMsgStr =  (dkgReady->strMsg).replace(0,1,1,DKG_ECHO);
				//Above operation changes the first byte of the message string to derive the
				//corresponding DKGEchoMessage
				DKGEchoMessage dkgEcho_SignRemoved = DKGEchoMessage(buddy, echoMsgStr);
				map <DKGEchoOrReadyMessage, map <NodeID, string> >::iterator
						echo_it = dkgEchoOrReadyMsgReceived.find(dkgEcho_SignRemoved);
				NodeIDSize dkgEchoCnt;							
				if(echo_it == dkgEchoOrReadyMsgReceived.end())	
					dkgEchoCnt = 0;
				else 
					dkgEchoCnt = echo_it->second.size();				
					
				NodeIDSize echo_threshold = (NodeIDSize)ceil((sysparams.get_n() + sysparams.get_t() + 1.0)/2);
				//cout << "READY_IT " << (NodeIDSize)ready_it->second.size() << endl;
				if((dkgEchoCnt < echo_threshold) && ((NodeIDSize)ready_it->second.size() == sysparams.get_t() + 1)){
					//Make Q_bar and M_bar messages, while DKGReady is sent by me
					dkgReadyValidityMsg = dkgReady_SignRemoved;
					dkgReadyValidityMsgDSAs = ready_it->second;

					msgLog << endl << endl << endl;
					msgLog << "============================================" << endl;
					msgLog << "*1ENOUGH DKG_READY message for " << selfID << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
					msgLog << "*Threshold : Ready = " << sysparams.get_t() + 1 << endl;
					msgLog << "*Received Ready Message Num = " << (NodeIDSize)ready_it->second.size() << endl;
					msgLog << "*DKG_Readys are sent out..." << endl;
					msgLog << "============================================" << endl << endl;


					vector<NodeID>::iterator iter;//For the active nodes list					
					for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
						//if (*iter != selfID){
						DKGReadyMessage dkgReadySent(buddyset, buddyset.get_leader(),ph,dkgReady->DecidedVSSs);
						buddyset.send_message(*iter, dkgReadySent);	
						gettimeofday (&now, NULL);
						msgLog << "DKG_READY " << dkgReadySent.get_ID() << " for " << dkgReadySent.leader << " SENT from " << selfID <<
											" to " << *iter << " at " <<  now.tv_sec << "." << setw(6) <<
											now.tv_usec << " standard 1" << endl;
					}									
				}else if((NodeIDSize)ready_it->second.size() == sysparams.get_n() - sysparams.get_t() - sysparams.get_f()){
					//Stop timer, if any
					if (leaderChangeTimerID){
						Timer::cancel(leaderChangeTimerID);
						leaderChangeTimerID = 0;
					}

					msgLog << endl << endl << endl;
					msgLog << "============================================" << endl;
					msgLog << "*2ENOUGH DKG_READY message for " << selfID << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
					msgLog << "*Threshold : Ready = " << sysparams.get_n() - sysparams.get_t() - sysparams.get_f() << endl;
					msgLog << "*Received Ready Message Num = " << (NodeIDSize)ready_it->second.size() << endl;
					msgLog << "============================================" << endl << endl;

					//Proceed with VSS for only the agreed dealers and compute the share
					DecidedVSSs = dkgReady->DecidedVSSs;
					//sort(DecidedVSSs.begin(),DecidedVSSs.end());
					//cout << "COMPLETE!!! for node " << selfID << " at " << now.tv_sec << "." << setw(6) << now.tv_usec << endl;
					completeDKG(); 
				}
			}else if (!dkgReady->msgValid) {
				gettimeofday(&now, NULL);
				msgLog<<"Invalid DKGReady for " << dkgReady->leader << " from "<<buddyID<<" to "<<selfID
				<< " at " << now.tv_sec << "." << setw(6) << now.tv_usec <<"\n";
			}
		}
		break; 
		case DKG_HELP:{
			gettimeofday(&now, NULL);
			msgLog << "DKG_HELP * for * RECEIVED from " << buddyID << " to " << selfID << " at " <<
								now.tv_sec << "." << setw(6) << now.tv_usec << endl;
			//cerr << "DKG_HELP from" << buddyID << " to " << selfID << endl;
		}
		break;
		case LEADER_CHANGE:{
			LeaderChangeMessage *leaderChange = static_cast<LeaderChangeMessage*>(nm);
			gettimeofday(&now, NULL);
			msgLog << "LEADER_CHANGE " << leaderChange->get_ID() << " for " << leaderChange ->nextLeader << " RECEIVED from " << buddyID << " to " << selfID << " at " << now.tv_sec << "." << setw(6) << now.tv_usec << endl;
			if(ph > leaderChange->ph) {
				//TODO: Actual system need not to display the following messages.
			  cerr<<"Phase for LeaderChange "<<leaderChange->ph<<" is older than the current phase "<<ph<<endl;				  
			} else if(ph < leaderChange->ph) {
				//TODO: Messages from the future phase should be stored. 
				//Do it when I make decision about the recovery set B
			} else if((leaderChange->msgValid)&&(nodeState!=DKG_COMPLETED)&&(nodeState!=AGREEMENT_COMPLETED)){
				if(leaderChange->nextLeader!=buddyset.get_leader()){
					if ((leaderChange->nextLeader + sysparams.get_n() - buddyset.get_leader()) 
						% sysparams.get_n() > sysparams.get_t() + sysparams.get_f()) {
						msgLog << "* LeaderChange index out of range" << endl;
						break;
					}
					++validLeaderChangeMsgCnt;	
					LeaderChangeMessage leaderChange_SignRemoved(buddy,leaderChange->strMsg);
					map<LeaderChangeMessage, map <NodeID, string> >::iterator it = leaderChangeMsg.find(leaderChange_SignRemoved);
					if (it == leaderChangeMsg.end()){
						map <NodeID, string> signature;
						signature.insert(make_pair(buddyID,leaderChange->DSA));
						it = leaderChangeMsg.insert(make_pair(leaderChange_SignRemoved, signature)).first;
					} else
						it->second.insert(make_pair(buddyID,leaderChange->DSA));
			
					//L++ = min (L++, L received)
					NodeID index_L, index_received, index_smallest;
					for(NodeID index = 0; index < activeNodes.size(); ++index)
						if(activeNodes[index] == buddyset.get_leader()){index_L = index; break;}
					for(NodeID index = 0; index < activeNodes.size(); ++index)									
						if(activeNodes[index] == leaderChange->nextLeader) {index_received = index; break;}
					for(NodeID index = 0; index < activeNodes.size(); ++index)
						if(activeNodes[index] == nextSmallestLeader) {index_smallest = index; break;}
					//cerr<<"index_L, index_received, index_smallest resp. are "<<index_L <<" "<< index_received<<" "<< index_smallest<<endl;				
					if(((index_smallest < index_L)&&(index_L < index_received))||
						((index_received < index_smallest)&&(index_smallest < index_L))||
						((index_L < index_received)&&(index_received < index_smallest)))
							nextSmallestLeader = activeNodes[index_received];					
					
					//Add Q, R/M to Q_cap R_cap or Q_bar and M_bar
					if (leaderChange->msgType == VSS_READY)
					{// Add Q, R/M to Q_cap R_cap
						map <VSSReadyMessage, map <NodeID, string> >::iterator it_received;
						map <VSSReadyMessage, map <NodeID, string> >::iterator it;
						for(it_received = leaderChange->vssReadyMsg.begin(); it_received != leaderChange->vssReadyMsg.end(); ++it_received){
							//Copy to  vssReadyMsg
							it = vssReadyMsg.find(it_received->first);
							if (it == vssReadyMsg.end())//No entry for this dealer in local vssReadyMsg
								it = vssReadyMsg.insert(make_pair(it_received->first,it_received->second)).first;
							else//Entry for this dealer exists. add the received ready messages 
								it->second.insert(it_received->second.begin(), it_received->second.end());
							//Copy to vssReadyMsgSelected
							if (NodeIDSize(vssReadyMsgSelected.size()) < sysparams.get_t() + 1){
								it = vssReadyMsgSelected.find(it_received->first);
								if (it == vssReadyMsgSelected.end())//No entry for this dealer in local vssReadyMsg
									it = vssReadyMsgSelected.insert(make_pair(it_received->first,it_received->second)).first;
								else//Entry for this dealer exists. add the received ready messages 
									it->second.insert(it_received->second.begin(), it_received->second.end());								
							}
						}
					}else {
						dkgReadyValidityMsg = leaderChange->dkgEchoOrReadyMsg;
						dkgReadyValidityMsgDSAs.clear();
						dkgReadyValidityMsgDSAs = leaderChange->dkgEchoOrReadyMsgDSAs;
					}				
					if((validLeaderChangeMsgCnt >= size_t(sysparams.get_t() + 1))&&(nodeState != LEADER_CHANGE_STARTED)) {
						// LeaderChange message is not yet sent. There are t+1 requests   
						sendLeaderChangeMessage(nextSmallestLeader);			
					}
					else if(NodeIDSize(it->second.size()) == sysparams.get_n() - sysparams.get_t() - sysparams.get_f()){
						//Optimistic step is starting again					
						//Remove leaderchange message sent for the current (one to be removed) leader
						LeaderChangeMessage lc_tobe_removed = leaderChange_SignRemoved; 
						lc_tobe_removed.nextLeader = buddyset.get_leader();
						leaderChangeMsg.erase(lc_tobe_removed);						
						buddyset.set_leader(leaderChange->nextLeader);//Set the received leader as new leader
						gettimeofday (&now, NULL);
						msgLog<<"NEW_LEADER * : "<<leaderChange->nextLeader<< " NL from * to * at " << now.tv_sec << "." << setw(6) << now.tv_usec <<endl;
						validLeaderChangeMsgCnt-= sysparams.get_n() - sysparams.get_t() - sysparams.get_f(); //remove count (n-t-f) for the next leader
						nextSmallestLeader = buddyset.get_previous_leader();//Set new smallest Leader
						nodeState = FUNCTIONAL; //nodeState is no longer Leader_Change_Started
						startAgreement();
					}
				} else if((nodeState == LEADER_UNCONFIRMED)&& (buddyset.get_leader() ==selfID)){
					//DKG is just started. This is a message for the leader to collect required leaderchange certificate
					// Node
					//LeaderChange check + Check if the VSSs completed and start DKG then
					LeaderChangeMessage leaderChange_SignRemoved(buddy,leaderChange->strMsg);
					map<LeaderChangeMessage, map <NodeID, string> >::iterator it = leaderChangeMsg.find(leaderChange_SignRemoved);
					if (it == leaderChangeMsg.end()){
						map <NodeID, string> signature;
						signature.insert(make_pair(buddyID,leaderChange->DSA));
						it = leaderChangeMsg.insert(make_pair(leaderChange_SignRemoved, signature)).first;
					} else
						it->second.insert(make_pair(buddyID,leaderChange->DSA));
						
					if(NodeIDSize(it->second.size()) == sysparams.get_n() - sysparams.get_t() - sysparams.get_f()){
						//First Optimistic step is starting					
						nextSmallestLeader = buddyset.get_previous_leader();//Set new smallest Leader
						gettimeofday (&now, NULL);
						msgLog<<"E_LEADER_CONFIRM * for "<< selfID << " RS from * to * at " << now.tv_sec
							<< "."	<< setw(6) << now.tv_usec << endl;
						nodeState = FUNCTIONAL; //nodeState is no longer Leader_Change_Started
						if (NodeIDSize(vssReadyMsgSelected.size()) == sysparams.get_t() + 1) {
						//if (NodeIDSize(vssReadyMsgSelected.size()) >= sysparams.get_t() + 1)
						// ANDY: I am not sure whether this is a bug or not
							startAgreement();
						}
					}					
				}// else cerr<<"Invalid LeaderChange Message (2) received from "<<buddyID<<endl;
		    }//else cerr<<"Invalid LeaderChange Message (1) received from "<<buddyID<<endl;
		}
		break;
		case RECONSTRUCT_SHARE:{
			cerr << "RECONSTRUCT_SHARE message from" << buddyID << " to " << selfID << endl;
		}
		break;
		case PUBLIC_KEY_EXCHANGE:{
				cerr << "PUBLIC_KEY_EXCHANGE message from" << buddyID
							<< " to " << selfID << endl;
				PublicKeyExchangeMessage *pubkeymsg = static_cast<PublicKeyExchangeMessage*>(nm);
				clientPublicKeys.erase(buddyID);//delete old key, if any
				clientPublicKeys.insert(make_pair(buddyID,pubkeymsg->publicKey));
				G1 quorumPublicKey;		
				if (result.C.get_Type() == Feldman_Matrix){
					CommitmentMatrix matrix = result.C.get_Matrix();
					quorumPublicKey = matrix.getEntry(0,0);
				}else{
					CommitmentVector vector = result.C.get_Vector();
					quorumPublicKey = vector.getShare(0);
				}	
				PublicKeyExchangeMessage pubkeySend(buddyset,quorumPublicKey);
				buddyset.send_message(buddyID,pubkeySend);
				//cerr<<"Public Key is sent to client "<<buddyID<<endl;
		}
		break;
		case BLS_SIGNATURE_REQUEST:
		{ 
			cerr << "BLS_SIGNATURE_REQUEST message from" <<
					buddyID << " to " << selfID << endl;
		 	BLSSignatureRequestMessage *signatureRequest = static_cast<BLSSignatureRequestMessage*>(nm);
			//cerr << "BLS_SIGNATURE_REQUEST received RECEIVED from " << buddyID<<endl;
			if(ph > signatureRequest->ph) {
				//TODO: Actual system need not to display the following messages.
			  cerr<<"Phase for BLS_SIGNATURE_REQUEST"<<signatureRequest->ph<<" is older than the current phase "<<ph<<endl;
			} else {
				//In practice it is required to check the state of the node.
				//If it has not yet completed the DKG, then it should send appropriate messages to the client
				//A node should also check the message before signing
				const Pairing& e = sysparams.get_Pairing();
				G1 msgHashG1, signatureShare;
				hash_msg(msgHashG1, signatureRequest->msg,e);				
				if(e(sysparams.get_U(),signatureRequest->signature) == e(clientPublicKeys[buddyID],msgHashG1)){
					signatureShare = msgHashG1^result.share;
		  			BLSSignatureResponseMessage response(buddyset,ph,msgHashG1,signatureShare);
		  			buddyset.send_message(buddyID,response);
				}//else cerr<<"Client siganture is incorrect.\n";				
		  	}
		}
		break;
		case WRONG_BLS_SIGNATURES:
		{
			cerr << "WRONG_BLS_SIGNATURES message from" << buddyID << endl;
			WrongBLSSignaturesMessage *wrongSignatures = static_cast<WrongBLSSignaturesMessage*>(nm);
			//cerr << "WRONG_BLS_SIGNATURES received RECEIVED from " << buddyID<<endl;
			if(ph > wrongSignatures->ph) {
				//TODO: Actual system need not to display the following messages.
			  cerr<<"Phase for WRONG_BLS_SIGNATURES"<< wrongSignatures->ph<<" is older than the current phase "<<ph<<endl;
			} else {
				const Pairing& e = sysparams.get_Pairing();
				map <NodeID, G1> correctSignatures;
				for(map <NodeID, G1>::iterator iter = wrongSignatures->signatures.begin(); iter != wrongSignatures->signatures.end(); ++iter){
					G1 pubKeyShare = result.C.publicKeyShare(sysparams,iter->first);
					if(e(sysparams.get_U(),iter->second) == e(pubKeyShare,wrongSignatures->msgHash))
						correctSignatures.insert(make_pair(iter->first,iter->second));
				}
				VerifiedBLSSignaturesMessage verifiedSign(buddyset,ph,wrongSignatures->msgHash,correctSignatures);
		  		buddyset.send_message(buddyID,verifiedSign);
			}			
		}
		break;		
		default:{
			cerr << "Unknown network message received\n"<<nm->get_message_type();
		}
		break;
		}
		
	  }
	  break;
  	case TIMER:{
	    TimerMessage *tm = static_cast<TimerMessage*>(m);
	    switch(tm->get_type()) {
		case TIMER_MSG_LEADER_CHANGE:{
			//LeaderChangeTimerMessage *lctm = static_cast<LeaderChangeTimerMessage*>(tm);
			//buddyset.get_next_leader();
			
			// If the TIMEOUT event is triggered by the most recent timer
			//if (leaderChangeTimerID == tm->get_ID()) {
				gettimeofday(&now, NULL);
				msgLog << "TIMEOUT " << tm->get_ID() << " for " << buddyset.get_leader() << " RECEIVED from " << selfID << " to " << buddyset.get_next_leader() << " at " << now.tv_sec << "." << setw(6) << now.tv_usec << endl;
				sendLeaderChangeMessage(buddyset.get_next_leader());
			//}
		}break;
		case TIMER_MSG_PHASE_CHANGE:{
			//PhaseChangeTimerMessage *pctm = static_cast<PhaseChangeTimerMessage*>(tm);
			changePhase();
		}break;
		default:{
			  cerr<<"Unknown timer message received "<<tm->get_type() << endl;
		}break;
	    }		
  	  }break;
  	}
  	delete m;
  	//cerr<<endl;  	
  }//Check with Ian about the return value
  return 1;
}

void Node::hybridVSSInit(const Zr& secret){

  	//const Pairing& e = sysparams.get_Pairing();
  	unsigned short t = sysparams.get_t();

	timeval now;
	
  	gettimeofday (&now, NULL);
  	msgLog << "COMPUTE_BI * for * RS from " << selfID << " to * at " << now.tv_sec <<
  			"." << setw(6) << now.tv_usec << endl;
	BiPolynomial fxy(sysparams, t, secret);

	gettimeofday (&now, NULL);
	msgLog << "COMPUTE_CM * for * RS from " << selfID << " to * at " << now.tv_sec <<
	  			"." << setw(6) << now.tv_usec << endl;

  	Commitment C(sysparams,activeNodes, fxy, commType);

  //sending send messages
  vector<NodeID>::iterator iter;
  //cerr << "Sending sharing secret" << endl;
  for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
  	Zr nodeZr = Zr(sysparams.get_Pairing(),(long int)*iter);
	Polynomial a = fxy(nodeZr);
	//if (*iter != selfID){
	//a.dump(stderr,"Poly to be send");
	VSSSendMessage vssSend(ph,C,a);
	buddyset.send_message(*iter, vssSend);

	gettimeofday (&now, NULL);
	msgLog << "VSS_SEND " << vssSend.get_ID() << " for " << "* SENT from " << selfID <<
			" to " << *iter << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec
			<< " standard 1" << endl;

  }					
	//  cerr << endl << endl;
}

void Node::startAgreement(){
	//Perform DKG Send related activies	
	timeval now;
	if(selfID == buddyset.get_leader() && selfID > non_responsive_leader_number){//The node is the current leader

		if (leaderChangeTimerID){
			timeoutLog << endl << "deleting the previous timer: " << leaderChangeTimerID << endl;
			Timer::cancel(leaderChangeTimerID);
			leaderChangeTimerID = 0;
		}

		if(nodeState == LEADER_UNCONFIRMED){ 
			//I am the current; but I am not confirmed yet;
			//Being and Optimistic Leader, I am not sending send leaderchange for the next leader
			//sendLeaderChangeMessage(buddyset.get_next_leader());
			return;
		}
		//sending DKGSend messages

		msgLog << endl << endl << endl;
		msgLog << "============================================" << endl;
		msgLog << "*Leader has started Agreement\n";
		msgLog << "*ENOUGH VSS_READY message for " << selfID << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << endl;
		msgLog << "*Threshold : Ready = " << sysparams.get_t() + 1 << endl;
		//msgLog << "Received Ready Message Num = " << it->second.getReadyMsgCnt() << endl;
		msgLog << "*Ready messages are sending out..." << endl;
		msgLog << "============================================" << endl << endl;

		map <LeaderChangeMessage, map<NodeID, string> >::const_iterator it_leadchg;
		for(it_leadchg = leaderChangeMsg.begin(); it_leadchg != leaderChangeMsg.end();++it_leadchg)
			if ((it_leadchg->first.nextLeader == buddyset.get_leader())&&
				((NodeIDSize)it_leadchg->second.size()>= sysparams.get_n() - sysparams.get_t() - sysparams.get_f())) 
				{/*lc_present =true; */break;}
		
			
		if (dkgReadyValidityMsgDSAs.size()){//DKGEcho or DKGReady are from the previous leader are used
			for(vector<NodeID>::iterator iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
				//if (*iter != selfID){
				DKGSendMessage dkgSend(ph,it_leadchg->first ,it_leadchg->second, (NetworkMessageType)dkgReadyValidityMsg.strMsg[0],
										dkgReadyValidityMsg, dkgReadyValidityMsgDSAs);
				buddyset.send_message(*iter, dkgSend);	
				gettimeofday (&now, NULL);
				msgLog << "DKG_SEND " << dkgSend.get_ID() << " for " << "* SENT from " << selfID <<
						" to " << *iter << " at " <<  now.tv_sec << "." << setw(6) <<
						now.tv_usec << " standard 1" << endl;
			}		 	
		} else{//VSSReady are used
		 	for(vector<NodeID>::iterator iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
				//if (*iter != selfID){
				DKGSendMessage dkgSend(ph, it_leadchg->first ,it_leadchg->second, vssReadyMsgSelected);
				buddyset.send_message(*iter, dkgSend);
				gettimeofday (&now, NULL);
				msgLog << "DKG_SEND " << dkgSend.get_ID() <<  " for " << "* SENT from " << selfID <<
						" to " << *iter << " at " <<  now.tv_sec << "." << setw(6) <<
						now.tv_usec << " standard 1" << endl;
			}
  		}
		nodeState = AGREEMENT_STARTED;
		 
	} else{ //The node is not the current leader
		if (leaderChangeTimerID){
			timeoutLog << endl << "deleting the previous timer: " << leaderChangeTimerID << endl;
			Timer::cancel(leaderChangeTimerID);
			leaderChangeTimerID = 0;
		}
	       	unsigned int time_diff = get_time_diff((buddyset.get_param().get_t()), incremental_change);
		gettimeofday (&now, NULL);
		timeoutLog << endl << "time_diff from node# " << selfID << " is " << time_diff << " ms @ " <<
			now.tv_sec << "." << setw(6) << now.tv_usec << endl;
		leaderChangeTimerID = Timer::new_timer(new LeaderChangeTimerMessage
	       		(buddyset.get_next_leader(),ph),time_diff);
		timeoutLog << "ID = " << leaderChangeTimerID << endl << endl;
	}
	//nodeState = AGREEMENT_STARTED;
}


void Node::completeDKG(){
	timeval now;
	//Subset of C_final for NodeIDs in DecidedVSSs
	map<NodeID, CommitmentAndShare> DecidedValues;
	//Note that it is possible delete entries from C_final map.
	//But, I am avoiding that as STL's erase with iterator in a loop is buggy
	
	//DecidedVSSs broadcast is now completed. DKG will now eventually complete for sure.
	nodeState = AGREEMENT_COMPLETED;
	
	//check if all VSSs in DecidedVSS are completed or not
	map<NodeID, CommitmentAndShare>::const_iterator it  = C_final.begin();
	bool VSSsCompleted = false;
	for(set <NodeID>::iterator set_it = DecidedVSSs.begin();;){				
		while((*set_it > it->first)&& (it != C_final.end()))	++it;
		//If at least one require VSS is not yet completed or it ends then get out of loop
		if ((*set_it < it->first)||(it == C_final.end())) break;
		
		// Match found; Add the corresponding Matrix and Share to the DecidedValues map
		DecidedValues.insert(make_pair(it->first, it->second));		
		if ( ++set_it == DecidedVSSs.end()) {
		//Match found for every NodeId in DecidedVSSs; All VSSs completed
			VSSsCompleted = true;			
			break;
		}
	}
	if (!VSSsCompleted) {cerr<<"All VSS not yet complete\n";return;} //All required VSSs are not yet completed	 

	for(it = DecidedValues.begin(); it != DecidedValues.end(); ++it){
		result.C*= it->second.C;
		result.share+= it->second.share;
	}
	DKGCompleteMessage dkgCompleteMsg(ph, buddyset.get_leader(), DecidedVSSs, result.C, result.share);
	//dkgCompleteMsg.dump(stderr);
	gettimeofday (&now, NULL);
	msgLog<<"DKG_COMPLETE * for "<<buddyset.get_leader() << " RS from " << selfID << " to * at "
			<< now.tv_sec << "." << setw(6) << now.tv_usec << " :)" <<endl;
	cout<<"DKG_COMPLETE * for " <<buddyset.get_leader()<< " RS from " << selfID << " to * at "
				<< now.tv_sec << "." << setw(6) << now.tv_usec << " :)" <<endl;
	//DecidedVSSs broadcast and decided VSSs are now completed
	nodeState = DKG_COMPLETED;
	//fstream logFStream("dkg.log",ios::out); logFStream <<selfID<<" "<<buddyset.get_leader()<<" ";logFStream.close();
	// Get performance measurements
	measure_now();
	msgLog.close();	
}

void Node::sendLeaderChangeMessage(NodeID nextLeader){
	timeval now;
	
	if ((nodeState != LEADER_CHANGE_STARTED)&&(nodeState != DKG_COMPLETED)){
		//sending LeaderChange messages
		vector<NodeID>::iterator iter; 
		if (dkgReadyValidityMsgDSAs.size()){
			for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
				//if (*iter != selfID){
				LeaderChangeMessage leadChg = LeaderChangeMessage(buddyset,ph, nextLeader, (NetworkMessageType)dkgReadyValidityMsg.strMsg[0], dkgReadyValidityMsg,dkgReadyValidityMsgDSAs);
				buddyset.send_message(*iter, leadChg);
				gettimeofday (&now, NULL);
				msgLog << "LEADER_CHANGE " << leadChg.get_ID() << " for " << nextLeader << " SENT from " << selfID << " to " << *iter << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " standard 1" << endl;
  			}		 	
		 } else{ 
			for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
				//if (*iter != selfID){
				LeaderChangeMessage leadChg = LeaderChangeMessage(buddyset,ph, nextLeader, vssReadyMsgSelected);
				buddyset.send_message(*iter, leadChg);
				gettimeofday (&now, NULL);
				msgLog << "LEADER_CHANGE " << leadChg.get_ID() << " for " << nextLeader << " SENT from " << selfID << " to " << *iter << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " standard 1" << endl;
			}
  		}
  		nodeState = LEADER_CHANGE_STARTED;
	}
}

void Node::changePhase(){
	
}

int main(int argc, char **argv)
{
  Message::init_ctr();

  Phase ph;
  if (argc != 8) {
	cerr << "Usage: " << argv[0] <<" portnum certfile keyfile contactlist phase CommitmentType[0/1] non_responsive_leader_number\n";
	exit(1);
  }
  in_port_t portnum = atoi(argv[1]);
  const char *certfile = argv[2];
  const char *keyfile = argv[3];
  const char *contactlist = argv[4];

  ph = atoi(argv[5]);
  CommitmentType type = (CommitmentType)atoi(argv[6]);

  int non_responsive_leader_number = atoi(argv[7]);

  gnutls_global_init();
  Node node("pairing.param", "system.param", INADDR_ANY, portnum, 
			certfile, keyfile, contactlist, ph, type, non_responsive_leader_number);
  return node.run();
}
