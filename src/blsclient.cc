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
#include "buddyset.h"
#include "exceptions.h"
#include "lagrange.h"

class BLSClient : public Application {
public:
    BLSClient(const char *pairingfile, const char *sysparamfile, const char *certfile, 
	    const char *keyfile, const char *contactlistfile, Phase ph):
	Application(BLS_CLIENT, pairingfile, sysparamfile, 0, 0, certfile, keyfile, contactlistfile, ph),
	msgLog("message.log",ios::out)
    {
    //Generate a random public/pivate key pair
    	clientPrivateKey = Zr(sysparams.get_Pairing(),true);
    	clientPublicKey = sysparams.get_U()^clientPrivateKey;
    	validSignature = false;
    }

    int run();
private:
  string strID;
  Zr clientPrivateKey;
  G1 clientPublicKey;
  G1 quorumPublicKey;
  G1 DKGPublicKey;
  map <NodeID, G1> signatureShares;
  G1 signature;
  bool validSignature;
  string msg;// Signature message
  G1 msgHashG1; //Message hash
  //map<unsigned int, KeyShares> sharesmap;  // Map from phase to KeyShares  
  	fstream msgLog;
};

int BLSClient::run()
{
 //sleep (10);
 //cerr<<"Starting a Client\n";	
	//Exchange the public key with the quorum
	
	
  PublicKeyExchangeMessage pubkeymsg(buddyset, clientPublicKey);
  vector<NodeID>::iterator iter;//For the active nodes list		
	for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
		buddyset.send_message(*iter, pubkeymsg);
		//cerr<<"Public Key is sent to Node "<<*iter<<endl;
	}
	
  while(1) {
 	NodeID buddyID = 0;//0 for timer and user messages
	Message *m = get_next_message(buddyID, 0);

	switch(m->get_class()) {
	    case USER:
		{
		    UserMessage *um = static_cast<UserMessage*>(m);
		    switch(um->get_type()) {
			case USER_MSG_PING:{
				PingUserMessage *pum = static_cast<PingUserMessage*>(um);
				cerr << "Pinging " << pum->get_who() << "\n";
				PingNetworkMessage pnm(buddyset, time(0));
				buddyset.send_message(pum->get_who(), pnm);
			}
			    break;
			case SIGN: {				
				
				BLSSignatureRequestUserMessage *sign = static_cast<BLSSignatureRequestUserMessage*>(um);
				msg = sign->msg;
				write_ui(msg,time(NULL));
				hash_msg(msgHashG1,msg,sysparams.get_Pairing());
				G1 mySignature = msgHashG1^clientPrivateKey;
				//cerr<<"Message is"<<msg<<endl;
				BLSSignatureRequestMessage signRequest(buddyset, ph, msg,mySignature);
				signatureShares.clear(); validSignature = false;		
				vector<NodeID>::const_iterator iter;//For the active nodes list					
				for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
					buddyset.send_message(*iter, signRequest);
				}
							
			} 
			default:
			    {
				cerr << "Unknown user command\n";
			    }
			    break;
		    }
		}
		break;
	    case NETWORK:
		{
		    NetworkMessage *nm = static_cast<NetworkMessage*>(m);
		    //const Buddy *buddy = buddyset.find_buddy_id(buddyID);
		    switch(nm->get_message_type()) {
			case NET_MSG_PING:
			{
				PingNetworkMessage *pnm = static_cast<PingNetworkMessage*>(nm);
				cerr << "Received ping from id " << buddyID <<", timestamp = " << pnm->t << "\n";
			}
			break;	break;
			case PUBLIC_KEY_EXCHANGE:
			{
				PublicKeyExchangeMessage *pubkeymsg = static_cast<PublicKeyExchangeMessage*>(nm);
				//cerr << "Received Public Key from " << buddyID <<endl;
				quorumPublicKey = pubkeymsg->publicKey;
						
			}
			break;
			case BLS_SIGNATURE_RESPONSE:
			{
				BLSSignatureResponseMessage *signResponse = static_cast<BLSSignatureResponseMessage*>(nm);
				if (buddyID == 2 || buddyID == 3 || buddyID == 5 || buddyID == 8 || buddyID == 17 || buddyID == 24 || buddyID == 35|| buddyID == 32 || buddyID == 33 || buddyID == 37 || buddyID == 38 || buddyID == 28 || buddyID == 30||  	buddyID == 4 || buddyID == 6 || buddyID == 7 || buddyID == 9 || buddyID == 10 || buddyID == 11 || buddyID == 12 || buddyID == 13 || buddyID == 18 || buddyID == 20 || buddyID == 21 || buddyID == 22 || buddyID == 23 || buddyID == 27 || buddyID == 29 || buddyID ==31 || buddyID == 34 || buddyID == 36 || buddyID == 40)
					continue;
				cerr << "Received BLS Siganture share from " << buddyID <<endl;
				if(ph > signResponse->ph) {
					//TODO: Actual system need not to display the following messages.
			  		cerr<<"Phase for  BLS signature response message"<<signResponse->ph<<" is older than the current phase "<<ph<<endl;		  
				} else if(ph < signResponse->ph) {
					//TODO: Actual system need not to display the following messages.
			  		cerr<<"Phase for  BLS signature response message"<<signResponse->ph<<" is newerolder than the current phase "<<ph<<endl;							 
				} else {					
					signatureShares.insert(make_pair(buddyID, signResponse->signatureShare));
					if (((NodeID)signatureShares.size() == 2 * sysparams.get_t() + 1) && !signature.isElementPresent()){
					    // We can now construct the signature
					    //cerr << "Constructing the Signature\n";					    				    
					    //Make an array of the indices and shares;
						vector <Zr> indices; vector <G1> shares;
						const Pairing& e = sysparams.get_Pairing();
						for(map<NodeID, G1>::const_iterator it = signatureShares.begin();
							 it != signatureShares.end(); ++it){						
							indices.push_back(Zr(e,(signed long)it->first));
							shares.push_back(it->second);
						}						
						//pushing evaluation at zero
						Zr alpha(e,(long)0);
						vector<Zr> coeffs = lagrange_coeffs(indices, alpha);
						G1 tempSignature = lagrange_apply(coeffs, shares);
						measure_init();
						if(e(sysparams.get_U(),tempSignature) == e(quorumPublicKey,msgHashG1)){
						  cerr << "\n*** CORRECT!\n\n";						  
						} else {						
						  cerr << "\n*** DIFFERENT!\n\n";
						  //Send a Wrong Signatures Message						  
					    }
					    measure_now();
					    //Code Testing: Send Wronfg Signature Message Anyways
						WrongBLSSignaturesMessage wrongSignatures(buddyset,ph,msgHashG1,signatureShares);
						vector<NodeID>::iterator iter;//For the active nodes list		
						for(iter = activeNodes.begin();iter != activeNodes.end(); ++iter){
							buddyset.send_message(*iter, wrongSignatures);
							//cerr<<"WrongBLSSignatures message is sent to "<<*iter<<endl;
						}	    
					}
				}
			} 
			break;
			case VERIFIED_BLS_SIGNATURES:{
					if(validSignature) break;
					VerifiedBLSSignaturesMessage* verifiedSign = static_cast<VerifiedBLSSignaturesMessage*>(nm);
					//cerr << "VerifiedBLSSignaturesMessage from " << buddyID <<endl;
					//pushing evaluation at zero
					vector <Zr> indices; vector <G1> shares;
					const Pairing& e = sysparams.get_Pairing();
					for(map<NodeID, G1>::const_iterator it = verifiedSign->signatures.begin();
						it != verifiedSign->signatures.end(); ++it){						
						indices.push_back(Zr(e,(signed long)it->first));
						shares.push_back(it->second);
					}
					//Zr alpha(e,(long)0);
					//vector<Zr> coeffs = lagrange_coeffs(indices, alpha);
					//G1 tempSignature = lagrange_apply(coeffs, shares);
					//if(e(sysparams.get_U(),tempSignature) == e(quorumPublicKey,msgHashG1))
					validSignature = true;				
			}
			break;
			default:
			    {
				cerr << "Unknown network message received\n";
			    }
			    break;
		    }
		}
		break;
	}

	delete m;
    }
}

int main(int argc, char **argv)
{
    Phase ph;
    if (argc != 5) {
	cerr << "Usage: " << argv[0] <<
	    "certfile keyfile contactlist phase\n";
	exit(1);
    }  
    //in_port_t portnum = atoi(argv[1]);
    const char *certfile = argv[1];
    const char *keyfile = argv[2];
    const char *contactlist = argv[3];
  	ph = atoi(argv[4]);
	cout<<"Input the System Phase"<<endl;
	cin>>ph;

    gnutls_global_init();

    BLSClient client("pairing.param", "system.param", certfile, keyfile, contactlist,ph);
    return client.run();
}
