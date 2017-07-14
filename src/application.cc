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



#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <iomanip>
#include "application.h"
#include "usermessage.h"
#include "networkmessage.h"
#include "buddyset.h"
#include "exceptions.h"
#include "timer.h"
#include <sstream>
#include <fstream>

struct timeval current;

Application::
Application(SystemType systemtype, 
			const char *pairingparamfile,
			const char *sysparamfile, in_addr_t listen_addr, 
			in_port_t listen_port, const char *certfile,
			const char *keyfile, const char *contactlistfile, 
			Phase ph): systemtype(systemtype),sysparams(pairingparamfile, sysparamfile),
			buddyset(sysparams, certfile, keyfile), ph(ph), timeout_times(0) {
  // Ignore SIGPIPE
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
	cerr << "Error ignoring SIGPIPE\n";
  } else {
	//cerr << "Ignoring SIGPIPE\n";
  }
  
  //  cerr << "Starting as " << (systemtype == BULLETIN ? "BB" :
  //							 systemtype == NODE ? "Node" :
  //							 systemtype == CLIENT ? "Client" :
  //							 "Unknown system type") << "\n";
  
  if (systemtype != BLS_CLIENT) {
  	// Make the listening socket
	  //read the historical data to decide the timeout function

	  gettimeofday (&current, NULL);
  		listenfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  		if (listenfd < 0) {
  	  		perror("socket");
  	  		exit(1);
  		}
	
		sockaddr_in sin;
		sin.sin_family = AF_INET;
		sin.sin_port = htons(listen_port);
		sin.sin_addr.s_addr = htonl(listen_addr);
	
		int one = 1;
		int res = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &one,
						 sizeof(one));
		if (res < 0) {
	    	perror("setsockopt");
	    	cerr<<"Current error is Here\n";
	    	exit(1);
		}
	
		res = bind(listenfd, (sockaddr *)&sin, sizeof(sin));
	
		if (res < 0) {
	  		perror("bind");
	    	exit(1);
		}
	
		res = listen(listenfd, 5);
		if (res < 0) {
	  		perror("listen");
		  exit(1);
		}   

  } else listenfd = -1;
  // On what fd will user commands show up?
  userfd = 0;
  
  buddyset.init_contact_list(contactlistfile);
  
  //Intialzie the active user's list
  map<BuddyID, ContactEntry> buddy_list;
  map<BuddyID, ContactEntry>::iterator iter;
  buddy_list = buddyset.get_buddy_list();
  for(iter = buddy_list.begin(); iter != buddy_list.end();++iter)
	{
	  activeNodes.push_back(iter->first);
	}
}

//BuddyID& buddyID returns ID for the sender 
Message *Application::get_next_message(BuddyID& buddyID, BuddyID selfID)
{
    while (1) {
		// Figure out where our next message is coming from
		int maxfd = -1;
		fd_set rfd;

		FD_ZERO(&rfd);

		// UI input
		if (userfd >= 0) {
	    		FD_SET(userfd, &rfd);
	   	 	if (userfd > maxfd) maxfd = userfd;
		}

		// New incoming socket connections
		if (listenfd >= 0) {
	    		FD_SET(listenfd, &rfd);
	   	 	if (listenfd > maxfd) maxfd = listenfd;
		}

		// Messages on existing connections
		int buddymaxfd = buddyset.set_fds(&rfd);
		if (buddymaxfd > maxfd) maxfd = buddymaxfd;

		// See if a timer message will expire soon
		struct timeval timer;

		// Get performance measurements
		//measure_now();
		int res = select(maxfd+1, &rfd, NULL, NULL, Timer::time_to_next(&timer));

		if (res == 0) {
		    // See if a TimerMessage is ready to fire
	    		TimerMessage *tmsg = Timer::get_next();
	    		if (tmsg) return tmsg;
		}

		// Figure out what happened
		if (userfd >= 0 && FD_ISSET(userfd, &rfd)) {
	    		UserMessage *usermessage = UserMessage::read_message();
	    	if (usermessage == NULL) {
				//cerr << "User input closed\n";
				userfd = -1;
				close(userfd);
	    	} else {
				return usermessage;
	    	}
		}

		if (listenfd >= 0 && FD_ISSET(listenfd, &rfd)) {
		    	sockaddr_in sin;
	    		socklen_t sinlen = sizeof(sin);

	    		int newfd = accept(listenfd, (sockaddr *)&sin, &sinlen);
	    		if (newfd >= 0) {
				buddyset.add_buddy_fd(newfd);
			}
		}

		Buddy *foundbuddy = buddyset.find_set_fd(&rfd);

		if (foundbuddy) {

	   	 	if (foundbuddy->got_cert() == 0) {

				foundbuddy->read_cert();

				if (foundbuddy->got_cert() == 0) {
				    	// Closed socket; get rid of this buddy
					//cerr<<"Deleting(1) buddy "<<  foundbuddy->get_id() << " from " << selfID <<endl;
			    		buddyset.close_buddy(foundbuddy);
				} else {
				    	buddyset.add_buddy_id(foundbuddy);
				}
	    	} else {
			try {
			    Message *newmsg = NetworkMessage::read_message(systemtype,foundbuddy);
			    if (newmsg == NULL) {
				// Closed socket; 
			        //cerr<<"Deleting(2) buddy "<<  foundbuddy->get_id()<<" on fd "<<foundbuddy->get_fd()<<endl;
					buddyset.close_buddy(foundbuddy);
			    } else {
			    	buddyID = foundbuddy->get_id();
			    	return newmsg;
		    	}
			} catch (InvalidMessageException e) {
		    	cerr<<"Invalid message received from buddy id "<<foundbuddy->get_id() << "\n";
			}
	    	}
		}// else cerr<<"foundbuddy is null\n";
    }
}

void Application::measure_init()
{
    gettimeofday(&start_time, NULL);
}

void Application::measure_now()
{
	struct timeval now;
	gettimeofday(&now, NULL);

	long realms = (now.tv_sec - start_time.tv_sec) * 1000 +
		(now.tv_usec - start_time.tv_usec) / 1000;

	struct rusage rus;
	getrusage(RUSAGE_SELF, &rus);

	long userms = rus.ru_utime.tv_sec * 1000 + rus.ru_utime.tv_usec / 1000;
	long sysms = rus.ru_stime.tv_sec * 1000 + rus.ru_stime.tv_usec / 1000;
	string outputFileName = "dkg_";
	std::stringstream IStream; IStream << NodeID(buddyset.get_my_id());
	outputFileName+=IStream.str();
	outputFileName.append(".log");
	fstream logFStream(outputFileName.data(), ios::out);
	logFStream << setfill('0');
	logFStream << "RT: " << realms << endl;
	logFStream << "PT: " << sysms + userms << endl;
	logFStream << "Start: " << start_time.tv_sec << "." << setw(6) << start_time.tv_usec << endl;
	logFStream << "Now: " << now.tv_sec << "." << setw(6) << start_time.tv_usec << endl;
	logFStream << endl;
	logFStream.close();
}

unsigned long Application::get_time_diff(int t, unsigned long incre){
	//Check with Ian about the overflow (> 49 days)
	timeout_times++;
	if (timeout_times == 1) {
		// This is the first time of timeout
		struct timeval now;
		gettimeofday(&now, NULL);

		last_timeout = (now.tv_sec - start_time.tv_sec) * 1000 +
			(now.tv_usec - start_time.tv_usec) / 1000;
		first_timeout = last_timeout;

  	 	 return last_timeout;
	} else if (timeout_times <= t + 1) {
		if (incre == 0) {
			// There is no historical data available for the current setting
			last_timeout += first_timeout;
			return last_timeout;
		}
		else {
			last_timeout += incre;
			return last_timeout;
		}
	} else {
		// starting point of exponential growth
		last_timeout *= 2;
		return last_timeout;
	}
}
