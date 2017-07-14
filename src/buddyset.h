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



#ifndef __BUDDYSET_H__
#define __BUDDYSET_H__

#include <map>
#include <netinet/in.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h>
#include <queue>
#include <string>
#include "systemparam.h"
#include "buddy.h"
#include "networkmessage.h"

using namespace std;

struct ContactEntry {
    in_addr_t addr;
    in_port_t port;
};

class BuddySet {
    public:
	BuddySet(const SystemParam &sysparams, const char *certfile, const char *keyfile);
	~BuddySet();

	const SystemParam &get_param() const { return sysparams; }
	void init_contact_list(const char *filename);
	int set_fds(fd_set *fdsp);
	Buddy *find_set_fd(fd_set *fdsp);
	Buddy *add_buddy_fd(int fd);
	Buddy *add_buddy_fd(int fd, BuddyID id);
	void notify_add_buddy_fd(int fd, BuddyID id);
	void notify_add_buddy_id(Buddy *buddy);
	void add_buddy_id(Buddy *buddy);
	Buddy *find_buddy_id(BuddyID id) const;
	void close_buddy(Buddy *buddy);
	void del_buddy(Buddy *buddy);
	void send_message(BuddyID id, const class NetworkMessage &message);
	const string &get_cert() const { return my_cert; }
	size_t sig_size() const { return 40; }
	void sign(const unsigned char *data, size_t len,
		unsigned char *sig) const;
	const map<BuddyID, ContactEntry>& get_buddy_list ()const {return contactlist;}
	BuddyID get_my_id() const {return my_id;}
	BuddyID get_leader() const {return leader;}
	void set_leader(BuddyID new_leader);
	BuddyID get_next_leader();
	BuddyID get_previous_leader();
	int get_first_msg_type(BuddyID id) {return first_msg_type[id];}
	void del_first_msg_type(BuddyID id) {
		// To be implemented if needed}
	}
	bool set_first_msg_type(BuddyID id, int type) {
		for (map<BuddyID, int>::iterator fmtiter = first_msg_type.begin();
				fmtiter != first_msg_type.end(); fmtiter++) {
			if (fmtiter->first == id) {
				return false;
			}
		}
		first_msg_type[id] = type;
		return true;
	}
	
    private:
	const SystemParam &sysparams;
	map<int, Buddy*> fdmap;
	map<BuddyID, Buddy*> idmap;
	map<BuddyID, ContactEntry> contactlist;
	map<BuddyID, int> first_msg_type;
	BuddyID leader;
	string my_cert;
	gcry_sexp_t my_dsa_privkey;
	NodeID my_id;
	int last_fd_found;
	int notifyfds[2];
	int notifyids[2];

	Buddy *find_buddy(BuddyID id, int contact = 0);
};

#endif
