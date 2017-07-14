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
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <gnutls/x509.h>
#include "buddyset.h"

using namespace std;

BuddySet::BuddySet(const SystemParam &sysparams, const char *certfilename,
	const char *keyfilename): sysparams(sysparams)
{
	my_dsa_privkey = NULL;
    if (keyfilename) {
	gnutls_x509_privkey_t my_privkey;
	gnutls_x509_privkey_init(&my_privkey);

	// Read the file
	ifstream keyfile;
	keyfile.open(keyfilename);
	string keystring;
	getline(keyfile, keystring, '\0');
	keyfile.close();
	gnutls_datum_t keydatum;
	keydatum.data = (unsigned char *)keystring.data();
	keydatum.size = keystring.size();
	gnutls_x509_privkey_import(my_privkey, &keydatum, GNUTLS_X509_FMT_PEM);

	// Extract the params from the privkey
	gnutls_datum_t pd, qd, gd, yd, xd;
	gnutls_x509_privkey_export_dsa_raw(my_privkey, &pd, &qd, &gd, &yd,
		&xd);
	gnutls_x509_privkey_deinit(my_privkey);

	// Construct libgcrypt MPIs from the pieces
	gcry_mpi_t p, q, g, y, x;
	gcry_mpi_scan(&p, GCRYMPI_FMT_USG, pd.data, pd.size, NULL);
	gcry_mpi_scan(&q, GCRYMPI_FMT_USG, qd.data, qd.size, NULL);
	gcry_mpi_scan(&g, GCRYMPI_FMT_USG, gd.data, gd.size, NULL);
	gcry_mpi_scan(&y, GCRYMPI_FMT_USG, yd.data, yd.size, NULL);
	gcry_mpi_scan(&x, GCRYMPI_FMT_USG, xd.data, xd.size, NULL);
	gnutls_free(pd.data);
	gnutls_free(qd.data);
	gnutls_free(gd.data);
	gnutls_free(yd.data);
	gnutls_free(xd.data);

	// Build the sexp holding the private DSA key
	gcry_sexp_build(&my_dsa_privkey, NULL,
		"(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))", p, q, g, y, x);
	gcry_mpi_release(p);
	gcry_mpi_release(q);
	gcry_mpi_release(g);
	gcry_mpi_release(y);
	gcry_mpi_release(x);
    }    
    if (certfilename) {
	// Read the file
	ifstream certfile;
	certfile.open(certfilename);
	getline(certfile, my_cert, '\0');
	certfile.close();

	// Extract our own ID from it
	gnutls_datum_t certdatum;
	certdatum.data = (unsigned char *)my_cert.data();
	certdatum.size = my_cert.size();
	gnutls_x509_crt_t cert;
	gnutls_x509_crt_init(&cert);
	gnutls_x509_crt_import(cert, &certdatum, GNUTLS_X509_FMT_PEM);

	// Get the DN
	size_t buflen = 0;
	gnutls_x509_crt_get_dn(cert, NULL, &buflen);
	char buf[buflen];
	gnutls_x509_crt_get_dn(cert, buf, &buflen);

	// Extract the ID from the DN
	if (!strncmp(buf, "CN=DPKG ID ", 11)) {
	    my_id = atoi(buf + 11);  // This will magically convert "BB" to 0
	    //cerr << "Own ID is " << my_id << "\n";
	} else {
	    my_id = NODEID_NONE;
	    cerr << "Cannot determine own ID\n";
	}
	gnutls_x509_crt_deinit(cert);
    }

    // Create the pipe used to notify the main thread of a newly
    // connected Buddy
    pipe(notifyfds);
    pipe(notifyids);
}

BuddySet::~BuddySet()
{
    gcry_sexp_release(my_dsa_privkey);
}

void BuddySet::init_contact_list(const char *filename)
{
    if (filename == NULL) return;

    ifstream file;
    file.open(filename);
    bool isleader = false;//To check if leader char is ever set or not
    while (1) {
		string nextline;
		getline(file, nextline);
		if (file.eof()) break;
		// Parse each line of the file
		// Format: id <space> i.p.ad.dr <space> port <space>[L]
		int id, a1, a2, a3, a4, port;
		char leader_char;
		char certfilename[200];
		int res = sscanf(nextline.data(), "%d %d.%d.%d.%d %d %s %c",&id, &a1, &a2, &a3, &a4, &port, certfilename, &leader_char);
		if ((res == 8)&& (leader_char == 'L')) {isleader = true; leader = id;}
		if (res < 7) {
	    	cerr << "Bad scanned line: " << nextline << "\n";
	    	continue;
		}
		//Add contact Entry
		ContactEntry ce;
		ce.addr = (a1 << 24) + (a2 << 16) + (a3 << 8) + a4;
		ce.port = port;
		contactlist[id] = ce;
		
		//Add Buddy and Certificate
		string cert;			
		// Read the file
		ifstream certfile;
		certfile.open(certfilename);
		if (certfile.good()) {
			getline(certfile, cert, '\0');
			certfile.close();   
			Buddy *newbuddy = new Buddy(*this, -1, id);//fd = -1 as there is no circuit yet    
    	    		idmap[newbuddy->get_id()] = newbuddy;
			newbuddy->set_cert(cert);
		} else cerr << "Certificate doesn't exist for " << id<< "\n";
    }
    //If no Leader character (L) present, select first node in the contact list as the one
    if (!isleader) leader = (contactlist.begin())->first;
    file.close();
}

void BuddySet::set_leader(BuddyID new_leader){
	//Note that I have to first change the leader in the file
	//NOT YET DONE
	leader = new_leader;
}

BuddyID BuddySet::get_next_leader(){
	map<BuddyID,ContactEntry>::iterator lead_it;
    lead_it = contactlist.find(leader);
    if (++lead_it != contactlist.end())    
    	return lead_it->first;
    else
    	return contactlist.begin()->first;
}	

BuddyID BuddySet::get_previous_leader(){
	map<BuddyID,ContactEntry>::iterator lead_it;
    lead_it = contactlist.find(leader);
    if (lead_it != contactlist.begin())    
    	return (--lead_it)->first;
    else
    	return contactlist.rbegin()->first;
}
int BuddySet::set_fds(fd_set *fdsp)
{
    // Set the new buddy notification pipe for sure
    FD_SET(notifyfds[0], fdsp);
    FD_SET(notifyids[0], fdsp);
    int maxfd = notifyfds[0];
    if (notifyids[0] > maxfd) {
	maxfd = notifyids[0];
    }
    for (map<int, Buddy*>::iterator fditer = fdmap.begin();
	    fditer != fdmap.end(); fditer++) {
//    	cerr << "set dsp: " << fditer->first << endl;
	FD_SET(fditer->first, fdsp);
	if (fditer->first > maxfd) maxfd = fditer->first;
    }
    return maxfd;
}

Buddy *BuddySet::find_set_fd(fd_set *fdsp)
{
    // First, see if we have data on the new buddy notification pipe
    if (FD_ISSET(notifyfds[0], fdsp)) {
	int newfd;
	BuddyID newid;
	char buf[sizeof(newfd)+sizeof(newid)];
	read(notifyfds[0], buf, sizeof(newfd)+sizeof(newid));
	memmove(&newfd, buf, sizeof(newfd));
	memmove(&newid, buf+sizeof(newfd), sizeof(newid));
	add_buddy_fd(newfd, newid);
    }

    // then, see if we have failed connections
    if (FD_ISSET(notifyids[0], fdsp)) {
	Buddy* newBuddy;
	char buf[sizeof(newBuddy)];
	read(notifyids[0], buf, sizeof(newBuddy));
	memmove(&newBuddy, buf, sizeof(newBuddy)); if (find_buddy(newBuddy->get_id()) == NULL) {
		// just now there has not been an incoming connection
		// idmap[newBuddy->get_id()] = newBuddy;
		add_buddy_id (newBuddy);
	}
    }
	

    map<int, Buddy*>::iterator fditer, startat;
    startat = fdmap.find(last_fd_found);
    if (startat != fdmap.end()) {
	++startat;
    }
    if (startat == fdmap.end()) {
	startat = fdmap.begin();
    }
    for (fditer = startat; fditer != fdmap.end(); fditer++) {
	if (FD_ISSET(fditer->first, fdsp)) { 
	    last_fd_found = fditer->first;
	    return fditer->second;
	}
    }
    for (fditer = fdmap.begin(); fditer != startat; fditer++) {
	if (FD_ISSET(fditer->first, fdsp)) { 
	    last_fd_found = fditer->first;
	    return fditer->second;
	}
    }
    return NULL;
}

Buddy *BuddySet::add_buddy_fd(int fd)
{

    Buddy *newbuddy = new Buddy(*this, fd);
    
    fdmap[fd] = newbuddy;
    BuddyID id = newbuddy->get_id();
  // cerr << "Special Adding buddy" << id << " ;" << "fd " << fd << endl;
    //cerr<<"Adding new Buddy "<<id<<" at "<<fd<<endl;
    // Check if we already have a (presumably stale) buddy with this id
  /*  map<BuddyID,Buddy *>::const_iterator found;
    found = idmap.find(id);
    if (found != idmap.end()){
		del_buddy(found->second);
    }
    if (id != NODEID_NONE)*/ idmap[id] = newbuddy;    	
    return newbuddy;
}

void BuddySet::add_buddy_id(Buddy *buddy)
{
//	cerr << "Adding buddy " << buddy -> get_id() << endl;
	// Now before we add, we check whether there exists a buddy with the same name or not
	// TODO
	Buddy *oriBuddy = find_buddy_id (buddy->get_id());
	// cout << "for node " <<  buddy->get_id() << endl;
	if (oriBuddy != NULL) {
		//cout << "HERE!!" << endl;
		pthread_mutex_lock (&(oriBuddy->mutex));
		buddy->msgqueue = oriBuddy->msgqueue;
		buddy->sentqueue = oriBuddy->sentqueue;
		// cout << "oriBuddy-> sentqueuesize = " << (oriBuddy->sentqueue).size() << endl;
		// cout << "oriBuddy-> msgqueuesize = " << (oriBuddy->msgqueue).size() << endl;
		pthread_mutex_unlock (&(oriBuddy->mutex));
	}
	idmap[buddy->get_id()] = buddy;
}

Buddy *BuddySet::find_buddy_id(BuddyID id) const
{
    map<BuddyID,Buddy *>::const_iterator found;
    found = idmap.find(id);
    if (found == idmap.end()) return NULL;
    return found->second;
}

void BuddySet::notify_add_buddy_id(Buddy *buddy)
{
    // Tell the main thread to add (id, *buddy) to the id map
	char buf[sizeof(buddy)];
	memmove(buf, &buddy, sizeof(buddy));
	write(notifyids[1], buf, sizeof(buddy));
}

void BuddySet::notify_add_buddy_fd(int fd, BuddyID id)
{
    // Tell the main thread to add (fd,id) to the buddy map
    char buf[sizeof(fd)+sizeof(id)];
    memmove(buf, &fd, sizeof(fd));
    memmove(buf+sizeof(fd), &id, sizeof(id));
    write(notifyfds[1], buf, sizeof(fd)+sizeof(id));
    // cout << "Add buddy fd notified" << endl;
    // cout << fd << " " << id << endl;
}

Buddy *BuddySet::add_buddy_fd(int fd, BuddyID id)
{
    //Buddy *buddy = new Buddy(*this, fd, id);
    
     // This will eventually turn into actual TLS.  For now, we just
    // exchange X.509 certs, but don't do any of the encryption.
	//cerr << "Adding buddy" << id << " ;" << "fd " << fd << endl;
    Buddy *buddy = find_buddy_id(id);

    if (buddy == NULL) {
    	buddy = new Buddy(*this, fd, id);
    	idmap[buddy->get_id()] = buddy;
    } else {
	  int old_fd = buddy->get_fd();
	  fdmap.erase(old_fd);	  	  
	}
	buddy->set_fd(fd);
	fdmap[fd] = buddy; 
    return buddy;
}

void BuddySet::close_buddy(Buddy *buddy)
{
    int fd = buddy->get_fd();
    fdmap.erase(fd);
    buddy->close_fd();
}

void BuddySet::del_buddy(Buddy *buddy)
{
    int fd = buddy->get_fd();
    BuddyID id = buddy->get_id();
    if (fd >= 0) fdmap.erase(fd);
    idmap.erase(id);
    delete buddy;
    if (fd >= 0) close(fd);
}

Buddy *BuddySet::find_buddy(BuddyID id, int contact)
{
    // Look up the buddy by id
    map<BuddyID, Buddy*>::iterator iditer = idmap.find(id);
    if (iditer == idmap.end()) return NULL; 
    return iditer->second;
}

void BuddySet::send_message(BuddyID id, const NetworkMessage &message)
{
    Buddy *buddy = find_buddy(id, 1);
   // gettimeofday (&g_now, NULL); //Stage 1
    if (!buddy) return;
    buddy->write_messagestr(message.get_netMsgStr());
}

void BuddySet::sign(const unsigned char *data, size_t len,
	unsigned char *sig) const
{
    // First hash the data
    unsigned char hashbuf[20];
    gcry_md_hash_buffer(GCRY_MD_SHA1, hashbuf, data, len);

    // Make an mpi out of the hash
    gcry_mpi_t hashm;
    gcry_mpi_scan(&hashm, GCRYMPI_FMT_USG, hashbuf, 20, NULL);

    // Make an sexp out of the mpi
    gcry_sexp_t hashs;
    gcry_sexp_build(&hashs, NULL, "(%m)", hashm);
    gcry_mpi_release(hashm);

    // Sign the sexp
    gcry_sexp_t sigs;
    gcry_pk_sign(&sigs, hashs, my_dsa_privkey);
    gcry_sexp_release(hashs);

    // Find the r and s pieces inside
    gcry_sexp_t dsas, rs, ss;
    gcry_mpi_t r, s;
    dsas = gcry_sexp_find_token(sigs, "dsa", 0);
    gcry_sexp_release(sigs);
    rs = gcry_sexp_find_token(dsas, "r", 0);
    ss = gcry_sexp_find_token(dsas, "s", 0);
    gcry_sexp_release(dsas);
    r = gcry_sexp_nth_mpi(rs, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(rs);
    s = gcry_sexp_nth_mpi(ss, 1, GCRYMPI_FMT_USG);
    gcry_sexp_release(ss);

    // Write them to the appropriate place
    size_t nr, ns;
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &nr, r);
    gcry_mpi_print(GCRYMPI_FMT_USG, NULL, 0, &ns, s);
    memset(sig, 0, 40);
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)sig+(20-nr),
	    nr, NULL, r);
    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)sig+20+(20-ns),
	    ns, NULL, s);
    gcry_mpi_release(r);
    gcry_mpi_release(s);
}
