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



#include <pthread.h>
#include <iomanip>
#include <iostream>
#include <sys/time.h>
#include <string>
#include <stdlib.h>
#include <fstream>
#include <iomanip>
#include <unistd.h>
#include "buddyset.h"
#include "buddy.h"

using namespace std;

Buddy::Buddy(BuddySet &buddyset, int fd) :
	buddyset(buddyset), fd(fd), thread_is_running(false), id(NODEID_NONE),
    is_server(1), has_cert(0), buddy_dsa_pubkey(NULL)
{
	pthread_mutex_init(&mutex, NULL);
    //cerr << "Received new buddy on fd " << fd << "\n";
}

Buddy::Buddy(BuddySet &buddyset, int fd, NodeID id) :
    buddyset(buddyset), fd(fd), thread_is_running(false), id(id),
    is_server(0), has_cert(0), buddy_dsa_pubkey(NULL)
{
	pthread_mutex_init(&mutex, NULL);
    //cerr << "Contacting new buddy id " << id << " on fd " << fd << "\n";

    // This will eventually turn into actual TLS.  For now, we just
    // exchange X.509 certs, but don't do any of the encryption.
    //send_cert();
}

const SystemParam &Buddy::get_param() const
{
    return buddyset.get_param();
}

void Buddy::send_cert(int usefd) const
{
    if (usefd < 0) usefd = fd;
    if (usefd < 0) return;
    //cerr << "Sending cert\n";
    const string &cert = buddyset.get_cert();
    unsigned int len = htonl(cert.size());
    write(usefd, (char *)&len, 4);
    write(usefd, cert.data(), cert.size());
    //cerr << "Sent cert\n";
}
void Buddy::set_cert(string cert)
{
    buddy_dsa_pubkey = NULL;
    gnutls_x509_crt_t buddy_cert;
    gnutls_x509_crt_init(&buddy_cert);
    
    gnutls_datum_t certdatum;
    certdatum.data = (unsigned char*)cert.data();
    certdatum.size = cert.length();
    gnutls_x509_crt_import(buddy_cert, &certdatum, GNUTLS_X509_FMT_PEM);

    // Extract the params from the pubkey
    gnutls_datum_t pd, qd, gd, yd;
    gnutls_x509_crt_get_pk_dsa_raw(buddy_cert, &pd, &qd, &gd, &yd);
    gnutls_x509_crt_deinit(buddy_cert);

    // Construct libgcrypt MPIs from the pieces
    gcry_mpi_t p, q, g, y;
    gcry_mpi_scan(&p, GCRYMPI_FMT_USG, pd.data, pd.size, NULL);
    gcry_mpi_scan(&q, GCRYMPI_FMT_USG, qd.data, qd.size, NULL);
    gcry_mpi_scan(&g, GCRYMPI_FMT_USG, gd.data, gd.size, NULL);
    gcry_mpi_scan(&y, GCRYMPI_FMT_USG, yd.data, yd.size, NULL);
    gnutls_free(pd.data);
    gnutls_free(qd.data);
    gnutls_free(gd.data);
    gnutls_free(yd.data);

    // Build the sexp holding the public DSA key
    gcry_sexp_build(&buddy_dsa_pubkey, NULL,
	    "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))", p, q, g, y);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);
    gcry_mpi_release(y);

    has_cert = 1;	
}

void Buddy::destroy_mutex() {
	pthread_mutex_destroy(&mutex);
}

void Buddy::get_cert()
{
    buddy_dsa_pubkey = NULL;
    gnutls_x509_crt_t buddy_cert;
    gnutls_x509_crt_init(&buddy_cert);

    // Read the length of the cert
    unsigned int len;
    //cerr << "Waiting for cert header\n";
    if (read_record((unsigned char *)&len, 4) != 4) return;
    //cerr << "Got cert header\n";
    len = ntohl(len);

    // Read the actual cert (in PEM format)
    unsigned char certbuf[len];
    //cerr << "Waiting for cert\n";
    if (read_record(certbuf, len) != (int)len) return;
    //cerr << "Got cert\n";
    gnutls_datum_t certdatum;
    certdatum.data = certbuf;
    certdatum.size = len;
    gnutls_x509_crt_import(buddy_cert, &certdatum, GNUTLS_X509_FMT_PEM);

    // Extract the DN from the cert
    size_t buflen = 0;
    gnutls_x509_crt_get_dn(buddy_cert, NULL, &buflen);
    char buf[buflen];
    gnutls_x509_crt_get_dn(buddy_cert, buf, &buflen);

    // Extract the ID from the DN
    // cout << "buf: " << endl << buf << endl;
    if (!strncmp(buf, "CN=DPKG ID ", 11)) {
	id = atoi(buf + 11);  // This will magically convert "BB" to 0
	//cerr << "ID " << id << " received from buddy\n";
    } else {
	id = NODEID_NONE;
	cerr << "Unknown ID received from buddy\n";
    }

    // Extract the params from the pubkey
    gnutls_datum_t pd, qd, gd, yd;
    gnutls_x509_crt_get_pk_dsa_raw(buddy_cert, &pd, &qd, &gd, &yd);
    gnutls_x509_crt_deinit(buddy_cert);

    // Construct libgcrypt MPIs from the pieces
    gcry_mpi_t p, q, g, y;
    gcry_mpi_scan(&p, GCRYMPI_FMT_USG, pd.data, pd.size, NULL);
    gcry_mpi_scan(&q, GCRYMPI_FMT_USG, qd.data, qd.size, NULL);
    gcry_mpi_scan(&g, GCRYMPI_FMT_USG, gd.data, gd.size, NULL);
    gcry_mpi_scan(&y, GCRYMPI_FMT_USG, yd.data, yd.size, NULL);
    gnutls_free(pd.data);
    gnutls_free(qd.data);
    gnutls_free(gd.data);
    gnutls_free(yd.data);

    // Build the sexp holding the public DSA key
    gcry_sexp_build(&buddy_dsa_pubkey, NULL,
	    "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))", p, q, g, y);
    gcry_mpi_release(p);
    gcry_mpi_release(q);
    gcry_mpi_release(g);
    gcry_mpi_release(y);

    has_cert = 1;

    //if (is_server) {
	//	send_cert();
    //}
}

Buddy::~Buddy()
{
    cerr << "Destroying buddy on fd " << fd << "\n";
    gcry_sexp_release(buddy_dsa_pubkey);
}

void Buddy::close_fd()
{
    if (fd < 0) return;
    close(fd);
    fd = -1;
}

int Buddy::read_record(unsigned char *buffer, size_t len) const
{
    if (fd < 0) return 0;

    int res = 0;
    while (len > 0) {
	int piece = read(fd, buffer, len);
	if (piece < 0) return piece;
	if (piece == 0) return res;
	buffer += piece;
	len -= piece;
	res += piece;
    }
    return res;
}

int Buddy::read_messagestr(string &msgstr) const
{
    int IDLength = 4;
    int lenLength = 4;
    int typeLength = 1;
    int headerLength = IDLength + lenLength + typeLength;
    unsigned char header[headerLength];

    size_t res = read_record(header, headerLength);
    if (res < (unsigned int)headerLength) return -1;

    int lengthFieldStart = IDLength + typeLength;
    unsigned int len = (header[lengthFieldStart] << 24) + 
	(header[lengthFieldStart+1] << 16) + 
	(header[lengthFieldStart+2] << 8) + 
	header[lengthFieldStart+3];

    unsigned char message[len+headerLength];
    memmove(message, header, headerLength);
    res = read_record(message+headerLength, len);
    if (res < len) return -1;
    msgstr.assign((char *)message, len+headerLength);

    return 0;
}

static void *launch_writer_thread(void *data)
{
    Buddy *buddy = (Buddy *)data;
    buddy->writer_thread();
    pthread_exit(NULL);
}

ssize_t write_fully(int fd, const char *buf, size_t len)
{
    ssize_t bytes_written = 0, res;
    while(len) {
    	 res = write(fd, buf, len);
    	 if (res < 0) return res;
    	 if (res == 0) return bytes_written;
    	 bytes_written += res;
    	 buf += res;
    	 len -= res;
    }
    return bytes_written;
}

void Buddy::writer_thread(void) {
	while (true) {

		if (fd < 0) {
			const map<BuddyID, ContactEntry> contactlist = buddyset.get_buddy_list();
			map<BuddyID, ContactEntry>::const_iterator citer = contactlist.find(id);

			if (citer != contactlist.end()) {
				fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
				sockaddr_in sin;
				sin.sin_family = AF_INET;
				sin.sin_port = htons(citer->second.port);
				sin.sin_addr.s_addr = htonl(citer->second.addr);
				// cout << "Connecting for id " << id << endl;
				int res = connect(fd, (sockaddr *)&sin, sizeof(sin));
				if (res < 0) {
					// this is original, but is this truely necessary?
					// cout << "connection failed " << this -> get_id() << endl;
					buddyset.notify_add_buddy_id(this);
					close(fd);
					return;
				}   
				send_cert(fd);
				buddyset.notify_add_buddy_fd(fd, id);
			} else {
				return;    
			}   
		}
		
    		pthread_mutex_lock (&mutex);

		if (msgqueue.empty()) {
			thread_is_running = false;
			pthread_mutex_unlock (&mutex);
			return;
		} 

    		string msgstr = msgqueue.front();
    		msgqueue.pop();

		int msg_type = (int)msgstr[4];

		// int recv_id = (msgstr[0] << 24) | (((msgstr[1]) << 16) & 0x00ffffff) |
		//	(((msgstr[2]) << 8) & 0x0000ffff) | (msgstr[3] & 0x000000ff);

		if (msg_type == VSS_SEND || msg_type == VSS_ECHO || msg_type == VSS_READY || msg_type == LEADER_CHANGE) {
			sentqueue.push(msgstr);
		}
 
    		pthread_mutex_unlock (&mutex);
    		size_t len = msgstr.size();

    		// The following line may block!
    		write_fully(fd, msgstr.data(), len);

	    	pthread_mutex_lock (&mutex);
    		if (msgqueue.empty() == true) {
    			thread_is_running = false;
    			pthread_mutex_unlock (&mutex);
    			return;
    		}

    	pthread_mutex_unlock (&mutex);
    }
}

void Buddy::help(fstream &msgLog) {
	timeval now;
	pthread_mutex_lock (&mutex);
	while (!sentqueue.empty()) {
		string msgstr = sentqueue.front();
		sentqueue.pop();

		msgqueue.push(msgstr);

		int msg_type = (int)msgstr[4];
		int recv_id = (msgstr[0] << 24) | (((msgstr[1]) << 16) & 0x00ffffff) |
			(((msgstr[2]) << 8) & 0x0000ffff) | (msgstr[3] & 0x000000ff);
		gettimeofday (&now, NULL);
		switch (msg_type) {
			case VSS_SEND:
				msgLog << "VSS_SEND " << recv_id << " for " << "* SENT from * to " << id << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " from help " << endl;
				break;
			case VSS_ECHO:
				msgLog << "VSS_ECHO " << recv_id << " for " << "* SENT from * to " << id << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " from help " << endl;
				break;
			case VSS_READY:
				msgLog << "VSS_READY " << recv_id << " for " << "* SENT from * to " << id << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " from help " << endl;
				break;
			case VSS_SHARED:
				msgLog << "VSS_SHARED " << recv_id << " for " << "* SENT from * to " << id << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " from help " << endl;
				break;
			case DKG_SEND:
				msgLog << "DKG_SEND " << recv_id << " for " << "* SENT from * to " << id << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " from help " << endl;
				break;
			case DKG_ECHO:
				msgLog << "DKG_ECHO " << recv_id << " for " << "* SENT from * to " << id << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " from help " << endl;
				break;
			case DKG_READY:
				msgLog << "DKG_READY " << recv_id << " for " << "* SENT from * to " << id << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << " from help " << endl;
				break;
			default:
				msgLog << "* " << recv_id << " for " << "* SENT from * to " << id << " at " <<  now.tv_sec << "." << setw(6) << now.tv_usec << "from help "  << endl;
		}
	}
	pthread_mutex_unlock (&mutex);

	if (!thread_is_running && msgqueue.size() != 0) {
		// Launch the writer thread
		thread_is_running = true;
		pthread_attr_t attr;
    		pthread_attr_init(&attr);
    		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    		pthread_t threadid;
    		pthread_create(&threadid, &attr, launch_writer_thread, this);
   	 }

}

void Buddy::write_messagestr(const string &msgstr)
{
    pthread_mutex_lock (&mutex);

    msgqueue.push(msgstr);
    pthread_mutex_unlock (&mutex);

    if (!thread_is_running) {
    	// Launch the writer thread
    	thread_is_running = true;
    	pthread_attr_t attr;
    	pthread_attr_init(&attr);
    	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    	pthread_t threadid;

    	if (msgqueue.empty() == true) {
           	cout << "HERE2 the msgqueue is EMPTY!!" << endl;
		// This should never happen
        }

    	pthread_create(&threadid, &attr, launch_writer_thread, this);
    }
}

int Buddy::verify(const unsigned char *data, size_t len,
	const unsigned char *sig) const
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
// Make mpis out of the signature
    gcry_mpi_t r, s;
    gcry_mpi_scan(&r, GCRYMPI_FMT_USG, sig, 20, NULL);
    gcry_mpi_scan(&s, GCRYMPI_FMT_USG, sig+20, 20, NULL);

    // Make an sexp for the signature
    gcry_sexp_t sigs;
    gcry_sexp_build(&sigs, NULL, "(sig-val (dsa (r %m)(s %m)))", r, s);
    gcry_mpi_release(r);
    gcry_mpi_release(s);

    // Verify the signature
    gcry_error_t vrf = gcry_pk_verify(sigs, hashs, buddy_dsa_pubkey);
    gcry_sexp_release(sigs);
    gcry_sexp_release(hashs);

    return vrf ? -1 : 0;
}

Buddy *Buddy::find_other_buddy(BuddyID id) const
{
    return buddyset.find_buddy_id(id);
}
