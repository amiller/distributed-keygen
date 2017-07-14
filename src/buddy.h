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



//Distributed Private-Key Generator

#ifndef __BUDDY_H__
#define __BUDDY_H__

#include <string>
#include <queue>
#include <gnutls/x509.h>
#include <fstream>
#include "systemparam.h"

using namespace std;

typedef NodeID BuddyID;

//class for buddy 
class Buddy{
 public:
    Buddy(class BuddySet &buddyset, int fd);
    Buddy(class BuddySet &buddyset, int fd, NodeID id);
    ~Buddy();

    const SystemParam &get_param() const;
    void close_fd();
    int get_fd() const { return fd; }
    int got_cert() const { return has_cert; }
    BuddyID get_id() const { return id; }
    Buddy *find_other_buddy(BuddyID id) const;
    int read_messagestr(string &msgstr) const;
    void write_messagestr(const string &msgstr);
    void writer_thread(void);
    int sig_size() const { return 40; }
    int verify(const unsigned char *data, size_t len,
	    const unsigned char *sig) const;
    void read_cert() { get_cert(); }
    const class BuddySet &get_buddyset(){return buddyset;}
    
    void set_fd (int fd) {this->fd = fd;}
     void set_cert(string cert);
     void send_cert(int usefd = -1) const;
     void help(fstream &msgLog);
     queue<string> msgqueue;
     queue<string> sentqueue;
     pthread_mutex_t mutex;
     
 private:
     BuddySet &buddyset;
     int fd;
     bool thread_is_running;
     BuddyID id;
     int is_server;
     int has_cert;
     gcry_sexp_t buddy_dsa_pubkey;

     int read_record(unsigned char *buffer, size_t len) const;
     void get_cert();
     void destroy_mutex();

  //To include public and private key
};
#endif
