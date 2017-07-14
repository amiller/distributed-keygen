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



#ifndef __IO_H__
#define __IO_H__

#include <stdio.h>
#include <string>

using namespace std;

void hexdump(FILE *f, const string &s);

void write_ui(string &body, unsigned int v);

void read_ui(const unsigned char *&buf, size_t &len, unsigned int &v);

void write_us(string &body, unsigned short v);

void read_us(const unsigned char *&buf, size_t &len,unsigned short &v);

void write_byte(string &body, unsigned char v);

void read_byte(const unsigned char *&buf, size_t &len, unsigned char &v);

#include "buddyset.h"

void addMsgHeader(NetworkMessageType type, string &body);

void addMsgID(int ID, string &body);

void write_sig(const BuddySet &buddyset, string &body, const string& msgStr);

bool read_sig(const Buddy *buddy, const unsigned char *&buf, size_t &len,
			 const unsigned char *signstart, const unsigned char *signend);

void write_G1(string &body, const G1& elt);

void read_G1(const unsigned char *&buf, size_t &len, G1& elt, const Pairing& e);

void write_Zr(string &body, const Zr& elt);

void read_Zr(const unsigned char *&buf, size_t &len, Zr& elt, const Pairing& e);

void write_str(string &body, const string &str, size_t slen);

void read_str(const unsigned char *&buf, size_t &len, string &str,
	size_t slen);

void hash_id(G1& elt, NodeID id, const Pairing& e);

void hash_msg(G1& elt, string msg, const Pairing& e);
#include "polynomial.h"

void read_Poly(const unsigned char *&buf, size_t& len, Polynomial& poly,
			   const Pairing& e);
void write_Poly(string &body, const Polynomial& poly);

#endif
