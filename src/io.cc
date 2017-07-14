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



#include "io.h"
#include "exceptions.h"

void hexdump(FILE *f, const string &s)
{
    size_t i,len = s.size();
    for (i=0;i<len;++i) {
	unsigned char b = s[i];
	fprintf(f, "%02x", b);
    }
}

void write_ui(string &body, size_t v)
{
    unsigned char buf[4];
    buf[0] = (v >> 24) & 0xff;
    buf[1] = (v >> 16) & 0xff;
    buf[2] = (v >> 8) & 0xff;
    buf[3] = (v) & 0xff;
    body.append((char *)buf, 4);
}

void read_ui(const unsigned char *&buf, size_t &len, size_t &v)
{
    if (len < 4) throw InvalidMessageException();
    v = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    buf += 4;
    len -= 4;
}

void write_us(string &body, unsigned short v)
{
    unsigned char buf[2];
    buf[0] = (v >> 8) & 0xff;
    buf[1] = (v) & 0xff;
    body.append((char *)buf, 2);
}

void read_us(const unsigned char *&buf, size_t &len, unsigned short &v)
{
    if (len < 2) throw InvalidMessageException();
    v = (buf[0] << 8) | buf[1];
    buf += 2;
    len -= 2;
}

void write_byte(string &body, unsigned char v)
{
    unsigned char buf[1];
    buf[0] = (v) & 0xff;
    body.append((char *)buf, 1);
}

void read_byte(const unsigned char *&buf, size_t &len,
	unsigned char &v)
{
    if (len < 1) throw InvalidMessageException();
    v = buf[0];
    buf += 1;
    len -= 1;
}

void write_G1(string &body, const G1& elt)
{
  bool compressed = true;
  write_byte(body, elt.isElementPresent());
  body.append(elt.toString(compressed));
}

void read_G1(const unsigned char *&buf, size_t &len, G1 &elt, const Pairing& e)
{
  bool elementPresent;
  unsigned char b;
  read_byte(buf, len, b); elementPresent = b;
  //delete &elt;
  if(elementPresent){
	  bool compressed = true;
	  size_t eltlen = e.getElementSize(Type_G1,compressed);
	  if (len < eltlen) throw InvalidMessageException();
	  elt = G1(e,(unsigned char *)buf, eltlen,compressed);
	  buf += eltlen;
	  len -= eltlen;
  } else elt = G1();
}

void write_Zr(string &body, const Zr& elt)
{
  write_byte(body, elt.isElementPresent());
  body.append(elt.toString());
}

void read_Zr(const unsigned char *&buf, size_t &len, Zr &elt, const Pairing& e){
  bool elementPresent;
  unsigned char b;
  read_byte(buf, len, b); elementPresent = b;
  //delete &elt;
  if(elementPresent){
	size_t eltlen = e.getElementSize(Type_Zr);
	if (len < eltlen) throw InvalidMessageException();
	elt = Zr(e,(unsigned char *)buf, eltlen);
	buf += eltlen;
	len -= eltlen;
  } else elt = Zr();
}

//Deserialization
void read_Poly(const unsigned char *&buf, size_t& len, Polynomial& poly, const Pairing& e){
  NodeIDSize size; 
  read_us(buf, len, size);
  vector<Zr> coeffs;
  for(NodeIDSize i = 0; i<size; ++i){
	Zr elt;
	read_Zr(buf, len, elt, e);
	coeffs.push_back(elt);
  }
  poly = Polynomial(coeffs);
}

void write_Poly(string &body, const Polynomial& poly)
{
  NodeIDSize size = poly.degree()+1;
  write_us(body, size);
  for(NodeIDSize i = 0; i<size; ++i)
	write_Zr(body,poly.getCoeff(i));  
}

void write_str(string &body, const string &str, size_t slen)
{
    size_t glen = str.size();
    if (glen > slen) glen = slen;
    body.append(str.data(), glen);
    if (glen < slen) {
	  char zerobuf[slen-glen];
	  memset(zerobuf, '\0', slen-glen);
	  body.append(zerobuf, slen-glen);
    }
}

void read_str(const unsigned char *&buf, size_t &len, string &str, size_t slen)
{
    if (len < slen) throw InvalidMessageException();
    str.assign((char *)buf, slen);
    buf += slen;
    len -= slen;
}

void addMsgID(int ID, string &body) {
	size_t len = body.size();
	string msgStr;
	unsigned char header[4];
	header[0] = (ID >> 24) & 0xff;
	header[1] = (ID >> 16) & 0xff;
	header[2] = (ID >> 8) & 0xff;
	header[3] = ID & 0xff;
	msgStr.append((char *) header, 4);
	msgStr.append(body, 0, len);
	body = msgStr;
}

void addMsgHeader(NetworkMessageType type, string &body){
    size_t len = body.size();
    string msgStr;
    unsigned char header[5];
    header[0] = type;
    header[1] = (len >> 24) & 0xff;
    header[2] = (len >> 16) & 0xff;
    header[3] = (len >> 8) & 0xff;
    header[4] = len & 0xff;
    msgStr.append((char *) header, 5);
    msgStr.append(body, 0, len);
    body = msgStr;
}

void write_sig(const BuddySet &buddyset, string &body, const string& msgStr)
{
    size_t sigsize = buddyset.sig_size();
    unsigned char sig[sigsize];
    buddyset.sign((const unsigned char *)msgStr.data(),msgStr.length(), sig);
    body.append((char *)sig, sigsize);
}

bool read_sig(const Buddy *buddy, const unsigned char *&buf, size_t &len, 
			const unsigned char *signstart, const unsigned char *signend)
{
    bool status = false;
    size_t sigsize = buddy->sig_size();
    if (len < sigsize) throw InvalidMessageException();
    
    if (buddy->verify(signstart, signend-signstart, buf) < 0) 
	  status = false;
	else 
	  status = true;
	  //{throw InvalidSignatureException();}
    buf += sigsize;
    len -= sigsize;
	return status;
}

void hash_msg(G1& elt, string msg, const Pairing& e)
{
    unsigned char hashbuf[20];
    //unsigned char idbuf[2];
    //idbuf[0] = (id >> 8) & 0xff;
    //idbuf[1] = (id) & 0xff;
    gcry_md_hash_buffer(GCRY_MD_SHA1, hashbuf, msg.data(), 2);
    elt = G1(e, (void*)hashbuf, 20);
}

void hash_id(G1& elt, NodeID id, const Pairing& e)
{
    unsigned char hashbuf[20];
    unsigned char idbuf[2];
    idbuf[0] = (id >> 8) & 0xff;
    idbuf[1] = (id) & 0xff;
    gcry_md_hash_buffer(GCRY_MD_SHA1, hashbuf, idbuf, 2);
    elt = G1(e, (void*)hashbuf, 20);
}
