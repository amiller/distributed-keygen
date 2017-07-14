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



#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include <iostream>
#include <string>

using namespace std;


typedef enum {NODE, BLS_CLIENT} SystemType;

enum{NETWORK, USER, TIMER};

//class for messages in the system
class Message{
private:
	static int msgctr;

protected:
	int message_class;
	int msg_ID;

public:
	Message(){msg_ID = next_ID();}

	//virtual ~Message(){}
	int get_class() const { return message_class;}
	int get_ID() const { return msg_ID;}

	static void init_ctr();
	static int next_ID ();
};

#endif
