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



#ifndef __TIMER_MESSAGE_H__
#define __TIMER_MESSAGE_H__

#include "message.h"
#include "systemparam.h"

typedef unsigned int TimerID;

typedef enum {
    TIMER_MSG_NONE,
    TIMER_MSG_LEADER_CHANGE,
	TIMER_MSG_PHASE_CHANGE
} TimerMessageType;

//class for timer messages in the system
class TimerMessage: public Message {
 public:
    TimerID get_id() const { return id; }
    void set_id(TimerID id) { this->id = id; }
    TimerMessageType get_type() const { return type; }

 protected:
    TimerMessageType type;
    TimerID id;
    TimerMessage(TimerMessageType type): type(type) { message_class = TIMER; }
};

class LeaderChangeTimerMessage: public TimerMessage {
public:
  LeaderChangeTimerMessage(NodeID leader, Phase ph) :
	    TimerMessage(TIMER_MSG_LEADER_CHANGE), leader(leader),ph(ph){}
  NodeID leader;
  Phase ph;
};

class PhaseChangeTimerMessage: public TimerMessage {
public:
  PhaseChangeTimerMessage(Phase nextPh) :
	    TimerMessage(TIMER_MSG_PHASE_CHANGE), nextPh(nextPh){}
  Phase nextPh;
};
#endif
