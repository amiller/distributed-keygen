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



#ifndef __TIMER_H__
#define __TIMER_H__

#include <sys/time.h>
#include <time.h>
#include "timermessage.h"

class Timer {
    public:
	// Deliver the given message after the given number of ms
	static TimerID new_timer(TimerMessage *msg, unsigned int ms);

	// Cancel a pending timer message
	static void cancel(const TimerID &id);

	// How long until the next timeout?  Fill in *tv and return tv,
	// unless no timers pending; in that case, return NULL
	static struct timeval *time_to_next(struct timeval *tv);

	// Extract the first pending timeout, if it is available
	static TimerMessage *get_next();

    private:
	Timer(const struct timeval *whenp, TimerMessage *msg);

	TimerID id;
	struct timeval when;
	TimerMessage *msg;
	Timer *next;
};

#endif
