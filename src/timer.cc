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



#include "timer.h"

static Timer *first = NULL;
static TimerID nextid = 0;

static void add_ms(struct timeval *resp, const struct timeval *tm,
	int ms)
{
    resp->tv_sec = tm->tv_sec;
    resp->tv_usec = tm->tv_usec + ms * 1000;
    if (resp->tv_usec > 1000000) {
	resp->tv_usec -= 1000000;
	resp->tv_sec += 1;
    }
}

static int diff_ms(struct timeval *a, struct timeval *b)
{
    return (a->tv_sec - b->tv_sec) * 1000 + (a->tv_usec - b->tv_usec) / 1000;
}

Timer::Timer(const struct timeval *whenp, TimerMessage *msg) :
    when(*whenp), msg(msg)
{
    id = ++(nextid);
    next = NULL;
    this->msg->set_id(id);
}

TimerID Timer::new_timer(TimerMessage *msg, unsigned int ms)
{
    // When should this timer go off?
    struct timeval now, then;
    gettimeofday(&now, NULL);
    add_ms(&then, &now, ms);

    // Make a new Timer node
    Timer *newt = new Timer(&then, msg);

    // Put it in the right place
    Timer **nextp = &first;
    while (*nextp && diff_ms(&then, &((*nextp)->when)) > 0) {
	nextp = &((*nextp)->next);
    }

    newt->next = *nextp;
    *nextp = newt;

    return newt->id;
}

void Timer::cancel(const TimerID &id)
{
    Timer **nextp = &first;

    while (*nextp) {
	if ((*nextp)->id == id) {
	    // Delete this entry
	    Timer *todel = *nextp;
	    *nextp = todel->next;
	    delete todel->msg;
	    todel->msg = NULL;
	    todel->next = NULL;
	    delete todel;
	    return;
	}
	nextp = &((*nextp)->next);
    }
}

struct timeval *Timer::time_to_next(struct timeval *tv)
{
    if (first == NULL) return NULL;

    struct timeval now;

    gettimeofday(&now, NULL);

    int diffms = diff_ms(&(first->when), &now);
    if (diffms > 0) {
	tv->tv_sec = diffms / 1000;
	tv->tv_usec = (diffms % 1000) * 1000;
    } else {
	tv->tv_sec = 0;
	tv->tv_usec = 0;
    }

    return tv;
}

TimerMessage *Timer::get_next()
{
    if (first == NULL) return NULL;

    struct timeval now;

    gettimeofday(&now, NULL);

    TimerMessage *ret;

    int diffms = diff_ms(&(first->when), &now);
    if (diffms > 0) {
	ret = NULL;
    } else {
	Timer *touse = first;
	first = first->next;
	touse->next = NULL;
	ret = touse->msg;
	touse->msg = NULL;
	delete touse;
    }
    return ret;
}
