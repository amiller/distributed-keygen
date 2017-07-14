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



#ifndef __EXCEPTIONS_H__
#define __EXCEPTIONS_H__

#include <stdexcept>

using namespace std;

class Exception: public runtime_error {
    public: Exception(string str = ""): 
	  runtime_error("DKG Exception: "+str) { }
};
class InvalidMessageException: public Exception { };

class InvalidSignatureException: public InvalidMessageException { };

class InvalidSystemParamFileException: public Exception { 
public: 
  InvalidSystemParamFileException(string str):
	Exception("Invalid System-Parameter File: "+str){}
};

//class NonExistingPairingException: public Exception { };

#endif
