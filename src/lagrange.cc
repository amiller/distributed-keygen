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



#include "lagrange.h"

const vector <Zr> lagrange_coeffs(const vector <Zr> indices, const Zr& alpha)
{
    // This could be optimized, but this will do for now
  Zr numer, denom;
  vector<Zr> coeffs;
  for (size_t i = 0; i < indices.size(); ++i) {
	numer = Zr(alpha,(long int)1); 
	denom = Zr(alpha,(long int)1);
	for (size_t j = 0; j < indices.size(); ++j) {
	  if (j == i) continue;
	  numer *= (indices[j] - alpha);
	  denom *= (indices[j] - indices[i]);
	}
	coeffs.push_back(numer/denom);
  }
  return coeffs;
}

const G1 lagrange_apply(const vector <Zr> coeffs, const vector <G1> shares)
{
  G1 falpha(shares[0],true);
  for (size_t i = 0; i < coeffs.size(); ++i) {
	falpha *= shares[i]^coeffs[i]; 
  }
  return falpha;
}


//For Zr
const Zr lagrange_apply(const vector <Zr> coeffs, const vector <Zr> shares){
  Zr falpha(shares[0],(long)0);
  for (size_t i = 0; i < coeffs.size(); ++i) {
	falpha += shares[i]*coeffs[i]; 
  }
  return falpha;	
}
