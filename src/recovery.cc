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



#include <iostream>
#include "polynomial.h"
#include "lagrange.h"
#include "systemparam.h"

int main()
{
  string sysParamFileStr = "system.param";
  string pairingParamFileStr = "pairing.param";

  SystemParam param((char*)pairingParamFileStr.data(), 
					(char*)sysParamFileStr.data());
  const Pairing &e = param.get_Pairing();
  
  Polynomial f(e,3);
  f.dump(stdout, "polynomial f is");

  Zr i_r[4], i_t[4], c_r[4], c_t[4], c[4];
  long int r,i;

  cout<<"Recovery Node (>4) is "; cin>>r;

  for (i=0;i<4;++i) {
	c_r[i] = Zr(e);
	c_t[i] = Zr(e);	
	c[i] = Zr(e);
	i_r[i] = Zr(e, i+1);
	i_t[i] = Zr(e, i+1);
  }
   i_r[3] = Zr(e,r);
  
  printf("Index\n");
  for (i=0;i<4;++i) {i_r[i].dump(stdout, NULL, 10);}
 
  Zr zero(e,(long int)0);
  lagrange_coeffs(4, c_r, i_r, zero);
  lagrange_coeffs(4, c_t, i_t, zero);


  for (i=0;i<3;++i) {
	c[i] = (c_t[i] - c_r[i])/c_r[3];
  }
  c[3] = c_t[3]/c_r[3];

  G1 tmp;
  tmp = param.get_U();  
  G1 shares[4], share_r1, share_r2;
  for (i=0;i<4;++i) {shares[i] = tmp^(f(i_t[i]));}

  share_r1 = lagrange_apply(4, c, shares);
  share_r2 = tmp^(f(i_r[3]));

  share_r1.dump(stdout,"Through Lagrange");
  share_r2.dump(stdout,"Direct Value");
}
