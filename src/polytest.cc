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
#include "bipolynomial.h"
//#include "lagrange.h"
#include "systemparam.h"

int main()
{
  //unsigned int n,t;
	string strU, typeStr;
	string sysParamFileStr = "system.param";
	string pairingParamFileStr = "pairing.param";
	//FILE *pairingParamFile = fopen("pairing.param","r");  
	//if (pairingParamFile == NULL) {
	//  cerr<<"Can't open pairing parameter file "<<"pairing.param" << "\n";
	//  return 0;
	//}
    SystemParam param((char*)pairingParamFileStr.data(), 
					  (char*)sysParamFileStr.data());
	//fclose(pairingParamFile);


	/*	fstream sysParamFStream ((char*)sysParamFileStr.data(),ios::in);
	while(sysParamFStream >> typeStr)
	  {
		if(typeStr == "n") {sysParamFStream >> n;continue;}
		if(typeStr == "t") {sysParamFStream >> t;continue;}
		if(typeStr == "U") {
		sysParamFStream >> strU;
		continue;
      }
    }
	sysParamFStream.close();*/

    //const pairing_t p = param.get_Pairing();
	const Pairing &e = param.get_Pairing();
	G1 U = param.get_U();
	

	Zr five(e,(long int)5);
	Zr six(e,(long int)6);
	Zr zero(e,(long int)1);


	//    element_t five;
	//    element_init_Zr(five, e);
	//    element_set_si(five, 5);

    Polynomial a, b(e,0,five), c(e,3), d(e,1,five), f(e,2,six,five);
	BiPolynomial a1,b1(e,0,five), c1(e,4), d1(e,2,five);

    //a1.dump(stdout, "a1");
    //b1.dump(stdout, "b1");
    //c1.dump(stdout, "c1");
    d1.dump(stdout, "d1");
	d1.getCoeff(0,0).dump(stdout, "d1(0,0)");
	printf("Degree %d",d1.degree());
    //d1 = d1;
    //d1.dump(stdout, "d=d");

    //element_t cf;
    //element_init_Zr(cf, e);
	//Zr cf(e);
	//printf("f");
    //for (int i=0; i<=5; ++i) {
	//cf = f.getCoeff(i);
	//cf.dump(stdout,NULL,16);
    //}
	//vector<Zr> vec_c = c.getCoeffs();
	//Polynomial tmp_c(vec_c);
	//tmp_c.dump(stdout, "tmp_c");

	//Polynomial ans = b*d;
	Polynomial p1 = c1(five);    
	Polynomial p2 = c1(six);    
	Zr ans1 = p1(six);
	Zr ans2 = p2(five);
	//b.dump(stdout, "b");
    //d.dump(stdout, "d");
	ans1.dump(stdout, "c1(5,6)");
	ans2.dump(stdout, "c1(6,5)");

    /*
	BiPolynomial f1 = b1;
    f1.dump(stdout, "f=b");

    BiPolynomial diff = d1 - b1;
    diff.dump(stdout, "diff");

    BiPolynomial polyzero = d1 - d1;
    polyzero.dump(stdout, "zero");

    BiPolynomial rediff = d1 - diff;
    rediff.dump(stdout, "rediff");

    polyzero -= rediff;
    polyzero.dump(stdout, "zero-rediff",10);
    polyzero -= polyzero;
    polyzero.dump(stdout, "zero-zero");

    rediff += rediff;
    rediff.dump(stdout, "rediff+rediff");
	*/

	/*
    // Pick four random indices for interpolation
	Zr indices[4], coeffs[4];
    for (int i=0;i<4;++i) {
	  coeffs[i] = Zr(e);
	  indices[i] = Zr(e, true);
    }
	printf("Index\n");
	for (int i=0;i<4;++i) {indices[i].dump(stdout, NULL, 10);}
    // Pick a random target
	Zr alpha(e,(long int)0);
	printf("alpha: "); alpha.dump(stdout, NULL, 10);

    // Get the Lagrange coefficients

    lagrange_coeffs(4, coeffs, indices, alpha);
	printf("Coeffs:\n");
	for (int i=0;i<4;++i) {
	  coeffs[i].dump(stdout, NULL, 10);
	}

    // Pick a random polynomial of degree 3
    Polynomial lpoly(e,3);
	G1 A[4];
    lpoly.dump(stdout, "lpoly", 10);

	G1 tmp;
	tmp = param.get_U();
	for (int i=0;i<4;++i) {
	  A[i] = U^lpoly.getCoeff(i);
	}

    // Compute the shares at the given indices
	G1 shares[4];
	Zr fi[4], fialpha(e,(long int)0), fialpha_real;
    for (int i=0;i<4;++i) {
	  fi[i] = lpoly(indices[i]);
	  shares[i] = tmp^(fi[i]);
    }

	//Verify shares
	G1 lhs(e,true), rhs(e,true);
	lhs = shares[2];
	Zr j = indices[2];
	for (int k=0;k<4;++k) {
	  Zr k_zr(e, (long int)k);
	  rhs *= A[k]^(j^k_zr);
	}
	if(lhs==rhs) 
	  cout<<"Equal"<<endl;
	else 
	  cout<<"Unequal"<<endl;

    // Reconstruct the poly at alpha using Lagrange
	G1 falpha(e);
    falpha = lagrange_apply(4, coeffs, shares);


	G1 falpha_real(e);
    fialpha_real = lpoly(alpha);
	falpha_real = tmp^fialpha_real;

    // See if they're the same
	falpha.dump(stdout,"falpha");
	falpha_real.dump(stdout,"falpha_real");
	
	for (size_t i = 0; i <4; ++i) {
	  fialpha += fi[i]*coeffs[i]; 
	}
	fialpha.dump(stdout, "fialpha ", 10);
	fialpha_real.dump(stdout, "fialpha_real ", 10);
	*/
}
