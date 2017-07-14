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



#include "polynomial.h"

// Create a random polynomial of degree t >= 0
Polynomial::Polynomial(const SystemParam &sys, unsigned int t)
{
    for (unsigned int i=0; i<=t; ++i) {
	  Zr randcoeff(sys.get_Pairing(),true);
	  coeffs.push_back(randcoeff);
    }
}

// Create a random polynomial of degree t with the given
// constant term
Polynomial::Polynomial(const SystemParam &sys, unsigned int t, const Zr& term)
{
  Zr constterm(term);
  coeffs.push_back(constterm);

  for (unsigned int i=1; i<=t; ++i) {
	Zr randcoeff(sys.get_Pairing(),true);
	coeffs.push_back(randcoeff);
  }
}
	
// Create a random polynomial f of degree t with f(index) = term 
Polynomial::Polynomial(const SystemParam &sys, unsigned int t, const Zr& index, 
					   const Zr& term)
{
  for (unsigned int i=0; i<=t; ++i) {
	Zr randcoeff(sys.get_Pairing(),true);
	coeffs.push_back(randcoeff);
  }
  Zr val = this->operator()(index);
  coeffs[0] = coeffs[0] - val + term;
}

// Create a polynomial from the a coefficient vector
Polynomial::Polynomial(const vector<Zr> coeffs)
{
    vector<Zr>::const_iterator iter;
    for(iter = coeffs.begin(); iter != coeffs.end(); iter++) {
	  Zr copycoeff(*iter);
	  this->coeffs.push_back(copycoeff);
    }
}



// Copy constructor
Polynomial::Polynomial(const Polynomial &p)
{
    vector<Zr>::const_iterator iter;
    for(iter = p.coeffs.begin(); iter != p.coeffs.end(); iter++) {
	  Zr copycoeff(*iter);
	  coeffs.push_back(copycoeff);
    }
}

// Destructor
Polynomial::~Polynomial()
{
  zero();
}

// Set a polynomial to zero
void Polynomial::zero()
{
  coeffs.clear();
}

static void copy_elt(Zr& a, const Zr b) {a = b;}
static void add_elt(Zr& a, const Zr b) {a += b;}
static void sub_elt(Zr& a, const Zr b) {a -= b;}

Polynomial& Polynomial::merge(const Polynomial &rhs,
	void(*mfunc)(Zr&, const Zr))
{
    // Make sure the degree is big enough (pad with 0s)
    size_t rsize = (size_t) rhs.degree()+1;
    while(coeffs.size() < rsize) {
	  Zr zerocoeff;
	  //Make a zero element
	  zerocoeff = rhs.getCoeff(0) + (rhs.getCoeff(0)).inverse(true);
	  coeffs.push_back(zerocoeff);
    }
    for(size_t i = 0; i < rsize; ++i) {
	  mfunc(coeffs[i], rhs.getCoeff(i));
    }
    // See if any leading coeffs are 0
    size_t mysize = coeffs.size();
    while (mysize > 0) {
	  --mysize;
	  if (coeffs[mysize].isIdentity(true)) {
		coeffs.pop_back();
	  } else break;
    }
    return *this;
}

Polynomial& Polynomial::operator=(const Polynomial &rhs)
{
    if (this == &rhs) return *this;
    zero();
    return merge(rhs, copy_elt);
}

Polynomial& Polynomial::operator+=(const Polynomial &rhs)
{
    return merge(rhs, add_elt);
}

Polynomial& Polynomial::operator-=(const Polynomial &rhs)
{
    return merge(rhs, sub_elt);
}

Polynomial& Polynomial::operator*=(const Polynomial &rhs)
{
  //Inefficient Implementation
  //FUTURE WORK: FFT-based fast multiplication
  vector<Zr> tmpcoeffs;
  coeffs.swap(tmpcoeffs);//copy coefficents to tmpcoeffs
  
size_t rsize = (size_t) rhs.degree() + 1;
  while(rsize) {
	--rsize;
	//Make a zero element and insert it into the result vector
	Zr zerocoeff;
	zerocoeff = rhs.coeffs[0] + rhs.coeffs[0].inverse(true);
	coeffs.insert(coeffs.begin(),1,zerocoeff);
	//this->dump(stdout, "result");
	vector<Zr> tmp;
	for (size_t i=0; i < tmpcoeffs.size(); ++i)
	  tmp.push_back(tmpcoeffs[i]*rhs.getCoeff(rsize));
	//result = (Polynomial(result) + Polynomial(tmp)).getCoeffs();
	(*this)+=Polynomial(tmp);
  }
  return *this;
}

// Extract the coefficient of x^i into the (already initialized)
// element_t coeff
const Zr Polynomial::getCoeff(unsigned int i) const
{
    if (i < coeffs.size())
	  return coeffs[i];
    else{
	  Zr tmp;
	  //Returning an unintialized element
	  return tmp;
	}
}

// Apply a polynomial at a point x using Horner's rule
const Zr Polynomial::operator()(const Zr &x) const
{
    Zr result(x);//to intialize as pairing is not available
	result -= result;//to make result zero

    size_t size = coeffs.size();
    while(size > 0){
	  --size;
	  Zr coeff(coeffs[size]);
	  result*=x;
	  result+=coeff;
    }
	return result;
}

void Polynomial::dump(FILE *f, char *label, unsigned short base) const
{
    if (label) fprintf(f, "%s: ", label);
    fprintf(f, "[ ");
    vector<Zr>::const_iterator iter;
    for(iter = coeffs.begin(); iter != coeffs.end(); iter++) {
	  (*iter).dump(f, NULL, base);
	  fprintf(f, " ");
    }
    fprintf(f, "]\n");
}
