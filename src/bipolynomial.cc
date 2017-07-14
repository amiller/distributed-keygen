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



#include "bipolynomial.h"

// Create a random symmetric bivariate polynomial of degree t >= 0
BiPolynomial::BiPolynomial(const SystemParam &sys, unsigned int t)
{
  for (unsigned int i=0; i<=t; ++i){
	vector<Zr> row;
	coeffs.push_back(row);
  }
  for (unsigned int i=0; i<=t; ++i){
	  Zr randcoeff(sys.get_Pairing(),true);
	  coeffs[i].push_back(randcoeff);
	for (unsigned int j=i+1; j<=t; ++j){
	  Zr randcoeff(sys.get_Pairing(),true);
	  coeffs[i].push_back(randcoeff);
	  coeffs[j].push_back(randcoeff);
    }
  }
}

// Create a random symmetric bivariate polynomial of degree t with the given
// constant term
BiPolynomial::BiPolynomial(const SystemParam &sys, unsigned int t, const Zr& term)
{
  for (unsigned int i=0; i<=t; ++i){
	vector<Zr> row;
	coeffs.push_back(row);
  }
  for (unsigned int i=0; i<=t; ++i){
	  Zr randcoeff(sys.get_Pairing(),true);
	  coeffs[i].push_back(randcoeff);
	for (unsigned int j=i+1; j<=t; ++j){
	  Zr randcoeff(sys.get_Pairing(),true);
	  coeffs[i].push_back(randcoeff);
	  coeffs[j].push_back(randcoeff);
    }
  }
  //Replace random constant term with the provided one
  Zr constterm(term);
  coeffs[0][0] = constterm;
}
	
// Create a random symmetric bivariate polynomial f of degree t with f(index) = term 
// NOT CORRECTED AS NOT Required
/*
BiPolynomial::BiPolynomial(const SystemParam &sys, unsigned int t, const Zr& index, 
					   const Zr& term)
{
  for (unsigned int i=0; i<=t; ++i) {
	Zr randcoeff(sys.get_Pairing(),true);
	coeffs.push_back(randcoeff);
  }
  Zr val = this->operator()(index);
  coeffs[0] = coeffs[0] - val + term;
}
*/

// Copy constructor
BiPolynomial::BiPolynomial(const BiPolynomial &p)
{
    vector< vector<Zr> >::const_iterator iter2d;
    vector<Zr>::const_iterator iter1d;
    for(iter2d = p.coeffs.begin(); iter2d != p.coeffs.end(); ++iter2d){
	  vector<Zr> row;
	  for(iter1d = iter2d->begin(); iter1d != iter2d->end(); ++iter1d){
		Zr copycoeff(*iter1d);
		row.push_back(copycoeff);
	  }
	  coeffs.push_back(row);
    }
}

// Destructor
BiPolynomial::~BiPolynomial()
{
  zero();
}

// Set a polynomial to zero
void BiPolynomial::zero()
{
  coeffs.clear();
}

static void copy_elt(Zr& a, const Zr b) {a = b;}
static void add_elt(Zr& a, const Zr b) {a += b;}
static void sub_elt(Zr& a, const Zr b) {a -= b;}

BiPolynomial& BiPolynomial::merge(const BiPolynomial &rhs,
	void(*mfunc)(Zr&, const Zr))
{
    // Make sure the degrees are big enough (pad with 0s)
    size_t rsize = rhs.coeffs.size();
	Zr zero = rhs.coeffs[0][0] + (rhs.coeffs[0][0]).inverse(true);

    while(coeffs.size() < rsize) {
	  vector<Zr> zerorowcoeff;
	  while(zerorowcoeff.size() < rhs.coeffs[coeffs.size()].size()) {
	  //Make a zero element
		Zr tmp(zero);
		zerorowcoeff.push_back(zero);
	  }
	  coeffs.push_back(zerorowcoeff);
    }

    for(size_t i = 0; i < rsize; ++i) {
	  size_t csize = rhs.coeffs[i].size();
	  for(size_t j = 0; j < csize; ++j)
		mfunc(coeffs[i][j], rhs.coeffs[i][j]);
    }

    // See if any leading coeffs are 0
    size_t myrsize = coeffs.size();
	bool rowfound = false;
    while (myrsize > 0) {
	  --myrsize;
	  size_t mycsize = coeffs[myrsize].size();
	  while (mycsize > 0) {
		--mycsize;		
		if (coeffs[myrsize][mycsize].isIdentity(true)) {
		  coeffs[myrsize].pop_back();
		} else break;
	  }
	  if(coeffs[myrsize].empty()&&!rowfound)
		//Delect row only until you hit first non-empty row
		coeffs.pop_back();
	  else 
		rowfound = true;
	}
	return *this;
}

BiPolynomial& BiPolynomial::operator=(const BiPolynomial &rhs)
{
    if (this == &rhs) return *this;
    zero();
    return merge(rhs, copy_elt);
}

BiPolynomial& BiPolynomial::operator+=(const BiPolynomial &rhs)
{
    return merge(rhs, add_elt);
}

BiPolynomial& BiPolynomial::operator-=(const BiPolynomial &rhs)
{
    return merge(rhs, sub_elt);
}

// Extract the coefficient of x^i into the (already initialized)
// element_t coeff
const Zr BiPolynomial::getCoeff(unsigned int i, unsigned int j) const
{
  if (i < coeffs.size())
	if (j < coeffs[i].size())	  
	  return coeffs[i][j];
  Zr tmp;
  return tmp;	//Returning an unintialized element  
}

// Apply a bipolynomial at a point x using Horner's rule
const Polynomial BiPolynomial::apply(const Zr &x) const
{
    Polynomial result;
	Polynomial polyx = Polynomial(vector<Zr>(1,x));

    size_t size = coeffs.size();
    while(size > 0){
	  --size;
	  result*=polyx;
	  Polynomial row(coeffs[size]);
	  result+=row;
    }
	return result;
}

void BiPolynomial::dump(FILE *f, char *label, unsigned short base) const
{
    if (label) fprintf(f, "%s: ", label);
    fprintf(f, "[\n ");
    vector< vector <Zr> >::const_iterator iter2d;
    vector<Zr>::const_iterator iter;
    for(iter2d = coeffs.begin(); iter2d != coeffs.end(); ++iter2d) 
	{
	  for(iter = iter2d->begin(); iter != iter2d->end(); ++iter)
		{
		  (*iter).dump(f, NULL, base);
		  fprintf(f, " ");
		}
	  fprintf(f, "\n");
	}
    fprintf(f, "]\n");
}
