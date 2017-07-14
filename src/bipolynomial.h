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



#ifndef __BIPOLYNOMIAL_H__
#define __BIPOLYNOMIAL_H__

#include "polynomial.h"

using namespace std;

class BiPolynomial {
    public:
	// Create the zero polynomial
	BiPolynomial() {}
	
	// Create a random polynomial of degree t >= 0
	BiPolynomial(const SystemParam &sys, unsigned int t);

	// Create a random polynomial of degree t with the given
	// constant term
	BiPolynomial(const SystemParam &sys, unsigned int t, const Zr& term);

	// Create a random polynomial f of degree t with f(index) = term 
	// NOT CORRECTED AS NOT Required
    //BiPolynomial(const SystemParam &sys, unsigned int t, const Zr& index, 
	//  const Zr& term) {}

	// Copy constructor
	BiPolynomial(const BiPolynomial &p);

	// Destructor
	~BiPolynomial();

	// Set a polynomial to zero
	void zero();

	// Assignment operators: be sure to test for self-assignment and
	// self-modification  (i.e. f = f or f += f)
	BiPolynomial& operator=(const BiPolynomial &rhs);
	BiPolynomial& operator+=(const BiPolynomial &rhs);
	BiPolynomial& operator-=(const BiPolynomial &rhs);

	// Non-assignment operators
	const BiPolynomial operator+(const BiPolynomial &rhs) const {
	    return BiPolynomial(*this) += rhs;
	}
	const BiPolynomial operator-(const BiPolynomial &rhs) const {
	    return BiPolynomial(*this) -= rhs;
	}

	// Extract the coefficient of x^iy^j into the (already initialized)
	// const Zr coeff
	const Zr getCoeff(unsigned int i, unsigned int j) const;

	// Apply a polynomial at a point (x,y) using Horner's rule
	const Polynomial apply(const Zr &x) const;
	const Polynomial operator()(const Zr &x) const{return apply(x);}

	// NOT IMPLEMENTED AS NOT Required
    //const Zr operator()(const Zr &x, const Zr &y) const{}

	// Get the degree of the polynomial (-1 for the zero polynomial)
	int degree() const { return coeffs.size() - 1; }
	
	// Dump the polynomial to stdout
	void dump(FILE *f, char *label = NULL, unsigned short base = 16) const;

    private:
	// Helper function for operators =, +=, -=
	BiPolynomial& merge(const BiPolynomial &rhs,
	    void(*mfunc)(Zr&, const Zr));

	// The coefficients; 
    //coeffs[i,j] is the term with degree i for x anf j for y
	vector< vector<Zr> > coeffs;
};

#endif
