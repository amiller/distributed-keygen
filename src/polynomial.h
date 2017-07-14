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



#ifndef __POLYNOMIAL_H__
#define __POLYNOMIAL_H__

#include <vector>
#include "systemparam.h"

using namespace std;

class Polynomial {
    public:
	// Create the zero polynomial
	Polynomial() {}
	
	// Create a random polynomial of degree t >= 0
	Polynomial(const SystemParam &sys, unsigned int t);

	// Create a random polynomial of degree t with the given
	// constant term
	Polynomial(const SystemParam &sys, unsigned int t, const Zr& term);

	// Create a random polynomial f of degree t with f(index) = term 
	Polynomial(const SystemParam &sys, unsigned int t, const Zr& index, 
			   const Zr& term);

    // Create a polynomial from the a coefficient vector
    Polynomial(const vector<Zr> coeffs);

    //Deserialization
    //  Polynomial(const SystemParam& sys, const unsigned char* buf, 
	//		   size_t len);

	// Copy constructor
	Polynomial(const Polynomial &p);

	// Destructor
	~Polynomial();

	// Set a polynomial to zero
	void zero();

    //toString
    //string toString() const;

	// Assignment operators: be sure to test for self-assignment and
	// self-modification  (i.e. f = f or f += f)
	Polynomial& operator=(const Polynomial &rhs);
	Polynomial& operator+=(const Polynomial &rhs);
	Polynomial& operator-=(const Polynomial &rhs);
	Polynomial& operator*=(const Polynomial &rhs);

	// Non-assignment operators
	const Polynomial operator+(const Polynomial &rhs) const {
	    return Polynomial(*this) += rhs;
	}
	const Polynomial operator-(const Polynomial &rhs) const {
	    return Polynomial(*this) -= rhs;
	}
	const Polynomial operator*(const Polynomial &rhs) const {
	    return Polynomial(*this) *= rhs;
	}

	// Extract the coefficient of x^i into the (already initialized)
	// const Zr coeff
	const Zr getCoeff(unsigned int i) const;

    //Get the coefficient vector
    const vector<Zr> getCoeffs() const{return coeffs;}

	// Apply a polynomial at a point x using Horner's rule
	//const Zr apply(const Zr &x) const{};
    const Zr operator()(const Zr &x) const;

	// Get the degree of the polynomial (-1 for the zero polynomial)
	int degree() const { return coeffs.size() - 1; }
	
	// Dump the polynomial to stdout
	void dump(FILE *f, char *label = NULL, unsigned short base = 16) const;

    private:
	// Helper function for operators =, +=, -=
	Polynomial& merge(const Polynomial &rhs,
	    void(*mfunc)(Zr&, const Zr));

	// The coefficients; coeffs[i] is the degree i term
	vector<Zr> coeffs;
};

#endif
