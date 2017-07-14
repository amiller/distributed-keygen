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



#ifndef __LAGRANGE_H__
#define __LAGRANGE_H__

#include "PBC/PBC.h"
#include <vector>
// Compute Lagrange coefficients.
// indices is an array of element_t of length num, containing the
//     indices to compute over (members of a Zr ring)
// coeffs is an array of element_t of length num, containing initialized
//     element_t's (members of the same Zr ring).
// alpha is the target index (a member of the same Zr ring, usually 0)
//
// After this routine sets coeffs, it will be true that:
//
// \sum_{i=0}^{num-1} coeffs[i] * f(indices[i]) = f(alpha)
//
// for any polynomial f of degree at most num-1
const vector <Zr> lagrange_coeffs(const vector <Zr> indices, const Zr& alpha);
//void lagrange_coeffs(size_t num, Zr* coeffs, Zr* indices, const Zr& alpha);

// Apply Lagrange coefficients.
// coeffs is the array of element_t of length num set by the above
//     function (members of a Zr ring)
// shares is an array of element_t of length num, containing the shares
//     to use in the reconstruction (members of any group)
// the reconstructed value is placed in falpha (a member of that same group)
//

//const G1 lagrange_apply(size_t num, Zr *coeffs, G1 *shares);
const G1 lagrange_apply(const vector <Zr> coeffs, const vector <G1> shares);
//For Zr
const Zr lagrange_apply(const vector <Zr> coeffs, const vector <Zr> shares);
#endif
