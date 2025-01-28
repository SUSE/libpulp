/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020-2021 SUSE Software Solutions GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * TODO: Extend the functions and parameters to cover more parameter
 * passing conventions of target platform ABIs.
 */

#include <stdio.h>

/*
 * According to the ABI for x86_64, the first to sixth parameters of the
 * POINTER or INTEGER classes are passed on registers, whereas the
 * seventh and subsequent parameters of the same class are passed on the
 * stack. This function has eight int parameters, which cover this
 * aspect of the ABI.
 *
 * NOTE: Once other platforms get supported by libpulp, this should be
 * reviewed and extended accordingly.
 */
void
int_params(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j)
{
  printf("%d-%d-%d-%d-%d-%d-%d-%d-%d-%d\n", a, b, c, d, e, f, g, h, i, j);
}

/*
 * According to the ABI for x86_64, the first to eigth parameters of the
 * SSE class are passed on vector registers (%xmm0 to %xmm7). Likewise,
 * parameters that fall into the SSEUP class use the same set of
 * registers. This function has ten float parameters, which cover this
 * aspect of the ABI.
 *
 * NOTE: Once other platforms get supported by libpulp, this should be
 * reviewed and extended accordingly.
 */
void
float_params(float a, float b, float c, float d, float e, float f, float g,
             float h, float i, float j)
{
  printf("%.1f-%.1f-%.1f-%.1f-%.1f-%.1f-%.1f-%.1f-%.1f-%.1f\n", a, b, c, d, e,
         f, g, h, i, j);
}
