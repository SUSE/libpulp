/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2021 SUSE Software Solutions GmbH
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

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md4.h"

#define BYTE_LENGTH 8
#define BLOCK_LENGTH (512 / BYTE_LENGTH)
#define BLOCK_PADDING (448 / BYTE_LENGTH)
#define SIZE_FIELD (BLOCK_LENGTH - BLOCK_PADDING)

/*
 * Calculates the MD4 of INPUT, which is LENGTH bytes long. Allocates memory
 * for the result and returns a pointer to it, or NULL on error.
 *
 * The implementation is based on the English description of the algorithm
 * provided by IETF RFC 1320 (https://tools.ietf.org/html/rfc1320).
 */
uint8_t *
MD4(char *input, uint64_t length)
{
  char *buffer;
  char *bufptr;

  uint64_t total;
  uint64_t zeros;

  uint32_t AA;
  uint32_t BB;
  uint32_t CC;
  uint32_t DD;

  /* Words for input parsing. */
  uint32_t X[16];

  /*
   * Digest state variables.
   *
   * MD4 specifies these variables as 32-bits words. However, the reference
   * implementation uses the unsigned long int type, which translates to
   * 64-bits on some architectures. This function sticks with 32-bits words,
   * even though it yields different results (when compared to the reference
   * implementation).
   */
  uint32_t A;
  uint32_t B;
  uint32_t C;
  uint32_t D;

  /* The output is the full set of state variables, expressed in bytes. */
  uint8_t *result;
  uint8_t *resptr;

  /*
   * Tie the width of the length parameter to the width of the size field
   * as specified in the RFC.
   */
  _Static_assert(sizeof(length) == SIZE_FIELD,
                 "The length of a block does not match the RFC");

  /*
   * Calculate the total number of bytes in the message after padding, starting
   * with the size of the input, which is already expressed in bytes.
   */
  total = length;

  /*
   * Even though MD4 expresses lengths in bits, this function operates on full
   * bytes, thus the mandatory padding of one bit becomes a mandatory padding
   * of one byte (b'1 becomes 0x80).
   */
  total = total + 1;

  /*
   * Likewise, since the granularity of the data is one byte, this function
   * also performs zero padding in byte-sized chunks, so count the number of
   * required zeroed bytes, then add it to the total data size.
   */
  zeros = total % BLOCK_LENGTH;
  if (zeros <= BLOCK_PADDING)
    zeros = BLOCK_PADDING - zeros;
  else
    zeros = BLOCK_LENGTH - (zeros - BLOCK_PADDING);
  total = total + zeros;

  /*
   * Finally, the last block gets padded with the message size. The message
   * size field has fixed length, so simply add it (in bytes, as usual).
   */
  total = total + SIZE_FIELD;

  /* Copy input into new buffer. */
  buffer = malloc(total);
  if (buffer == NULL) {
    warn("unable to allocate memory: %s", strerror(errno));
    return NULL;
  }
  memset(buffer, 0, total);
  memcpy(buffer, input, length);

  /*
   * Add padding (zero padding is skipped, because the buffer has already been
   * fully initialized to zero, with memset, above).
   */
  *(buffer + length) = 0x80;

  /*
   * Fill in the message size field in little-endian order. Length is first
   * multiplied by BYTE_LENGTH, because length is expressed in bytes, but the
   * message size field is expressed in bits.
   */
  for (int i = 0; i < SIZE_FIELD; i++) {
    *(buffer + length + 1 + zeros + i) =
        ((length * BYTE_LENGTH) >> (BYTE_LENGTH * i));
  }

  /*
   * Initial state of the 4-word buffer. It is unfortunate that the MD4
   * specification displays these sequences as if the contents of the variable
   * had been saved to memory in little-endian order.
   */
  A = 0x67452301;
  B = 0xefcdab89;
  C = 0x98badcfe;
  D = 0x10325476;

  /* Process the whole message, one block at a time. */
  bufptr = buffer;
  for (uint64_t i = 0; i < (total / BLOCK_LENGTH); i++) {

    /* Read 16 words (4-bytes each) from the padded message. */
    for (int j = 0; j < 16; j++) {
      X[j] = 0;

      /* Read 4 bytes in little-endian order to make up a work. */
      for (int k = 0; k < 4; k++) {
        X[j] = X[j] << BYTE_LENGTH;
        X[j] = X[j] | (0x00ff & *(bufptr + (3 - k)));
      }
      bufptr += 4;
    }

    /* Save previous state */
    AA = A;
    BB = B;
    CC = C;
    DD = D;

    /* Round 1. */
#define F(x, y, z) ((x & y) | ((~x) & z))
#define R1(A, B, C, D, i, s) \
  { \
    A = (A + F(B, C, D) + X[i]); \
    A = (A << s) | (A >> (32 - s)); \
  }
    /* clang-format off */
    R1(A, B, C, D,  0,  3);
    R1(D, A, B, C,  1,  7);
    R1(C, D, A, B,  2, 11);
    R1(B, C, D, A,  3, 19);
    R1(A, B, C, D,  4,  3);
    R1(D, A, B, C,  5,  7);
    R1(C, D, A, B,  6, 11);
    R1(B, C, D, A,  7, 19);
    R1(A, B, C, D,  8,  3);
    R1(D, A, B, C,  9,  7);
    R1(C, D, A, B, 10, 11);
    R1(B, C, D, A, 11, 19);
    R1(A, B, C, D, 12,  3);
    R1(D, A, B, C, 13,  7);
    R1(C, D, A, B, 14, 11);
    R1(B, C, D, A, 15, 19);
    /* clang-format on */
#undef R1
#undef F

    /* Round 2. */
#define G(x, y, z) ((x & y) | (x & z) | (y & z))
#define R2(A, B, C, D, i, s) \
  { \
    A = (A + G(B, C, D) + X[i] + 0x5A827999); \
    A = (A << s) | (A >> (32 - s)); \
  }
    /* clang-format off */
    R2(A, B, C, D,  0,  3);
    R2(D, A, B, C,  4,  5);
    R2(C, D, A, B,  8,  9);
    R2(B, C, D, A, 12, 13);
    R2(A, B, C, D,  1,  3);
    R2(D, A, B, C,  5,  5);
    R2(C, D, A, B,  9,  9);
    R2(B, C, D, A, 13, 13);
    R2(A, B, C, D,  2,  3);
    R2(D, A, B, C,  6,  5);
    R2(C, D, A, B, 10,  9);
    R2(B, C, D, A, 14, 13);
    R2(A, B, C, D,  3,  3);
    R2(D, A, B, C,  7,  5);
    R2(C, D, A, B, 11,  9);
    R2(B, C, D, A, 15, 13);
    /* clang-format on */
#undef R2
#undef G

    /* Round 3 */
#define H(x, y, z) (x ^ y ^ z)
#define R3(A, B, C, D, i, s) \
  { \
    A = (A + H(B, C, D) + X[i] + 0x6ED9EBA1); \
    A = (A << s) | (A >> (32 - s)); \
  }
    /* clang-format off */
    R3(A, B, C, D,  0,  3);
    R3(D, A, B, C,  8,  9);
    R3(C, D, A, B,  4, 11);
    R3(B, C, D, A, 12, 15);
    R3(A, B, C, D,  2,  3);
    R3(D, A, B, C, 10,  9);
    R3(C, D, A, B,  6, 11);
    R3(B, C, D, A, 14, 15);
    R3(A, B, C, D,  1,  3);
    R3(D, A, B, C,  9,  9);
    R3(C, D, A, B,  5, 11);
    R3(B, C, D, A, 13, 15);
    R3(A, B, C, D,  3,  3);
    R3(D, A, B, C, 11,  9);
    R3(C, D, A, B,  7, 11);
    R3(B, C, D, A, 15, 15);
    /* clang-format on */
#undef R3
#undef H

    /* Final additions. */
    A = A + AA;
    B = B + BB;
    C = C + CC;
    D = D + DD;
  }

  free(buffer);

  /* Allocate space for the whole digest, i.e. 4 32-bits words. */
  _Static_assert(MD4_LENGTH == 16,
                 "The length of the digest does not match the RFC");
  result = malloc(MD4_LENGTH);
  if (result == NULL) {
    warn("unable to allocate memory: %s", strerror(errno));
    return NULL;
  }

  resptr = result;
#define APPEND(item, buffer) \
  { \
    for (int i = 0; i < 4; i++) { \
      *(resptr) = (uint8_t)((item >> (BYTE_LENGTH * i)) & 0x0ff); \
      resptr++; \
    } \
  }
  APPEND(A, resptr);
  APPEND(B, resptr);
  APPEND(C, resptr);
  APPEND(D, resptr);
#undef APPEND

  return result;
}
