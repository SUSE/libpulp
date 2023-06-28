/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2023 SUSE Software Solutions GmbH
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

#ifndef INSNQ_H
#define INSNQ_H

#include <stdbool.h>
#include <stdint.h>

/** Define a 2Mb buffer for holding the instructions list.  */
#define INSN_BUFFER_MAX (2 * 1024 * 1024)

/** Define the current version of the instruction queue.  */
#define INSNQ_CURR_VERSION 1

/** The ULP instruction queue.  This works as follows:
 * 1- Libpulp write instructions that should be executed on the `ulp` tool
 * side. The main reason why this exists is because some processes are launched
 * with systemd memory protection mechanism, and a way to circunvent that is to
 * ptrace from an external process.
 *
 * 2- the `ulp` tool interpret the instructions after libpulp finishes
 * executing the function from its side (__ulp_apply_patch, for example).
 */
struct insn_queue
{
  /** Version of the queue running.  */
  int version;

  /** Number of instructions in this queue.  */
  int num_insns;

  /** Size in bytes of content.  Must not be larger than INSN_BUFFER_MAX.  */
  int size;

  /** Here to force 8-byte alignment on the buffer.*/
  int _align;

  /** Buffer holding the instructions.  */
  char buffer[INSN_BUFFER_MAX];
};

/** Shorthand for the instruction queue object.  */
typedef struct insn_queue insn_queue_t;

extern insn_queue_t __ulp_insn_queue;

/** Type of instructions.  */
enum __attribute__((__packed__)) ulp_insn_type
{
  /** NOP instruction.  Nothing is done.  */
  ULP_INSN_NOP = 0,

  /** Print a message.  */
  ULP_INSN_PRINT = 1,

  /** Write into target process.  */
  ULP_INSN_WRITE,

  ULP_NUM_INSNS,
};

/** Common instruction object.  Holds the type as well the size of the
    instruction in bytes.  */
struct ulp_insn
{
  /** Type of instruction.  */
  enum ulp_insn_type type;

  /** Size of instruction.  Max size is 24 bits to fit into 4 bytes.  */
  int size : 24;
};

/** A print instruction.  Print the content hold in `bytes`.  */
struct ulp_insn_print
{
  /** Base object.  */
  struct ulp_insn base;

  /** Bytes holding the string.  */
  char bytes[];
};

/** A write instruction.  Writes into the address the amout of `n` bytes given
    in bytes into the target process.  */
struct ulp_insn_write
{
  /** Base object.  */
  struct ulp_insn base;

  /** Number of bytes.  */
  uint32_t n;

  /** Address to patch.  */
  uintptr_t address;

  /** Content.  */
  unsigned char bytes[];
};

/** @brief Check if instruction is valid.
 *
 * This function will check if given instruction is valid.
 *
 * @param insn     Instruction to check.
 * @return         true if valid, false otherwise.
 */
static inline bool
ulp_insn_valid(struct ulp_insn *insn)
{
  switch (insn->type) {
    case ULP_INSN_NOP:
    case ULP_INSN_PRINT:
    case ULP_INSN_WRITE:
      return true;
      break;

    default:
      return false;
  }
}

#endif /* INSNQ_H */
