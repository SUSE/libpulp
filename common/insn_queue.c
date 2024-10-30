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

#include "ulp_common.h"
#include "insn_queue.h"
#include "error_common.h"

#include <assert.h>
#include <stdio.h>

/** @brief Interpret a print instruction.
 *
 * @param insn    Instruction to interpet. Must be a print instruction.
 *
 * @return        Size of interpreted instruction.
 */
int
insn_interpret_print(struct ulp_insn *insn)
{
  struct ulp_insn_print *p_insn = (struct ulp_insn_print *)insn;

  printf("%s\n", p_insn->bytes);
  return insn->size;
}

/** @brief Interpret NOP instruction.
 *
 * @param insn    Instruction to interpet. Must be a NOP instruction.
 *
 * @return        Size of interpreted instruction (always 1 byte).
 */
int
insn_interpret_nop(struct ulp_insn *insn)
{
  return sizeof(*insn);
}

/* Writes are specific from libpulp and libpulp-tools:
 *  - On tools, use ptrace.
 *  - On libpulp, set text permission and use memcpy.
 */
int
insn_interpret_write(struct ulp_insn *insn);

/** Table of decoders.  Index must match the `enum ulp_insn_table` object.  */
static int (*decoders[ULP_NUM_INSNS])(struct ulp_insn *insn) = {
  insn_interpret_nop,
  insn_interpret_print,
  insn_interpret_write,
};

/** @brief Interpret the given instruction.
 *
 * This function will interpret the given instruction.
 *
 * @param insn      Instruction to interpret.
 *
 * @return          Size of instruction interpreted.
 */
int
insn_interpret(struct ulp_insn *insn)
{
  int index = (int)insn->type;
  return (decoders[index])(insn);
}

/** @brief Interpret the instructions in queue.
 *
 * Interpret all instructions inserted into the queue object.
 *
 * @param queue
 */
int
insnq_interpret(insn_queue_t *queue)
{
  int pc = 0; /* Like a CPU program counter.  */
  int num_insns_executed = 0;

  int size = queue->size;
  int num_insns = queue->num_insns;
  char *buffer = queue->buffer;

  while (num_insns_executed < num_insns) {
    struct ulp_insn *insn = (struct ulp_insn *)&buffer[pc];
    if (ulp_insn_valid(insn)) {
      pc += insn_interpret(insn);
      num_insns_executed++;
    }
    else {
      /* Abort if an invalid insn is received.  */
      WARN("insnq: invalid insn with opcode %d. Further insns will be "
           "ignored.", (int)insn->type);
      return EINSNQ;
    }
  }

  /* The pc should stop at the size of the queue.  */
  if (pc != size) {
    WARN("insnq: there are bytes left in the instruction queue");
    return EINSNQ;
  }

  /* Number of instructions should match what is in the queue.  */
  if (num_insns_executed != num_insns) {
    WARN("insnq: not all instructions executed");
    return EINSNQ;
  }

  return 0;
}
