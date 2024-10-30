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

#include "insn_queue.h"
#include "introspection.h"
#include "ptrace.h"

#include <assert.h>
#include <stdio.h>

/** PID of target process in which we will execute the instructions.  */
static int remote_pid;

/** @brief Interpret WRITE instruction.
 *
 * @param insn    Instruction to interpet. Must be a WRITE instruction.
 *
 * @return        Size of interpreted instruction.
 */
int
insn_interpret_write(struct ulp_insn *insn)
{
  int pid = remote_pid; // Pass process pid.
  struct ulp_insn_write *winsn = (struct ulp_insn_write *)insn;
  if (write_bytes_ptrace(winsn->bytes, winsn->n, pid, winsn->address)) {
    return -1;
  }

  return insn->size;
}

/** @brief Get the instruction queue on remote process.
 *
 * This function will get the instruction queue on `queue_adddr` of process
 * with pid = `pid` that is on `queue_addr` and store it on the passed `queue`
 * object.
 *
 * @param queue       Queue object to write to.
 * @param queue_addr  Address of the queue on the remote process.
 * @parma pid         Pid of the remote process.
 *
 * @return            0 if success, anything else otherwise.
 */
static int
insnq_get_from_remote_process(insn_queue_t *queue, Elf64_Addr queue_addr,
                              int pid)
{
  memset(queue, 0, sizeof(*queue));
  uintptr_t bias = offsetof(insn_queue_t, buffer);

  /* Read first variables first.  */

  if (read_memory(queue, bias, pid, queue_addr)) {
    WARN("pid %d: unable to read remote queue.", pid);
    return EINSNQ;
  }

  /* Check queue version.  */
  if (queue->version > INSNQ_CURR_VERSION) {
    DEBUG("pid %d: ULP tool is too old, queue version is %d\n", pid,
          queue->version);
    return EOLDULP;
  }

  /* Then read just enough bytes of the queue to reduce ptrace band.  */
  uint32_t size = queue->size;
  if (size == 0) {
    return 0;
  }
  if (size > INSN_BUFFER_MAX) {
    WARN("pid %d: invalid insn queue size.", pid);
    return EINSNQ;
  }
  return read_memory((char *)queue + bias, size, pid, queue_addr + bias);
}

/** @brief Update the instruction queue on the remote process.
 *
 * This function will update the remote process queue, basically reseting it
 * for the next patch.
 *
 * @param queue       Queue object.
 * @param queue_addr  Address of the queue on the remote process to write to.
 * @parma pid         Pid of the remote process.
 *
 * @return            0 if success, anything else otherwise.
 */
static int
insnq_update_remote(insn_queue_t *queue, Elf64_Addr queue_address, int pid)
{
  Elf64_Addr size_addr, num_insns_addr;

  queue->size = 0;
  queue->num_insns = 0;

  size_addr = queue_address + offsetof(struct insn_queue, size);
  num_insns_addr = queue_address + offsetof(struct insn_queue, num_insns);

  if (write_bytes(&queue->size, sizeof(typeof(queue->size)), pid, size_addr)) {
    return EINSNQ;
  }

  if (write_bytes(&queue->num_insns, sizeof(typeof(queue->num_insns)), pid,
                  num_insns_addr)) {
    return EINSNQ;
  }

  return 0;
}

int
insnq_get_version(struct ulp_process *process)
{
  struct ulp_dynobj *libpulp_dynobj = process->dynobj_libpulp;
  int version = libpulp_dynobj->insn_queue_version;

  /* Check if we already have a version.  */
  if (version > 0) {
    return version;
  }

  /* Read remote process to get it.  */
  Elf64_Addr queue_addr = libpulp_dynobj->insn_queue;

  if (queue_addr == 0) {
    return 0;
  }

  if (read_memory(&version, sizeof(int), process->pid, queue_addr)) {
    return 0;
  }

  libpulp_dynobj->insn_queue_version = version;
  return version;
}

bool
insnq_check_compatibility(struct ulp_process *process)
{
  Elf64_Addr queue_addr = process->dynobj_libpulp->insn_queue;
  if (queue_addr == 0) {
    /* No queue means old libpulp, which we currently support.  */
    return true;
  }

  int version = insnq_get_version(process);
  if (version > INSNQ_CURR_VERSION) {
    return false;
  }

  return true;
}

static int
insnq_interpret_from_process_(int pid, Elf64_Addr queue_addr)
{
  static insn_queue_t queue;

  if (queue_addr == 0) {
    /* Libpulp is old and do not have a instruction queue.  */
    return EOLDLIBPULP;
  }

  /* Set global pid variable for this module.  */
  remote_pid = pid;

  ulp_error_t ret = insnq_get_from_remote_process(&queue, queue_addr, pid);
  if (ret) {
    WARN("pid %d: unable to retrieve instruction queue from process.", pid);
    return ret;
  }

  /* Make sure that the queue we got makes sense.  */
  if (queue.size > INSN_BUFFER_MAX) {
    WARN("pid %d: invalid insn queue size.", pid);
    return EINSNQ;
  }

  if (insnq_interpret(&queue)) {
    WARN("pid %d: interpret failure.", pid);
    return EINSNQ;
  }

  if (insnq_update_remote(&queue, queue_addr, pid)) {
    WARN("pid %d: unable to reset queue.", pid);
    return EINSNQ;
  }

  remote_pid = 0;
  return 0;
}

/** @brief Retrieve instruction queue from remote process and interpret them.
 *
 * This function will retrieve the remote instruction queue in the process
 * pointed by `process`, interpret it, and clean the queue afterwards.
 * for the next patch.
 *
 * NOTE: This function is not thread safe.
 *
 * @param process     Target process.
 * @return            0 if success, anything else otherwise.
 */
int
insnq_interpret_from_process(struct ulp_process *process)
{
  int pid = process->pid;
  Elf64_Addr queue_addr = process->dynobj_libpulp->insn_queue;

  return insnq_interpret_from_process_(pid, queue_addr);
}
