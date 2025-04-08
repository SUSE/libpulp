/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2025 SUSE Software Solutions GmbH
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

#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <stddef.h>
#include <string.h>
#include <limits.h>

#include "config.h"
#include "error.h"
#include "msg_queue.h"
#include "ulp.h"

#include "arch/powerpc64le/arch_common.h"

/* clang-format off */

/** Size of each instructions, in bytes.  */
#define INSN_SIZE 4

/** Declare ulp_prologue routine, defined in ulp_prologue.S.  */
extern unsigned char ulp_prologue[];

/** Size of the above object.  */
extern unsigned int ulp_prologue_size;

/** The NOP instruction.  */
static const unsigned char gNop[] = { 0x00, 0x00, 0x00, 0x60 };

/** Generate a branch (b) instruction according to offset.  */
static uint32_t
generate_branch_to_prologue(int32_t offset)
{
  return (offset & 0x00FFFFFF) | (0x4B << 24);
}

#define WITH_OFFSET(x) (-(INSN_SIZE * PRE_NOPS_LEN + (offset)))
#define WITHOUT_OFFSET WITH_OFFSET(0)

/* clang-format on */

/** @brief Copy the ulp prologue layout into the function to be patched's
 * prologue
 *
 * This function copies the new code prologue into the old function prologue
 * in order to redirect the execution to the new function.
 *
 */
static void
ulp_patch_prologue_layout(void *old_fentry, void *new_fentry, const unsigned char *prologue, int len)
{
  (void) len;

  /* Create a copy of the prologue.  */
  unsigned char prolog[ulp_prologue_size];
  memcpy(prolog, prologue, sizeof(prolog));

  unsigned char new_fentry_bytes[sizeof(void*)];
  memcpy(new_fentry_bytes, &new_fentry, sizeof(new_fentry_bytes));

  /* Patch the code with the address of the function we want to be redirected.  */
  prolog[32]  = new_fentry_bytes[6];
  prolog[33]  = new_fentry_bytes[7];
  prolog[36]  = new_fentry_bytes[4];
  prolog[37]  = new_fentry_bytes[5];
  prolog[40]  = new_fentry_bytes[2];
  prolog[41]  = new_fentry_bytes[3];
  prolog[44]  = new_fentry_bytes[0];
  prolog[45]  = new_fentry_bytes[1];

  /* Point to the prologue.  */
  char *fentry_prologue = old_fentry - INSN_SIZE * PRE_NOPS_LEN;
  memwrite(fentry_prologue, prolog, INSN_SIZE * PRE_NOPS_LEN);
}

/** @brief Get the offset of the NOP instruction.
 *
 * Some function do not have a global entry point prologue, that means
 * the NOP instruction is placed at the same address as the calling point.
 * We have to figure out which case we are handling.
 */
static int
get_branch_offset(void *fentry)
{
  int valid_offsets[] = {
    0, // NOP located at the calling point.
    8, // func with global entry point, NOP is located 8 bytes after it.
  };

  for (unsigned i = 0; i < ARRAY_LENGTH(valid_offsets); i++) {
    int offset = valid_offsets[i];
    void *fpos = (void *) ((char *)fentry + offset);

    /* Generate a branch instruction to the begining of the NOP prologue.  */
    uint32_t branch = generate_branch_to_prologue(WITH_OFFSET(offset));

    /* There are two cases we must check:
        - Function not livepatched: have a NOP insn here.
        - Function is livepatched: have a B (branch) insn here.  */
    if (memcmp(fpos, gNop, sizeof(gNop)) == 0 ||
        memcmp(fpos, &branch, sizeof(branch)) == 0) {
      return offset;
    }
  }

  /* Not valid.  */
  return -INT_MAX;
}

/** @brief skip the ulp prologue.
 *
 * When a function gets live patch, the nops at its entry point get replaced
 * with a backwards-jump to a small segment of code that redirects execution to
 * the new version of the function. However, when all live patches to said
 * function are deactivated (because the live patches have been reversed), the
 * need for the backwards-jump is gone.
 *
 * The following function replaces the backwards-jump with nops, thus making
 * the target function look like it did at the beginning of execution, i.e.
 * without live patches.
 *
 * @param fentry        Address to write the prologue to.
 */
static int
ulp_skip_prologue(void *fentry)
{
  int offset = get_branch_offset(fentry);
  if (offset < 0) {
    return ENOPATCHABLE;
  }

  unsigned char *dst = (unsigned char *)fentry + get_branch_offset(fentry);
  memwrite(dst, gNop, sizeof(gNop));

  return 0;
}

/** @brief Insert the backwards jump to the NOP prologue.
 *
 * When a function gets live patch, the nops at its entry point get replaced
 * with a backwards-jump to a small segment of code that redirects execution to
 * the new version of the function. This function does exactly this.
 *
 * @param fentry        Address to write the prologue to.
 */
static int
ulp_patch_addr_trampoline(void *old_fentry)
{
  int offset = get_branch_offset(old_fentry);
  if (offset < 0) {
    return ENOPATCHABLE;
  }

  uint32_t branch = generate_branch_to_prologue(WITH_OFFSET(offset));
  char *dst = (char *)old_fentry + offset;
  memwrite(dst, &branch, sizeof(branch));

  return 0;
}


/** @brief Actually patch the old function with the new function
 *
 * This function will finally patch the old function pointed by `old_faddr`
 * with the one pointed by `new_faddr`, replacing the ulp NOP prologue with
 * the intended content to redirect to the new function.
 *
 * @param old_faddr     Address of the old function.
 * @param new_faddr     Address of the new function.
 * @param enable        False to disable the redirection to the new function.
 *
 * @return              0 if success, error code otherwise.
 */
int
ulp_patch_addr(void *old_faddr, void *new_faddr, int enable)
{
  unsigned char *dst = (unsigned char *) old_faddr;

  int ret = 0;

  if (enable) {
    ulp_patch_prologue_layout(dst, new_faddr, ulp_prologue, INSN_SIZE * ULP_NOPS_LEN);
    ret = ulp_patch_addr_trampoline(dst);
  } else {
    ret = ulp_skip_prologue(dst);
  }

  return ret;
}


/** Key used for setuping a thread-cancel destructor.  */
static pthread_key_t ulp_key;

/** pthread_once to indicate that our destructor was installed.  */
static pthread_once_t ulp_once_control = PTHREAD_ONCE_INIT;

/** Destructor for mmap ulp_stack buffer.  Called when a thread is killed or
    exited.  */
static void
ulp_stack_cleanup(void *)
{
  if (ulp_stack[ULP_STACK_PTR] != 0UL) {
    int ret = munmap((void *)ulp_stack[ULP_STACK_PTR],
                     ulp_stack[ULP_STACK_REAL_SIZE]);
    libpulp_assert(ret == 0);

    ulp_stack[ULP_STACK_PTR] = 0;
    ulp_stack[ULP_STACK_REAL_SIZE] = 0;
    ulp_stack[ULP_STACK_USED_SIZE] = 0;

  }
}

/** Setup a destructor for the mmap buffer in ulp_stack.  */
static void
ulp_pthread_key_init(void)
{
  int ret = pthread_key_create(&ulp_key, ulp_stack_cleanup);
  libpulp_assert(ret == 0);
}

/** @brief Helper function called to allocate the ulp_stack
 *
 * In the ulp prologue in ppc64le we need to save the TOC and LR registers
 * before redirect into a new function, and we store it in a stack allocated
 * by mmap.  This routine does exactly this.
 *
 * @return  The address of the ulp_stack object.
 */
void *ulp_stack_helper(void)
{
  /* Comparison should have been done in trampoline_routine (this function
     caller), so just assert it here.  */
  libpulp_assert(ulp_stack[ULP_STACK_REAL_SIZE] <= ulp_stack[ULP_STACK_USED_SIZE]);

  /* NOTE: be careful with the functions we call here.  If we call a certain
     function here, then we may have problems livepatching it.  */

  /* Storage depleted, allocate a new stack.  */
  unsigned long old_size = ulp_stack[ULP_STACK_REAL_SIZE];

  /* Setup new stack size. Increase by PAGESIZE to be optimal */
  ulp_stack[ULP_STACK_REAL_SIZE] += sysconf(_SC_PAGESIZE);
  ulp_stack[ULP_STACK_REAL_SIZE] *= 2;

  void *old = (void *)ulp_stack[ULP_STACK_PTR];

  /* Allocate buffer for our stack.  */
  void *new = (void*) syscall(SYS_mmap, NULL, ulp_stack[ULP_STACK_REAL_SIZE],
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (new == (void *) -1) {
    /* In this case the system is out of memory...  And there is nothing
       we can do.  */
    libpulp_crash("libpulp: mmap returned -1, application can not continue\n");
    return ulp_stack;
  }

  /* In case we have a previous allocated buffer, then copy this.  */
  if (old != NULL) {

    /* We can't use memcpy here, hence do our thing.  */
    unsigned char *restrict oldp = old;
    unsigned char *restrict newp = new;
    unsigned long s = old_size;

    while (s > 0) {
      *newp++ = *oldp++;
      s--;
    }

    munmap(old, old_size);
    old = NULL;
  }

  ulp_stack[ULP_STACK_PTR] = (unsigned long) new;
  libpulp_assert(ulp_stack[ULP_STACK_PTR] != 0L);

  DEBUG("thread %lu: expanded stack to %lu bytes", pthread_self(), ulp_stack[ULP_STACK_REAL_SIZE]);

  /* Setup destructor for mmap memory, so we don't leak memory when a thread
     is destroyed.  */
  pthread_once(&ulp_once_control, ulp_pthread_key_init);

  return ulp_stack;
}
