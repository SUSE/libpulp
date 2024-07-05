#ifndef _ARCH_PPC64LE_H
#define _ARCH_PPC64LE_H

/** Offset of TLS pointer.  */
#define TLS_DTV_OFFSET 0x8000

/** Struct used to store the registers in memory.  */
typedef struct pt_regs registers_t;

/** Register in which the function stores the return value.  */
#define FUNCTION_RETURN_REG(reg) ((reg).gpr[3])

/** Register which acts as a program counter.  */
#define PROGRAM_COUNTER_REG(reg) ((reg).nip)

/** Register which acts as top of stack.  */
#define STACK_TOP_REG(reg)       ((reg).gpr[1])

/* Program load bias, which can be recovered by running `ld --verbose`.  */
#define EXECUTABLE_START         0x10000000UL

/**
 * Number of bytes that the kernel subtracts from the program counter,
 * when an ongoing syscall gets interrupted and must be restarted.
 */
#define RESTART_SYSCALL_SIZE     0

#endif
