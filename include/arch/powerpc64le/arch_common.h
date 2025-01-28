#ifndef _ARCH_PPC64LE_H
#define _ARCH_PPC64LE_H

/** Offset of TLS pointer.  */
#define TLS_DTV_OFFSET 0x8000

/* Program load bias, which can be recovered by running `ld --verbose`.  */
#define EXECUTABLE_START         0x10000000UL

/* The Red zone.  */
#define RED_ZONE_LEN             512

/**
 * Number of bytes that the kernel subtracts from the program counter,
 * when an ongoing syscall gets interrupted and must be restarted.
 */
#define RESTART_SYSCALL_SIZE     0

#ifdef __ASSEMBLER__
/* Declarations that requires assembler.  */

/** Field offset determining the real size (in bytes) of the ulp stack.  */
#define ULP_STACK_REAL_SIZE       0

/** Field offset determining the used size (in bytes) of the ulp stack.  */
#define ULP_STACK_USED_SIZE       8

/** Field offset determining the object pointer (allocated by mmap) of the ulp stack.  */
#define ULP_STACK_PTR             16

#else
/* Declarations that requires a C compiler.  */

/** Struct used to store the registers in memory.  */
typedef struct pt_regs registers_t;

/** Register in which the function stores the return value.  */
#define FUNCTION_RETURN_REG(reg) ((reg).gpr[3])

/** Register which acts as a program counter.  */
#define PROGRAM_COUNTER_REG(reg) ((reg).nip)

/** Register which acts as top of stack.  */
#define STACK_TOP_REG(reg)       ((reg).gpr[1])

/** Set the GLOBAL ENTRYPOINT REGISTER, which in power is r12.  */
#define SET_GLOBAL_ENTRYPOINT_REG(reg, val) (reg).gpr[12] = (val)

/** Field determining the real size (in longs) of the ulp stack.  */
#define ULP_STACK_REAL_SIZE       0

/** Field determining the used size (in longs) of the ulp stack.  */
#define ULP_STACK_USED_SIZE       1

/** Field determining the object pointer (allocated by mmap) of the ulp stack.  */
#define ULP_STACK_PTR             2

/** The ulp_stack object, defined in ulp_prologue.S.  */
extern __thread unsigned long ulp_stack[];

#endif /* __ASSEMBLER__ */
#endif /* _ARCH_PPC64LE_H */
