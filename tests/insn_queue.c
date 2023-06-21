#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>

void
ulp_warn(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

void
ulp_debug(const char *format, ...)
{
  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

void
msgq_push(const char *format, ...)
{
  va_list arglist;

  va_start(arglist, format);
  vprintf(format, arglist);
  va_end(arglist);
}

/* Disable the poisoning in error.h.  */
#define DISABLE_ERR_POISON

#include "../lib/error.c"
#include "../lib/insn_queue.c"
#include "../tools/insn_queue.c"
#include "../tools/ptrace.c"

/* Set a two-way communcation channel between child and parent.  */
static int fd[2][2];
static int is_child = false;

/* Send message.  */
static void
send(char c)
{
  if (is_child) {
    write(fd[0][1], &c, 1);
  }
  else {
    write(fd[1][1], &c, 1);
  }
}

/* Wait for message.  */
static void
wait_for(char x)
{
  char c;
  do {
    if (is_child) {
      read(fd[1][0], &c, 1);
    }
    else {
      read(fd[0][0], &c, 1);
    }
  }
  while (c != x);
}

/* Test1: Fill the queue with print messages.  All messages should be inserted
   successfully.  */
static void
test1_parent(int child_pid)
{
  printf("Test 1 start\n");
  wait_for('a');
  int stdout_copy = dup(1);
  close(1);
  if (insnq_interpret_from_process_(child_pid,
                                    (Elf64_Addr)&__ulp_insn_queue)) {
    abort();
  }
  fflush(stdout);
  dup2(stdout_copy, 1);
  send('b');
}

static void
test1_child(void)
{
  int n = INSN_BUFFER_MAX / 8;
  const char *string = "abc";
  for (int i = 0; i < n; i++) {
    insnq_insert_print(string);
  }

  send('a');
  wait_for('b');
}

/* Test2: Check if the queue correctly fails if it detects that the client is
   outdated.  */
static void
test2_parent(int child_pid)
{
  printf("Test 2 start\n");
  wait_for('c');
  if (insnq_interpret_from_process_(
          child_pid, (Elf64_Addr)&__ulp_insn_queue) != EOLDULP) {
    abort();
  }
  send('d');
  wait_for('1');
}

void
test2_child(void)
{
  /* Modify the queue version.  */
  int old_ver = __ulp_insn_queue.version;
  __ulp_insn_queue.version = 1 << 30;
  send('c');
  wait_for('d');
  __ulp_insn_queue.version = old_ver;
  send('1');
}

/* Test3: Fill the queue with write messages.  All messages should be inserted
   successfully, and there should be a write into the target process related to
   the address we passed.  */
volatile char write_frame[8];
static void
test3_parent(int child_pid)
{
  printf("Test 3 start\n");

  wait_for('e');
  /* We need to attach to proess in the test.  On the ULP tool that would
     already be done.  */
  attach(child_pid);

  ulp_error_t ret =
      insnq_interpret_from_process_(child_pid, (Elf64_Addr)&__ulp_insn_queue);
  if (ret) {
    printf("Error interpreting queue on test 3\n");
    abort();
  }
  detach(child_pid);

  send('f');
}

static void
test3_child(void)
{
  char buf[8];
  for (int i = 0; i < 8; i++) {
    buf[i] = 'a';
  }

  int n = INSN_BUFFER_MAX / align_to(sizeof(struct ulp_insn_write) + 8, 8);
  for (int i = 0; i < n; i++) {
    insnq_insert_write((void *)write_frame, 8, buf);
  }

  send('e');
  wait_for('f');

  if (memcmp(buf, (void *)write_frame, 8) != 0) {
    abort();
  }
}

/* Test4: Try to add more messages than supported in the queue. It should fail.
 */
static void
test4_child(void)
{
  char buf[8];
  for (int i = 0; i < 8; i++) {
    buf[i] = 'a';
  }

  int n = (INSN_BUFFER_MAX) / align_to(sizeof(struct ulp_insn_write) + 8, 8);
  for (int i = 0; i < n; i++) {
    insnq_insert_write((void *)write_frame, 8, buf);
  }

  /* Last write should be blocked.  */
  ulp_error_t ret = insnq_insert_write((void *)write_frame, 8, buf);

  /* Should detect that we are out of memory in the queue and fail.  */
  if (ret != EINSNQ) {
    abort();
  }

  send('g');
  wait_for('h');
}

static void
test4_parent(int child_pid)
{
  printf("Test 4 start\n");

  wait_for('g');
  /* We need to attach to proess in the test.  On the ULP tool that would
     already be done.  */
  attach(child_pid);

  ulp_error_t ret =
      insnq_interpret_from_process_(child_pid, (Elf64_Addr)&__ulp_insn_queue);
  if (ret) {
    printf("Error interpreting queue on test 3\n");
    abort();
  }
  detach(child_pid);

  send('h');
}

static int
parent(pid_t child_pid)
{
  test1_parent(child_pid);
  test2_parent(child_pid);
  test3_parent(child_pid);
  test4_parent(child_pid);

  if (insnq_ensure_emptiness()) {
    /* Ensure that the queue ends empty.  */
    abort();
  }
  return 0;
}

static void
child(void)
{
  test1_child();
  test2_child();
  test3_child();
  test4_child();
}

int
main(void)
{
  pid_t pid;
  pipe(fd[0]);
  pipe(fd[1]);

  pid = fork();
  if (pid == 0) {
    is_child = true;
    child();
  }
  else {
    parent(pid);

    int wstatus;
    waitpid(pid, &wstatus, 0);

    if (WIFEXITED(wstatus)) {
      int r = WEXITSTATUS(wstatus);
      if (r) {
        printf("Process %d returned non-zero: %d\n", pid, r);
        return 1;
      }
    }
    else {
      printf("Process %d ended without calling exit\n", pid);
      return 1;
    }
  }

  close(fd[0][0]);
  close(fd[0][1]);
  close(fd[1][0]);
  close(fd[1][1]);
  printf("Success\n");
  return 0;
}
