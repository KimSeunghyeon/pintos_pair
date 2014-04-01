#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

bool is_valid_pointer( uint32_t* pagedir, const void *p );
void assertValidPointer(uint32_t* pagedir, void* p);
void assertValidStack(uint32_t* pagedir, struct intr_frame* f, int args);
void assertValidStackEntry(uint32_t* pagedir, struct intr_frame*f, int n);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static int
syscall_write(int fd, const void* buffer, unsigned size)
{
  if(fd == STDIN_FILENO) return -1;

  if(fd == STDOUT_FILENO)
  {
    putbuf((const char*)buffer, size);
    return size;
  }
  return fd_write(fd, buffer, size);
}

static int
syscall_read(int fd, void* buffer, unsigned size)
{
  if(fd == STDOUT_FILENO) return -1;
  int amt = 0;
  if(fd == STDIN_FILENO)
  {
    while(amt < (int)size)
    {
      *((uint8_t*)buffer) = input_getc();
      ++buffer;
    }
  }
  else
  {
    amt = fd_read(fd, buffer, size);
  }
  return amt;
}

bool is_valid_pointer( uint32_t* pagedir, const void *p )
{
  bool ret = is_user_vaddr(p) && pagedir_get_page( pagedir, p );
  return ret;
}

#define GET_STACK(INTR_FRAME, OFFSET, CAST_AS) \
  *( (CAST_AS*)(INTR_FRAME->esp + (OFFSET)))

void assertValidPointer(uint32_t* pagedir, void* p)
{
  if(!is_valid_pointer(pagedir, p))
    thread_exit(-1);
}

void assertValidStack(uint32_t* pagedir, struct intr_frame* f, int args)
{
  assertValidPointer(pagedir, f->esp + (args-1) * 4);
}

void assertValidStackEntry(uint32_t* pagedir, struct intr_frame*f, int n)
{
  assertValidPointer(pagedir, GET_STACK(f, n, void*));
}



static void
syscall_handler (struct intr_frame *f)
{
  uint32_t* pagedir = thread_current()->pagedir;
  /* We always need to have a space for *at least* the system call nr */
  assertValidStack(pagedir, f, 1);
  int syscall_nr = GET_STACK(f, 0, int);
  /* printf ("system call no %d!\n", syscall_nr); */
  /* hex_dump(f->esp, f->esp, 16, true); */
  switch(syscall_nr)
  {
    case SYS_HALT:
      power_off();
      break;
    case SYS_EXIT:
      assertValidStack( pagedir, f, 2 );
      thread_exit( GET_STACK(f, 4, int) );
      break;
    case SYS_EXEC:
      assertValidStack( pagedir, f, 2 );
      assertValidStackEntry(pagedir, f, 4);
      f->eax = (int)process_execute( GET_STACK(f, 4, const char*) );
      break;
    case SYS_WAIT:
      assertValidStack( pagedir, f, 2 );
      if(! is_user_vaddr(GET_STACK(f, 4, void*))) thread_exit(-1);
      f->eax = process_wait( GET_STACK(f, 4, struct thread*) );
      break;
    case SYS_CREATE:
      assertValidStack( pagedir, f, 2 );
      assertValidStackEntry(pagedir, f, 4);
      f->eax = (int)filesys_create( GET_STACK(f, 4, const char*), GET_STACK(f, 8, unsigned));
      break;
    case SYS_REMOVE:
      assertValidStack( pagedir, f, 2 );
      assertValidStackEntry(pagedir, f, 4);
      f->eax = (int)filesys_remove( GET_STACK(f, 4, const char*) );
      break;
    case SYS_OPEN:
      assertValidStack( pagedir, f, 2 );
      assertValidStackEntry(pagedir, f, 4);
      f->eax = fd_open( GET_STACK(f, 4, const char*), false);
      break;
    case SYS_FILESIZE:
      assertValidStack( pagedir, f, 2 );
      f->eax = (int)fd_filesize( GET_STACK(f, 4, int));
      break;
    case SYS_READ:
      assertValidStack( pagedir, f, 4 );
      assertValidStackEntry(pagedir, f, 8);
      f->eax = syscall_read( GET_STACK(f, 4, int), GET_STACK(f, 8, void*), GET_STACK(f, 12, unsigned));
      break;
    case SYS_WRITE:
      assertValidStack( pagedir, f, 4 );
      assertValidStackEntry(pagedir, f, 8);
      f->eax = syscall_write( GET_STACK(f, 4, int), GET_STACK(f, 8, const void*), GET_STACK(f, 12, unsigned));
      break;
    case SYS_SEEK:
      assertValidStack( pagedir, f, 3 );
      fd_seek( GET_STACK(f, 4, int), GET_STACK(f, 8, unsigned) );
      break;
    case SYS_TELL:
      assertValidStack( pagedir, f, 2 );
      f->eax = (int)fd_tell( GET_STACK(f, 4, int) );
      break;
    case SYS_CLOSE:
      assertValidStack( pagedir, f, 2 );
      fd_close(GET_STACK(f, 4, int));
      break;
    default:
      printf("unknown system call??\n");
      thread_exit (-1);
  }
}
