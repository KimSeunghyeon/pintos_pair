#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

static void
syscall_handler (struct intr_frame *f)
{
	int *sn = f->esp;
	//printf ("\nsystem call: %d\n", *sn);

	switch (*sn) {
	case SYS_EXIT:
		sys_exit_handler(f);
		break;
	case SYS_HALT:
		sys_halt_handler(f);
		break;
	case SYS_EXEC:
		sys_exec_handler(f);
		break;
	case SYS_WAIT:
		sys_wait_handler(f);
		break;
	case SYS_CREATE:
		sys_create_handler(f);
		break;
	case SYS_REMOVE:
		sys_remove_handler(f);
		break;
	case SYS_OPEN:
		sys_open_handler(f);
		break;
	case SYS_FILESIZE:
		sys_filesize_handler(f);
		break;
	case SYS_READ:
		sys_read_handler(f);
		break;
	case SYS_WRITE:
		sys_write_handler(f);
		break;
	case SYS_SEEK:
		sys_seek_handler(f);
		break;
	case SYS_TELL:
		sys_tell_handler(f);
		break;
	case SYS_CLOSE:
		sys_close_handler(f);
		break;


	default:
		//printf ("system call!\n");
		printf ("\nsystem call: %d\n", *sn);
		break;
	}

}
