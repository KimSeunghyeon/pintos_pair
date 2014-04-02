#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <inttypes.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static void sys_halt_handler (struct intr_frame *);
static void sys_exit_handler (struct intr_frame *);
static void exit_handler (int status); // what is this??
/*static void sys_exec_handler (struct intr_frame *);
static void sys_wait_handler (struct intr_frame *);
static void sys_create_handler (struct intr_frame *);
static void sys_remove_handler (struct intr_frame *);
static void sys_open_handler (struct intr_frame *);
static void sys_filesize_handler (struct intr_frame *);
static void sys_read_handler (struct intr_frame *);
static void sys_write_handler (struct intr_frame *);
static void sys_seek_handler (struct intr_frame *);
static void sys_tell_handler (struct intr_frame *);
static void sys_close_handler (struct intr_frame *);
*/

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f)
{
	int *sn = f->esp;
	//printf ("\nsystem call: %d\n", *sn);

	switch (*sn) {
	case SYS_HALT:
		sys_halt_handler(f);
		break;
	case SYS_EXIT:
		sys_exit_handler(f);
		break;
	case SYS_EXEC:
		sys_exec_handler(f);
		break;
	/*case SYS_WAIT:
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
	*/

	default:
		//printf ("system call!\n");
		printf ("\nsystem call: %d\n", *sn);
		break;
	}

}

/* Search file_case in the current process with given fd
 * and return matched file_case. If there is no match,
 * returns NULL  */
static struct file_case *
get_file_case (int fd)
{
	struct list *fd_list = &thread_current()->master_proc->fd_list;
	struct list_elem *curr_list = list_head (fd_list);
	struct file_case *curr_list_fc;

	while ((curr_list = list_next (curr_list)) != list_end (fd_list)) {
		curr_list_fc = list_entry(curr_list, struct file_case, elem);
		if (curr_list_fc->fd == fd) {
			return curr_list_fc;
		}
	}
	return NULL;
}

static void
sys_halt_handler (struct intr_frame *f)
{
	power_off();
}

static void
sys_exit_handler (struct intr_frame *f)
{
	int *status = *(int *)(f->esp + 4);
	if (is_kernel_vaddr(status)) {
		f->eax = -1;
		exit_handler (-1);
	}
	else {
		f->eax = status;
		exit_handler (status);
	}
}

static void
exit_handler (int status)
{
	enum intr_level old_level;
	old_level = intr_disable();
	printf ("%s: exit(%d)\n", thread_current()->name, status);
	thread_current()->master_proc->thread_died = true;
	thread_current()->master_proc->thread_die_status = status;
	file_close(thread_current()->loaded_file);

	if (thread_current()->master_proc->parent->slave->status == THREAD_BLOCKED) {
		thread_unblock(thread_current()->master_proc->parent->slave);
	}
	intr_set_level (old_level);
	process_exit();
	thread_exit ();
}

static void
sys_exec_handler (struct intr_frame *f)
{
	const char **file = (char *)(f->esp + 4);
	int status;

	//printf("exec: %s\n", *file);
	f->eax = process_execute(*file);
}


