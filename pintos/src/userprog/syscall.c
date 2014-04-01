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
static void exit_handler (int status);
static void sys_exit_handler (struct intr_frame *);
static void sys_halt_handler (struct intr_frame *);
static void sys_exec_handler (struct intr_frame *);
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
sys_halt_handler (struct intr_frame *f)
{
	power_off();
}
static void
sys_exec_handler (struct intr_frame *f)
{
	const char **file = (char *)(f->esp + 4);
	int status;

	//printf("exec: %s\n", *file);
	f->eax = process_execute(*file);
}
static void
sys_wait_handler (struct intr_frame *f)
{
	pid_t pid = *(int *)(f->esp + 4);

	f->eax = process_wait(pid);

}
static void
sys_create_handler (struct intr_frame *f)
{
	const char **file = (char *)(f->esp + 4);
	unsigned initial_size = *(unsigned *)(f->esp + 8);
	int result = false;

	if (*file == NULL) {
		exit_handler(-1);
	}
	if (strlen(*file) == 0 || strlen(*file) > 14) {
		result = false;
		goto sys_create_done;
	}
	lock_acquire(&filesys_lock);
	result = filesys_create(*file, (off_t)initial_size);
	lock_release(&filesys_lock);

	sys_create_done:
	f->eax = result;
}

static void
sys_remove_handler (struct intr_frame *f)
{
	const char **file = (char *)(f->esp + 4);
	int result = false;

	if (*file == NULL) {
		result = -1;
		goto sys_remove_done;
	}
	lock_acquire(&filesys_lock);
	result = filesys_remove(*file);
	lock_release(&filesys_lock);

	sys_remove_done:
	f->eax = result;
}
static void
sys_open_handler (struct intr_frame *f)
{
	const char **file = (char *)(f->esp + 4);

	struct list *fd_list = &thread_current()->master_proc->fd_list;
	//struct file_case *fcase = (struct file_case *)palloc_get_page(PAL_USER);
	int fd;
	struct file_case *fcase = (struct file_case *)malloc(sizeof(struct file_case));
	if (fcase == NULL) {
		fd = -1;
		goto sys_open_done;
	}

	if (*file == NULL) {
		fd = -1;
		goto sys_open_done;
	}
	lock_acquire(&filesys_lock);
	fcase->file = (void *)filesys_open(*file);
	lock_release(&filesys_lock);

	if (fcase->file == NULL) {
		//printf("sys_open failed");
		fd = -1;
		goto sys_open_done;
	}
	if (list_empty(fd_list)) {
		fcase->fd = 3;
	}
	else {
		struct file_case *front_fcase =
				list_entry(list_front(fd_list), struct file_case, elem);
		fcase->fd = front_fcase->fd + 1;
	}

	list_push_front(fd_list, &fcase->elem);
	fd = fcase->fd;

	sys_open_done:
	f->eax = fd;
}

static void
sys_filesize_handler (struct intr_frame *f)
{
	int fd = *(int *)(f->esp + 4);
	off_t result = -1;

	if (fd < 3) {
		result = -1;
		goto sys_filesize_done;
	}

	struct file_case *fc = get_file_case(fd);
	if (fc != NULL) {
		result = file_length(fc->file);
	}

	sys_filesize_done:
	f->eax = result;
}
static void
sys_read_handler (struct intr_frame *f)
{
	int fd = *(int *)(f->esp + 4);
	const void **buffer = (void *)(f->esp + 8);
	unsigned size = *(unsigned *)(f->esp + 12);

	uint8_t key;
	unsigned input_count = 0;
	int read_bytes = -1;


	if (fd == 0) {
		while (1) {
			key = input_getc();
			if (input_count > size) {
				*(char **)buffer[input_count] = '\0';
				break;
			}
			if (key == 13) {
				*(char **)buffer[input_count] = '\0';
				break;
			}
			else {
				*(char **)buffer[input_count] = key;
				input_count++;
			}
		}
		read_bytes = input_count;
		goto sys_read_done;
	}

	if (fd < 3) {
		read_bytes = -1;
		goto sys_read_done;
	}
	struct file_case *fc = get_file_case(fd);
	if (fc != NULL) {
		lock_acquire(&filesys_lock);
		read_bytes = file_read(fc->file, *buffer, (off_t)size);
		lock_release(&filesys_lock);
	}

	sys_read_done:
	f->eax = read_bytes;
}
static void
sys_write_handler (struct intr_frame *f)
{
	int fd = *(int *)(f->esp + 4);
	const void **buffer = (void *)(f->esp + 8);
	unsigned size = *(unsigned *)(f->esp + 12);

	int written_bytes = -1;

	off_t file_size;

	if (fd == 0) {
		written_bytes = -1;
		goto sys_write_done;
	}
	if (fd == 1) {
		putbuf(*buffer, size);
		written_bytes = size;
		goto sys_write_done;
	}

	struct file_case *fc = get_file_case(fd);
	if (fc != NULL) {
		file_size = file_length(fc->file);
		if ((int32_t)size > file_size) {
			lock_acquire(&filesys_lock);
			file_write(fc->file, *buffer, file_size);
			lock_release(&filesys_lock);
			written_bytes = (int)file_size;
		}
		else {
			lock_acquire(&filesys_lock);
			written_bytes = file_write(fc->file, *buffer, (off_t)size);
			lock_release(&filesys_lock);
		}
	}

	sys_write_done:
	f->eax = written_bytes;
}
static void
sys_seek_handler (struct intr_frame *f)
{
	int fd = *(int *)(f->esp + 4);
	unsigned position = *(unsigned *)(f->esp + 8);

	bool result = false;

	if (fd < 3) {
		result = false;
		goto sys_seek_done;
	}

	struct file_case *fc = get_file_case(fd);
	if (fc != NULL) {
		file_seek(fc->file, (off_t) position);;
	}

	sys_seek_done:
	f->eax = result;
}
static void
sys_tell_handler (struct intr_frame *f)
{
	int fd = *(int *)(f->esp + 4);

	unsigned position = -1;


	if (fd < 3) {
		position = -1;
		goto sys_tell_done;
	}
	struct file_case *fc = get_file_case(fd);
	if (fc != NULL) {
		position = (unsigned)file_tell(fc->file);
	}


	sys_tell_done:
	f->eax = position;
}
static void
sys_close_handler (struct intr_frame *f)
{
	int fd = *(int *)(f->esp + 4);
	int result = -1;

	if (fd < 3) {
		result = -1;
		goto sys_close_done;
	}

	struct file_case *fc = get_file_case(fd);
	if (fc != NULL) {
		list_remove(&fc->elem);
		lock_acquire(&filesys_lock);
		file_close(fc->file);
		lock_release(&filesys_lock);
		//palloc_free_page(fc);
		free(fc);
		result = 0;
	}

	sys_close_done:
	f->eax = result;
}
