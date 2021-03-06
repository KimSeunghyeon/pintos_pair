#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);


static void
process_init (struct process *proc)
{
	ASSERT(proc != NULL);
	list_init(&proc->children);
	list_init(&proc->slave_threads);
	list_init(&proc->fd_list);
	proc->parent = NULL;
	// Set pid same as tid for now
	proc->pid = -1;
	proc->slave = NULL;
	proc->slave_tid = -1;
	proc->thread_died = false;
	proc->thread_die_status = -1;
	proc->waiting = false;
}

/* Search child thread in the current process with given tid
 * and return matched thread. If there is no match, returns NULL */
static struct process *
get_proc_with_tid (tid_t tid)
{
	struct list *p_list = &process_list;
	struct list_elem *curr_list = list_head (p_list);
	struct process *curr_list_p;

	if (process_list.head.next == NULL) /* if list is not initialized */
				list_init(&process_list); /* initialize it */
	if (list_empty(&process_list))
		return NULL;
	while ((curr_list = list_next (curr_list)) != list_end (p_list)) {
		curr_list_p = list_entry(curr_list, struct process, pl_elem);

		//printf("process_get_proc:process found.. %d, tid: %d, given tid: %d\n", (curr_list_p->slave == NULL ? -1 : curr_list_p->slave_tid), curr_list_p->slave_tid, tid);
		if (curr_list_p->slave_tid == tid) {
			//printf("process_get_proc:matching process found.. %d\n", curr_list_p->slave_tid);
			return curr_list_p;
		}
	}
	return NULL;
}


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
	char *fn_copy;
	char *fn_test;
	char *p_test;
	struct file *test_file;
	tid_t tid;
	struct process *new_proc;

	//printf("process_execute.. %s: %s \n", thread_current()->name, file_name);
	if (thread_current()->master_proc == NULL) {
		enum intr_level old_level;
		old_level = intr_disable();
		new_proc = (struct process *)palloc_get_page(0);
		ASSERT(new_proc != NULL);
		process_init(new_proc);
		new_proc->parent = NULL;
		new_proc->slave_tid = thread_current()->tid;
		new_proc->slave = thread_current();
		new_proc->pid = thread_current()->tid;
		list_push_back(&new_proc->slave_threads, &thread_current()->p_elem); /* not used right now */
		if (process_list.head.next == NULL) /* if list is not initialized */
			list_init(&process_list); /* initialize it */
		list_push_back(&process_list, &new_proc->pl_elem);
		intr_set_level (old_level);
		//printf("process_execute: process is made.. tname: %s, tid: %d\n", thread_current()->name, new_proc->slave_tid);

		thread_current()->master_proc = new_proc;

		/* initialize locks */
		lock_init(&filesys_lock);
		lock_init(&thread_lock);
	}
	lock_acquire(&thread_lock);
	/* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL) {
		lock_release(&thread_lock);
		return TID_ERROR;
	}
	strlcpy (fn_copy, file_name, PGSIZE);

	/* test for exec-missing */
	fn_test = palloc_get_page (0);
	if (fn_test == NULL) {
		lock_release(&thread_lock);
		return TID_ERROR;
	}
	strlcpy (fn_test, file_name, PGSIZE);

	lock_acquire(&filesys_lock);
	test_file = filesys_open (strtok_r(fn_test, " ", &p_test));
	lock_release(&filesys_lock);

	palloc_free_page(fn_test);
	if (test_file == NULL) {
		lock_release(&thread_lock);
		return TID_ERROR;
	}
	else {
		file_close(test_file);
	}
	/* Create a new thread to execute FILE_NAME.  */

	tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
	//printf("name: %s, tid: %d\n", file_name, tid);
	if (tid == TID_ERROR) {
		palloc_free_page (fn_copy);
	}
	else {
		/* Create new child process and set parent and slave tid information */
		/* maybe need some synch */
		new_proc = (struct process *)palloc_get_page(0);
		ASSERT(new_proc != NULL);
		process_init(new_proc);
		new_proc->parent = thread_current()->master_proc;
		new_proc->slave_tid = tid;
		if (process_list.head.next == NULL) /* if list is not initialized */
			list_init(&process_list); /* initialize it */
		list_push_back(&process_list, &new_proc->pl_elem);
		list_push_back(&thread_current()->master_proc->children, &new_proc->child_elem);
		//printf("process_execute: process is made.. tid: %d\n", new_proc->slave_tid);

	}
	lock_release(&thread_lock);
	return tid;
}

/* A thread function that loads a user process and makes it start
   running. */
static void
start_process (void *f_name)
{
	char *file_name = f_name;
	struct intr_frame if_;
	bool success;

	struct process *master_process;

	//printf("process_start_process.. %s \n", thread_current()->name);

	/* Initialize interrupt frame and load executable. */
	memset (&if_, 0, sizeof if_);
	if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
	if_.cs = SEL_UCSEG;
	if_.eflags = FLAG_IF | FLAG_MBS;

	lock_acquire(&filesys_lock);
	success = load (file_name, &if_.eip, &if_.esp);
	lock_release(&filesys_lock);

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success) {
		thread_exit ();
	}
	else {
		/* find process with tid and set remaining informations */
		/* maybe need some synch */
		file_deny_write(thread_current()->loaded_file);
		lock_acquire(&thread_lock);
		master_process = get_proc_with_tid(thread_current()->tid);
		ASSERT(master_process != NULL);
		thread_current()->master_proc = master_process;
		master_process->slave = thread_current();
		master_process->pid = thread_current()->tid;

		list_push_back(&master_process->slave_threads, &thread_current()->p_elem); /* not used right now */
		lock_release(&thread_lock);
		//printf("process_start: process is changed.. name: %s, tid: %d\n", thread_current()->name, thread_current()->master_proc->slave_tid);

	}

	/* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
	asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
	int status;
	struct process *child;

	//printf("process_wait: name: %s\n", thread_current()->name);

	lock_acquire(&thread_lock);
	child = get_proc_with_tid(child_tid);
	if (child != NULL) {
		if (child->waiting == true) {
			lock_release(&thread_lock);
			return -1;
		}
		else {
			child->waiting = true;
		}
	}

	while (1) {
		child = get_proc_with_tid(child_tid);
		if (list_empty(&thread_current()->master_proc->children)) {
			lock_release(&thread_lock);
			return 0;
		}

		if (child->slave_tid == child_tid) {
			if (child->thread_died) {
				//printf("process_wait:child removed.. %d \n", child->slave_tid);
				list_remove(&child->child_elem);
				lock_release(&thread_lock);
				return child->thread_die_status;
			}
		}

		else { /* invalid child pid */
			lock_release(&thread_lock);
			return -1;
		}

		lock_release(&thread_lock);
		enum intr_level old_level;
		old_level = intr_disable();
		thread_block();
		intr_set_level (old_level);

		lock_acquire(&thread_lock);
	}
	/*

	lock_acquire(&thread_lock);
	child = get_proc_with_tid(child_tid);
	if (child != NULL) {
		if (child->slave_tid == child_tid) {
			if (child->thread_died) {
				//printf("process_wait:child removed.. %d \n", child->slave_tid);
				list_remove(&child->child_elem);
				lock_release(&thread_lock);
				return child->thread_die_status;
			}
		}
	}
	lock_release(&thread_lock);
	if (list_empty(&process_list))
		return 0;
	return -1;
	*/
	return -1;
}

void
process_exit (void)
{
	struct thread *curr = thread_current ();
	uint32_t *pd;

	//printf("process_exit.. %s \n", thread_current()->name);
	/* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
	pd = curr->pagedir;
	if (pd != NULL)
	{
		/* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
		curr->pagedir = NULL;
		pagedir_activate (NULL);
		pagedir_destroy (pd);
	}
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

static int parse_file_name (const char *file_name, void ***argv_);
static bool setup_arguments (void **esp, int argc, char **argv);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
	struct thread *t = thread_current ();
	struct Elf32_Ehdr ehdr;
	struct file *file = NULL;
	struct file *deny_file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pagedir = pagedir_create ();
	if (t->pagedir == NULL)
		goto done;
	process_activate ();

	/* Parse file name and get arguments */
	int argc = 0;
	char **argv = NULL;
	argc = parse_file_name (file_name, (void ***)&argv);
	if (argc == -1) {
		goto done;
	}
	strlcpy (t->name, argv[0], strlen(argv[0]) + 1);

	deny_file = filesys_open(argv[0]);
	if (deny_file != NULL) {
		thread_current()->loaded_file = deny_file;
	}

	/* Open executable file. */
	//file = filesys_open (file_name);
	ASSERT (argv[0] != NULL);
	file = filesys_open (argv[0]);
	if (file == NULL)
	{
		printf ("load: %s: open failed\n", argv[0]);
		goto done;
	}

	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 3
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
			|| ehdr.e_phnum > 1024)
	{
		printf ("load: %s: error loading executable\n", argv[0]);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++)
	{
		struct Elf32_Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type)
		{
		case PT_NULL:
		case PT_NOTE:
		case PT_PHDR:
		case PT_STACK:
		default:
			/* Ignore this segment. */
			break;
		case PT_DYNAMIC:
		case PT_INTERP:
		case PT_SHLIB:
			goto done;
		case PT_LOAD:
			if (validate_segment (&phdr, file))
			{
				bool writable = (phdr.p_flags & PF_W) != 0;
				uint32_t file_page = phdr.p_offset & ~PGMASK;
				uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
				uint32_t page_offset = phdr.p_vaddr & PGMASK;
				uint32_t read_bytes, zero_bytes;
				if (phdr.p_filesz > 0)
				{
					/* Normal segment.
                     Read initial part from disk and zero the rest. */
					read_bytes = page_offset + phdr.p_filesz;
					zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
							- read_bytes);
				}
				else
				{
					/* Entirely zero.
                     Don't read anything from disk. */
					read_bytes = 0;
					zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
				}
				if (!load_segment (file, file_page, (void *) mem_page,
						read_bytes, zero_bytes, writable))
					goto done;
			}
			else
				goto done;
			break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (esp))
		goto done;

	if (!setup_arguments (esp, argc, argv))
		goto done;


	/* Start address. */
	*eip = (void (*) (void)) ehdr.e_entry;

	success = true;

	done:
	/* We arrive here whether the load is successful or not. */
	file_close (file);
	return success;
}
/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Do calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Added for project 2 */
static int
parse_file_name (const char *file_name, void ***argv_)
{
	char *buffer = palloc_get_page(PAL_USER);
	int i;
	if (buffer == NULL) {
		return -1;
	}
	strlcpy(buffer, file_name, PGSIZE);
	char **argv = (char **)palloc_get_page(0);
	if (argv == NULL) {
		palloc_free_page(buffer);
		return -1;
	}
	char *token, *save_ptr;
	int argc = 0;

	for (token = strtok_r (buffer, " ", &save_ptr); token != NULL;
			token = strtok_r (NULL, " ", &save_ptr)) {
		argv[argc] = (char *)palloc_get_page(0);
		if (argv[argc] == NULL) {
			for (i = 0;i < argc;i++) {
				palloc_free_page(argv[i]);
			}
			palloc_free_page(argv);
			palloc_free_page(buffer);
			return -1;
		}
		strlcpy(argv[argc], token, PGSIZE);
		argc++;
	}

	*argv_ = (void**)argv;
	palloc_free_page(buffer);
	return argc;
}


static bool
setup_arguments (void **esp, int argc, char **argv)
{
	int i;

	/*
	stack_push(&esp, (void *)'\0', 4);
	stack_push(&esp, (void *)0, 4);
	for (i = argc - 1;i >= 0;i--) {
		stack_push(&esp, (void *)(*esp + i + 2), 4);
	}
	stack_push(&esp, (void *)(*esp + 4), 4);
	stack_push(&esp, (void *)(&argc), 4);

	 */
	char **args = palloc_get_page(0);
	if (args == NULL) {
		return false;
	}

	// argv
	for (i = argc - 1;i >= 0;i--) {
		*esp -= strlen(argv[i]) + 4 - strlen(argv[i]) % 4;
		strlcpy(*esp, argv[i], strlen(argv[i]) + 1);
		palloc_free_page(argv[i]);
		args[i] = *esp;
	}
	palloc_free_page(argv);

	// argv[n-1]
	*esp -= 4;
	memcpy(*esp, "\0", 1);

	// argv *
	for (i = argc - 1;i >= 0;i--) {
		*esp -= 4;
		memcpy(*esp, &args[i], 4);
	}
	palloc_free_page(args);

	// argv **
	int argss = (int)*esp;
	*esp -= 4;
	memcpy(*esp, &argss, 4);
	// argc
	*esp -= 4;
	memcpy(*esp, &argc, 4);
	// fake value
	*esp -= 4;
	memcpy(*esp, "\0", 1);


	//hex_dump(*esp, *esp, 80, true);
	return true;
}
