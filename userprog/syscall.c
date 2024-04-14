#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
/*================================================== IMPLEMENTATION START ==================================================*/
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "kernel/stdio.h"
#include "threads/palloc.h"
/*================================================== IMPLEMENTATION  END  ==================================================*/ 

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/*================================================== IMPLEMENTATION START ==================================================*/
void check_address (void *addr);

void halt (void);
void exit (int status);
bool create (const char *file, unsigned inital_size);
bool remove (const char *file);
tid_t fork (const char *thread_name, struct intr_frame *f);
int exec (char *file_name);
int wait (tid_t pid);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

static struct file *fd_to_file (int fd);
int file_to_fd (struct file *file);
void remove_fd (int fd);
/*================================================== IMPLEMENTATION  END  ==================================================*/ 

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

/*================================================== IMPLEMENTATION START ==================================================*/
const int STDIN = 1;
const int STDOUT = 2;
/*================================================== IMPLEMENTATION  END  ==================================================*/ 

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	
/*================================================== IMPLEMENTATION START ==================================================*/
	lock_init(&filesys_lock);
/*================================================== IMPLEMENTATION  END  ==================================================*/ 
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
/*================================================== IMPLEMENTATION START ==================================================*/
	switch (f->R.rax){

		case SYS_HALT:
			halt ();
			break;
		
		case SYS_EXIT:
			exit (f->R.rdi);
			break;

		case SYS_FORK:
			f->R.rax = fork (f->R.rdi, f);
			break;
			                    
		case SYS_EXEC:
			if (exec (f->R.rdi) == -1) exit (-1);
			break;
	
		case SYS_WAIT:	
			f->R.rax = wait (f->R.rdi);
			break; 

	    case SYS_CREATE:
			f->R.rax = create (f->R.rdi, f->R.rsi);
			break;

		case SYS_REMOVE:
			f->R.rax = remove (f->R.rdi);
			break;

		case SYS_OPEN:
			f->R.rax = open (f->R.rdi);
			break;	              
	               
        case SYS_FILESIZE:
			f->R.rax = filesize (f->R.rdi);
			break;

	    case SYS_READ:
			f->R.rax = read (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
	
		case SYS_WRITE:
			f->R.rax = write (f->R.rdi, f->R.rsi, f->R.rdx);
			break;
	                   
		case SYS_SEEK:
			seek (f->R.rdi, f->R.rsi);
			break;
	                  
        case SYS_TELL:
			f->R.rax = tell (f->R.rdi);
			break;
	                   
		case SYS_CLOSE:
			close (f->R.rdi);
			break;

		default:
			exit (-1);
			break;        
	}
}

void
check_address (void *addr)
{	
	if (is_kernel_vaddr (addr) || addr == NULL || pml4_get_page (thread_current ()->pml4, addr) == NULL) exit (-1);
}

void
halt (void)
{
	power_off ();
}

void
exit (int status)
{
	struct thread *t = thread_current ();
	t->exit_status = status; 
	printf ("%s: exit(%d)\n", thread_name (), status);
	thread_exit ();
}

bool
create (const char *file, unsigned inital_size)
{
	check_address (file);
	if (filesys_create (file, inital_size)) return true;
	else return false;
}

bool
remove (const char *file)
{
	check_address (file);
	return filesys_remove (file);
}

tid_t
fork (const char *thread_name, struct intr_frame *f)
{
	return process_fork (thread_name, f);
}

tid_t
exec (char *file_name)
{
	check_address (file_name);
	int size = strlen (file_name) + 1;

	char *fn_copy = palloc_get_page (PAL_ZERO);
	if (fn_copy == NULL) exit (-1);

	strlcpy (fn_copy, file_name, size);
	if (process_exec (fn_copy) == -1) return -1;

	NOT_REACHED ();
	return 0;
}

int
wait (tid_t pid)
{
	return process_wait (pid);
}


static struct file *
fd_to_file (int fd)
{
	if (fd < 0 || fd >= FDCOUNT_LIMIT) return NULL;
	return thread_current ()->fd_table[fd];
}

int
file_to_fd (struct file *file)
{
    struct thread *curr = thread_current ();
    struct file **fdt = curr->fd_table;

    while (curr->fd_idx < FDCOUNT_LIMIT && fdt[curr->fd_idx]) curr->fd_idx++;

    if (curr->fd_idx >= FDCOUNT_LIMIT) return -1;
    fdt[curr->fd_idx] = file;
    return curr->fd_idx;
}

void
remove_fd (int fd)
{
	if (fd < 0 || fd >= FDCOUNT_LIMIT) return NULL;
	thread_current ()->fd_table[fd] = NULL;
}

int
open (const char *file)
{
	check_address (file);
	lock_acquire (&filesys_lock);

	struct file *f = filesys_open (file);
	if (f == NULL) return -1;

	int fd = file_to_fd (f); 
	if (fd == -1) file_close (f);

	lock_release (&filesys_lock);
	return fd;
}

int
filesize (int fd)
{
	struct file *f = fd_to_file (fd);
	if (f == NULL) return -1;
	return file_length (f);
}

int
read (int fd, void *buffer, unsigned size)
{	
	check_address (buffer);
	check_address (buffer + size - 1);

	int read_count;
	struct file *f = fd_to_file (fd);
	if (f == NULL) return -1;

	unsigned char *buf = buffer;

	if (f == STDIN) {
		char key;
		for (read_count = 0; read_count < size; read_count++) {
			key = input_getc ();
			*buf++ = key;
			if (key == '\0') break;
		}
	}
	else if (f == STDOUT) return -1;
	else {
		lock_acquire (&filesys_lock);
		read_count = file_read (f, buffer, size);
		lock_release (&filesys_lock);
	}
	return read_count;
}

int
write (int fd, void *buffer, unsigned size)
{
	check_address (buffer);
	int read_count;

	struct file *f = fd_to_file (fd);
	if (f == NULL) return -1;

	if (f == STDOUT) {
		putbuf (buffer, size);
		read_count = size;
	}
	else if (f == STDIN) return -1;
	else {
		lock_acquire (&filesys_lock);
		read_count = file_write (f, buffer, size);
		lock_release (&filesys_lock);
	}
	return read_count;
}

void
seek (int fd, unsigned position)
{
	if (fd < 2) return NULL;
	file_seek (fd_to_file (fd), position);	
}

unsigned
tell (int fd)
{
	if (fd < 2) return NULL;
	return file_tell (fd_to_file (fd));
}

void
close (int fd)
{
	if (fd < 2) return NULL;
	struct file *f = fd_to_file (fd);
	if (f == NULL) return NULL;
	remove_fd (fd);
}
/*================================================== IMPLEMENTATION  END  ==================================================*/ 