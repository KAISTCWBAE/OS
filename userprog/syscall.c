#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
/* ---------- Project 2 ---------- */
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "kernel/stdio.h"
#include "threads/palloc.h"
/* ------------------------------- */

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);

/* Syscall function */
void halt(void);
void exit(int status);
bool create(const char *file, unsigned inital_size);
bool remove(const char *file);
tid_t fork (const char *thread_name, struct intr_frame *f);
int exec(char *file_name);
int wait(tid_t pid);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);


/* Syscall helper Functions */
static struct file *find_file_by_fd(int fd);
int add_file_to_fdt(struct file *file);
void remove_file_from_fdt(int fd);


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

const int STDIN = 1;
const int STDOUT = 2;

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
	
	/* 파일 사용 시 lock 초기화 */
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int sys_number = f->R.rax;
	switch (sys_number){

		case SYS_HALT:			/* Halt the operating system. */
			halt();
			break;
		
		case SYS_EXIT:			/* Terminate this process. */
			exit(f->R.rdi);
			break;

		case SYS_FORK:			/* Clone current process. */
			f->R.rax = fork(f->R.rdi, f);
			break;
			                    
		case SYS_EXEC:			/* Switch current process. */
			 if(exec(f->R.rdi) == -1)
			 	exit(-1);
           	 break;
	
		case SYS_WAIT:			/* Wait for a child process to die. */
			 f->R.rax = wait(f->R.rdi);
			 break; 

	    case SYS_CREATE:		/* Create a file. */
			 f->R.rax = create(f->R.rdi, f->R.rsi);
			 break;

		case SYS_REMOVE:		/* Delete a file. */
			 f->R.rax = remove(f->R.rdi);
			 break;

		case SYS_OPEN:			/* Open a file. */
			 f->R.rax = open(f->R.rdi);
			 break;	              
	               
        case SYS_FILESIZE: 		/* Obtain a file's size. */
			 f->R.rax = filesize(f->R.rdi);
			 break;

	    case SYS_READ:			/* Read from a file. */
			 f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			 break;
	
		case SYS_WRITE:			/* Write to a file. */
			 f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			 break;
	                   
		case SYS_SEEK:			/* Change position in a file. */
			 seek(f->R.rdi, f->R.rsi);
			 break;
	                  
        case SYS_TELL:			/* Report current position in a file. */
			 f->R.rax = tell(f->R.rdi);
			 break;
	                   
		case SYS_CLOSE:			/* Close a file. */
			 close(f->R.rdi);
			 break;

		default:
			// printf ("system call!\n");
			// thread_exit ();
			exit(-1);
			break;
		            
	}
	
}


/* ---- Project 2: User memory Access ----*/
// pml4_get_page(page map, addr(유저 가상주소)) : 유저 가상주소와 대응하는 물리주소를 확인하여 해당 물리주소와 연결된 커널 가상 주소를 반환하거나 만약 해당 물리주소가 가상 주소와 매핑되지 않은 영역이면 NULL 반환
void
check_address(void *addr)
{	
	struct thread *t = thread_current(); // 현재 스레드의 thread 구조체를 사용하기 위해서 t를 선언
	if (!is_user_vaddr(addr)||addr==NULL||pml4_get_page(t->pml4, addr)==NULL){
		// 해당 주소값이 유저 가장 주소에 해당하지 않고 or addr = Null or 유저 가상주소가 물리주소와 매핑되지 않은 영역

		exit(-1);
	}

}

/* project 2 : System Call */

void halt(void){

	power_off();
}


void exit(int status){

	struct thread *t = thread_current();
	t->exit_status = status; 
	printf ("%s: exit(%d)\n", thread_name(), status);
	thread_exit();

}

bool create(const char *file, unsigned inital_size){

	/* 성공 : True, 실패 : False */
	check_address(file);
	if(filesys_create(file, inital_size)){
		return true;
	}
	else	{	
		return false;
	}
}

bool remove(const char *file){

	/* 성공 : True, 실패 : False */
	check_address(file);
	return filesys_remove(file);

}

/* Project 2 : Process structure (fork) */

tid_t fork (const char *thread_name, struct intr_frame *f) {
	// check_address(thread_name);
	return process_fork(thread_name, f);// child thread namedl 들어온다
}

/* Project 2 : Process structure (exec, wait) */

tid_t exec(char *file_name){ // 현재 프로세스를 command line에서 지정된 인수를 전달하여 이름이 지정된 실행 파일로 변경

	check_address(file_name);
	int size = strlen(file_name) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO); // memory setting -> 메모리의 값을 원하는 크기만큼 세팅
	if (fn_copy == NULL){
		exit(-1);
	}
	strlcpy (fn_copy, file_name, size); // file_name을 fn_copy에 문자열 복사하겠다.

	if (process_exec(fn_copy) == -1){ // load 실패시 success -1로 되어 return
		return -1;
	}
	NOT_REACHED();
	return 0;

}

int wait(tid_t pid)
{
	return process_wait(pid);
}

/* Project 2 : File Descriptor */

static struct file *find_file_by_fd(int fd)
{
	if (fd < 0 || fd >= FDCOUNT_LIMIT){
		return NULL;
	}
	
	struct thread *cur = thread_current();
	
	return cur->fd_table[fd];
}

/* 
파일 객체(struct File)를 File Descriptor 테이블에 추가
현재 스레드의 fd_idx(file descriptor Table index 끝값) 반환
*/
int add_file_to_fdt(struct file *file)
{
    struct thread *cur = thread_current();
    struct file **fdt = cur->fd_table;

    // Find open spot from the front
    // fd 위치가 제한 범위 넘지않고, fd table의 인덱스 위치와 일치한다면
    while (cur->fd_idx < FDCOUNT_LIMIT && fdt[cur->fd_idx])
    {
        cur->fd_idx++;
    }

    // error - fd table full
    if (cur->fd_idx >= FDCOUNT_LIMIT)
        return -1;

    fdt[cur->fd_idx] = file;
    return cur->fd_idx;
}

void remove_file_from_fdt(int fd)
{
	struct thread *cur = thread_current();
	if (fd < 0 || fd >= FDCOUNT_LIMIT){
		return;
	}

	cur->fd_table[fd] = NULL;

}
/*
open(file) -> filesys_open(file) -> file_open(inode) -> file
open 함수 실행 -> filesys_open을 통해서 file open 함수에 inode를 넣고 실행하여 file을 반환받음
inode는 우리가 입력한 파일 이름을 컴퓨터가 알고 있는 파일이름으로 바꾸는 과정
file_obj = file이 되고, 이를 현재 스레드 파일 디스크립터 테이블에 추가하여 관리할 수 있게함
*/
int open(const char *file) // 파일 객체에 대한 파일 디스크립터 부여
{
	check_address(file);
	lock_acquire(&filesys_lock);

	struct file *file_obj = filesys_open(file);

	if (file_obj == NULL){
		return -1;
	}

	int fd = add_file_to_fdt(file_obj); 

	/* 파일 디스크립터가 가득 찬 경우 */
	if(fd==-1){
		file_close(file_obj);
	}

	lock_release(&filesys_lock);
	return fd;

}

/* 파일이 열려있다면 바이트 반환, 없다면 -1 반환 */
int filesize(int fd)
{
	struct file *file_obj = find_file_by_fd(fd);
	

	if (file_obj == NULL){
		return -1;
	}
	return file_length(file_obj);

}

/*
열린 파일의 데이터를 읽는 시스템 콜
- 파일에 동시 접근이 일어날 수 있으므로 Lock 사용 
- 파일 디스크립터를 이용하여 파일 객체 검색
- 파일 디스크립터가 0일 경우 키보드에 입력을 버퍼에 저장 후, 버퍼의 저장한 크기를 리턴 (input_getc() 이용)
- 파일 디스크립터가 0이 아닐 경우 파일의 데이터를 크기만큼 저장 후 읽은 바이트 수를 리턴

참고 :
NULL : 널 포인터 0x00000000 : 값이 없다, 비어 있다 의미 : pointer(void * ) 0
0 : 정수 0 : int
-> 포인터에서는 NULL, 0 같이 쓰인다!
*/

int read(int fd, void *buffer, unsigned size)
{	
	
	check_address(buffer);
	check_address(buffer+size-1);
	int read_count; // 글자수 카운트 용(for문 사용하기 위해)
	struct thread *cur = thread_current();
	struct file *file_obj = find_file_by_fd(fd);
	unsigned char *buf = buffer;

	if (file_obj == NULL)
		return -1;
	
	/* STDIN일 때 */
	if(file_obj == STDIN)
	{
		char key;
		for (int read_count = 0;read_count < size; read_count++){
			key = input_getc();
			*buf++ = key;
			if (key == '\0'){
				break;
			}
		}
		
	}
	/* STDOUT일 때 : -1 반환 */
	else if (file_obj == STDOUT)
	{
		return -1;
	}
	
	else {
			lock_acquire(&filesys_lock);
			read_count = file_read(file_obj,buffer, size); // 여기서만 lock을 이용하는 이유?, 키보드 입력 받을 때는 왜 안하는지?
			lock_release(&filesys_lock);
	}

	
	return read_count;


}

int write(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	int read_count; // 글자수 카운트 용(for문 사용하기 위해)
	struct file *file_obj = find_file_by_fd(fd);
	unsigned char *buf = buffer;

	if (file_obj == NULL)
		return -1;
	
	/* STDOUT일 때 */
	if(file_obj == STDOUT)
	{
		putbuf(buffer, size); // fd값이 1일 때, 버퍼에 저장된 데이터를 화면에 출력(putbuf()이용)
		read_count = size;
		
	}
	/* STDIN일 때 : -1 반환 */
	else if (file_obj == STDIN)
	{
		
		return -1;
	}
	
	else {
			lock_acquire(&filesys_lock);
			read_count = file_write(file_obj,buffer, size);
			lock_release(&filesys_lock);
	}
	return read_count;

}

/* 파일의 위치(offset)를 이동하는 함수 */
void seek(int fd, unsigned position)
{
	
	struct file *file_obj = find_file_by_fd(fd);
	if (fd < 2)
		return;
	// fileobj->pos = position;
	file_seek(file_obj, position);	
}



/* 파일의 시작점부터 현재 위치까지의 offset을 반환 */
unsigned tell(int fd)
{
	struct file *file_obj = find_file_by_fd(fd);
	if (fd < 2){
	   return;
	}
	return file_tell(file_obj);
}

void close(int fd)
{
	if (fd <= 1) return;
	struct file *file_obj = find_file_by_fd(fd);
	
	
	if (file_obj == NULL)
	{
		return;
	}

	remove_file_from_fdt(fd);


}