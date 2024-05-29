#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "include/threads/init.h"
#include "include/threads/vaddr.h"
#include "include/filesys/filesys.h"
#include "include/filesys/file.h"
#include "include/lib/stdio.h"
#include "include/threads/synch.h"
#include "userprog/process.h"
#include "include/devices/input.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void get_argument(void *rsp, int *arg, int count);
bool remove(const char *file);
bool create(const char *file, unsigned initial_size);
void halt(void);
void exit(int status);
int write(int fd, const void *buffer, unsigned length);
int read(int fd, void *buffer, unsigned size);
int exec(const char *file);
int open(const char *file);
void close(int fd);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	// filesys lock 추가
	lock_init(&filesys_lock);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	/* 유저 스택에 저장되어 있는 시스템 콜 번호를 이용해 시스템 콜 핸들러 구현*/
	/* 스택 포인터가 유저 영역인지 확인*/
	/* 저장된 인자 값이 포인터일 경우 유저 영역의 주소인지 확인*/
	/* 0: halt*/
	/* 1: exit*/
	/* 2: fork*/
	/* . . .*/
	/* 14: sys_close*/
	/*
	레지스터 인자 순서
	 *num  ("rax")
	 *a1  ("rdi")
	 *a2  ("rsi")
	 *a3  ("rdx")
	 *a4  ("r10")
	 *a5  ("r8")
	 *a6  ("r9")
	*/

	int syscall_number = f->R.rax;

	int *arg = f->R.rsi;

	// 시스템 콜 번호 10번 -> SYS_WRITE
	switch (syscall_number)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_CREATE:;
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:;
		f->R.rax = remove(f->R.rdi); // 결과를 rax 레지스터에 저장한다
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	case SYS_EXEC:
		// get_argument(sp, arg, 1);
		f->R.rax = exec((const char *)arg[0]);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;

	default:
		printf("Unknown system call! : %d\n", syscall_number);
		thread_exit();
		break;
	}

	// printf("system call!\n");
	// thread_exit();
}

// 주소 값이 유저 영역에서 사용하는 주소 값인지 확인하는 함수
void check_address(void *addr)
{
	/* 포인터가 가리키는 주소가 유저 영역의 주소인지 확인*/
	/* pintos에서는 시스템 콜이 접근할 수 있는 주소를 0x8048000 ~ 0xc0000000으로 제한함 */
	/* 잘못된 접근일 경우 프로세스 종료 exit(-1)*/

	// printf("%d\n", addr);
	// 커널의 주소 영역이면 프로세스 종료
	if (addr == NULL || is_kernel_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL)
	{
		exit(-1);
	}
}

// 유저 스택에 있는 인자들을 커널에 저장하는 함수
void get_argument(void *rsp, int *arg, int count)
{
	/* 유저 스택에 저장된 인자값들을 커널로 저장*/
	/* 인자가 저장된 위치가 유저영역인지 확인*/
	/* 스택에서 인자들을 8byte 크기로 꺼내어 arg 배열에 순차적으로 저장*/
	/* 스택 포인터(rsp)에 count(인자의 개수) 만큼의 데이터를 arg에 저장*/

	check_address((void *)arg[0]);
	for (int i = 0; i < count; i++)
	{
		void *arg_ptr = (void *)((uint8_t *)rsp + i * sizeof(uint64_t));
		check_address(arg_ptr);
		arg[i] = *(int *)arg_ptr;
	}
}

// pintos를 종료하는 시스템 콜
void halt(void)
{
	/* power_off()를 사용하여 pintos 종료*/
	power_off();
}

/* 현재 프로세스를 종료시키는 시스템 콜
 * 종료 시 “프로세스 이름: exit(status)” 출력 (Process Termination Message)
 * 정상적으로 종료 시 status는 0
 * status: 프로그램이 정상적으로 종료됐는지 확인*/
void exit(int status)
{
	/* 실행중인 스레드 구조체를 가져옴*/
	/* 프로세스 종료 메시지 출력
	 * 출력 양식: "프로세스이름: exit(종료상태)"*/
	/* 스레드 종료*/

	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

// 파일이름과 크기에 해당하는 파일을 생성하는 시스템 콜
bool create(const char *file, unsigned initial_size)
{
	/* 파일 이름과 크기에 해당하는 파일 생성*/
	/* 파일 생성 성공 시 true 반환, 실패 시 false 반환*/
	check_address((void *)file);
	return filesys_create(file, initial_size);
}

// 파일 이름에 해당하는 파일을 제거하는 시스템 콜
bool remove(const char *file)
{
	/* 파일 이름에 해당하는 파일을 제거*/
	/* 파일 제거 성공 시 true 반환, 실패 시 false 반환 */
	check_address((void *)file);
	return filesys_remove(file);
}

int write(int fd, const void *buffer, unsigned length)
{
	/* 파일에 동시 접근이 일어날 수 있으므로 lock 사용
	 * 파일 디스크립터를 이용하여 파일 객체 검색
	 * 파일 디스크립터가 1일 경우 버퍼에 저장된 값을 화면에 출력 후
	 * 버퍼의 크기 리턴 (putbuf() 이용)
	 * 파일 디스크립터가 1이 아닐 경우 버퍼에 저장된 데이터를 크기만큼
	 * 파일에 기록후 기록한 바이트 수를 리턴*/
	check_address(buffer);
	struct file *file = process_get_file(fd);

	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, length);
		return length;
	}
	if (fd == STDIN_FILENO)
	{
		return 0;
	}

	lock_acquire(&filesys_lock);
	int write_byte = file_write(file, buffer, length);
	lock_release(&filesys_lock);

	return write_byte;
}

int read(int fd, void *buffer, unsigned size)
{
	/* 파일에 동시 접근이 일어날 수 있으므로 lock 사용
	 * 파일 디스크립터를 이용하여 파일 객체 검색
	 * 파일 디스크립터가 0일 경우 키보드에 입력을 버퍼에 저장 후 버퍼의
	 * 저장한 크기를 리턴 (input_getc() 이용)
	 * 파일 디스크립터가 0이 아닐 경우 파일의 데이터를 크기만큼 저장 후
	 * 읽은 바이트 수를 리턴*/
	check_address(buffer);			  // 버퍼 시작 주소 체크
	check_address(buffer + size - 1); // 버퍼 끝 주소도 유저 영역 내에 있는지 체크
	unsigned char *buf = buffer;
	int read_count;

	if (fd == STDIN_FILENO)
	{
		char key;
		for (read_count = 0; read_count < size; read_count++)
		{
			key = input_getc();
			*buf++ = key;
			if (key == '\0') // 엔터값
			{
				break;
			}
		}
		return read_count;
	}

	if (fd == STDOUT_FILENO)
	{
		return -1;
	}

	struct file *file = process_get_file(fd);
	if (file == NULL)
	{
		return -1;
	}

	lock_acquire(&filesys_lock);
	int read_byte = file_read(file, buffer, size);
	lock_release(&filesys_lock);

	return read_byte;
}

int exec(const char *file)
{
	/* process_execute()함수를 호출하여 자식 프로세스 생성
	 * 생성된 자식 프로세스의 프로세스 디스크립터를 검색
	 * 자식 프로세스의 프로그램이 적재될 때까지 대기
	 * 프로그램 적재 실패 시 -1 리턴
	 * 프로그램 적재 성공 시 자식 프로세스의 pid 리턴*/
}

// 파일을 열 때 사용하는 시스템 콜
int open(const char *file)
{
	/* 파일을 open
	 * 해당 파일 객체에 파일 디스크립터 부여
	 * 파일 디스크립터 리턴
	 * 해당 파일이 존재하지 않으면 -1 리턴*/

	check_address(file);
	struct file *f = filesys_open(file);
	if (f == NULL)
	{
		return -1;
	}
	int fd = process_add_file(f);

	if (fd == -1)
	{
		file_close(f);
	}

	return fd;
}

// 파일 닫기
void close(int fd)
{
	/* 파일 디스크립터에 해당하는 파일을 닫음
	 * 파일 디스크립터 테이블 해당 엔트리 초기화*/
	if (fd < 0 || fd >= FDT_COUNT_LIMIT)
	{
		return NULL;
	}
	struct thread *t = thread_current();
	struct file *file = t->fd_table[fd];
	file_close(file);
}

// 파일의 크기를 알려주는 시스템 콜
int filesize(int fd)
{
	/* 파일 디스크립터를 이용하여 파일 객체 검색
	 * 해당 파일의 길이를 리턴
	 * 해당 파일이 존재하지 않으면 -1 리턴*/

	struct thread *t = thread_current();
	struct file *file = process_get_file(fd);

	if (file == NULL)
	{
		return -1;
	}
	return file_length(file);
}

// 열린 파일의 위치 (offset)를 이동하는 시스템 콜
void seek(int fd, unsigned position)
{
	/* 파일 디스크립터를 이용하여 파일 객체 검색
	 * 해당 열린 파일의 위치(offset)를 position만큼 이동*/
	// position = 현재 위치를 기준으로 이동할 거리
	struct file *file = process_get_file(fd);
	if (fd <= 2)
	{
		return;
	}

	check_address(file);

	if (file == NULL)
	{
		return;
	}

	file_seek(file, position);
}

// 열린 파일의 위치(offset)를 알려주는 시스템 콜
unsigned tell(int fd)
{
	/* 파일 디스크립터를 이용하여 파일 객체 검색
	 * 해당 열린 파일의 위치를 반환*/
	// 성공시 파일의 위치를 반환, 실패 시 -1 반환
	struct file *file = process_get_file(fd);
	if (fd <= 2)
	{
		return;
	}
	check_address(file);

	if (file == NULL)
	{
		return;
	}

	return file_tell(file);
}
