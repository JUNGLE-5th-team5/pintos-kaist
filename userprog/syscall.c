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
#include "include/lib/stdio.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
void check_address(void *addr);
void get_argument(void *rsp, int *arg, int count);
bool remove(const char *file);
bool create(const char *file, unsigned initial_size);
void halt(void);
void exit(int status);
int write(int fd, const void *buffer, unsigned length);
int exec(const char *file);

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

	int syscall_number = f->R.rax;
	uint32_t *sp = f->rsp; // 유저 스택 포인터
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
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_EXEC:
		get_argument(sp, arg, 1);
		f->R.rax = exec((const char *)arg[0]);
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
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, length);
		return length;
	}
}

int exec(const char *file)
{
	/* process_execute()함수를 호출하여 자식 프로세스 생성
	 * 생성된 자식 프로세스의 프로세스 디스크립터를 검색
	 * 자식 프로세스의 프로그램이 적재될 때까지 대기
	 * 프로그램 적재 실패 시 -1 리턴
	 * 프로그램 적재 성공 시 자식 프로세스의 pid 리턴*/
}
