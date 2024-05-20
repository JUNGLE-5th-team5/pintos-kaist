#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

#define F (1 << 14) // 소수점 아래 14비트 사용
#define TO_REAL_NUM(num) (num * F)

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

static struct list sleep_list;

// static struct list all_list;

static int64_t load_avg = 0;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;   /* # of timer ticks spent idle. */
static long long kernel_ticks; /* # of timer ticks in kernel threads. */
static long long user_ticks;   /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4		  /* # of timer ticks to give each thread. */
static unsigned thread_ticks; /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread(thread_func *, void *aux);

static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *)(pg_round_down(rrsp())))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void thread_init(void)
{
	ASSERT(intr_get_level() == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof(gdt) - 1,
		.address = (uint64_t)gdt};
	lgdt(&gdt_ds);

	/* Init the globla thread context */
	lock_init(&tid_lock);
	list_init(&ready_list);
	list_init(&sleep_list);
	// list_init (&all_list);
	list_init(&destruction_req);

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread();
	init_thread(initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void thread_start(void)
{
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init(&idle_started, 0);
	thread_create("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down(&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void thread_tick(void)
{
	struct thread *t = thread_current();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return();
}

int32_t my_multiply(int x, int y)
{
	return ((int64_t)x * y) / F;
}

int32_t my_division(int x, int y)
{
	return ((int64_t)x * F) / y;
}

int round_toward_zero(int x)
{
	return x / F;
}

int round_to_nearest(int x)
{
	if (x >= 0)
	{
		return (x + F / 2) / F;
	}
	else
	{
		return (x - F / 2) / F;
	}
}

void mlfqs_increase_recent_cpu(void)
{
	if (thread_current() != idle_thread)
	{
		thread_current()->recent_cpu = thread_current()->recent_cpu + (1 * F);
	}
}

void thread_calc(int64_t ticks)
{
	struct thread *curr_thread = thread_current();
	int ready_threads;
	if (curr_thread == idle_thread)
	{
		ready_threads = list_size(&ready_list);
	}
	else
	{
		ready_threads = list_size(&ready_list) + 1;
	}

	if (ticks % 100 == 0)
	{
		load_avg = my_multiply(my_division(TO_REAL_NUM(59), TO_REAL_NUM(60)), load_avg) + my_division(TO_REAL_NUM(1), TO_REAL_NUM(60)) * ready_threads;
		int decay = my_division((load_avg * 2), ((load_avg * 2) + (1 * F)));

		if (curr_thread != idle_thread)
		{
			curr_thread->recent_cpu = my_multiply(decay, curr_thread->recent_cpu) + (curr_thread->nice * F);
		}

		struct list_elem *e = list_begin(&ready_list);
		for (e = list_begin(&ready_list); e != list_end(&ready_list); e = list_next(e))
		{
			struct thread *thread = list_entry(e, struct thread, elem);
			thread->recent_cpu = my_multiply(decay, thread->recent_cpu) + (thread->nice * F);
		}

		struct list_elem *el = list_begin(&sleep_list);
		for (el = list_begin(&sleep_list); el != list_end(&sleep_list); el = list_next(el))
		{
			struct thread *thread = list_entry(el, struct thread, elem);
			thread->recent_cpu = my_multiply(decay, thread->recent_cpu) + (thread->nice * F);
		}
	}

	if (ticks % TIME_SLICE == 0)
	{
		struct list_elem *e = list_begin(&ready_list);
		if (curr_thread != idle_thread)
		{
			curr_thread->priority = PRI_MAX - round_to_nearest(curr_thread->recent_cpu / 4) - (curr_thread->nice * 2);
		}

		for (e = list_begin(&ready_list); e != list_end(&ready_list); e = list_next(e))
		{
			struct thread *thread = list_entry(e, struct thread, elem);
			thread->priority = PRI_MAX - round_to_nearest(thread->recent_cpu / 4) - (thread->nice * 2);
		}

		struct list_elem *el = list_begin(&sleep_list);
		for (el = list_begin(&sleep_list); el != list_end(&sleep_list); el = list_next(el))
		{
			struct thread *thread = list_entry(el, struct thread, elem);
			thread->priority = PRI_MAX - round_to_nearest(thread->recent_cpu / 4) - (thread->nice * 2);
		}
	}
}

/* Prints thread statistics. */
void thread_print_stats(void)
{
	printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
		   idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t thread_create(const char *name, int priority,
					thread_func *function, void *aux)
{
	struct thread *t;
	tid_t tid;

	ASSERT(function != NULL);

	/* Allocate thread. */
	t = palloc_get_page(PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread(t, name, priority);
	tid = t->tid = allocate_tid();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t)kernel_thread;
	t->tf.R.rdi = (uint64_t)function;
	t->tf.R.rsi = (uint64_t)aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock(t);
	preempt_priority();

	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void thread_block(void)
{
	ASSERT(!intr_context());
	ASSERT(intr_get_level() == INTR_OFF);
	thread_current()->status = THREAD_BLOCKED;
	schedule();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void thread_unblock(struct thread *t)
{
	enum intr_level old_level;

	ASSERT(is_thread(t));

	old_level = intr_disable();
	ASSERT(t->status == THREAD_BLOCKED);
	// list_push_back (&ready_list, &t->elem);
	list_insert_ordered(&ready_list, &t->elem, compare_priority, NULL);

	t->status = THREAD_READY;
	intr_set_level(old_level);
}

void thread_sleep(int64_t wakeup_time)
{
	struct thread *cur = thread_current();

	if (cur != idle_thread)
	{
		enum intr_level old_level;
		old_level = intr_disable();

		cur->wakeup_ticks = wakeup_time;
		list_push_back(&sleep_list, &cur->elem);

		thread_block();

		intr_set_level(old_level);
	}
}

void thread_wakeup(int64_t curr_tick)
{
	enum intr_level old_level;
	old_level = intr_disable();

	struct list_elem *item;

	for (item = list_begin(&sleep_list); item != list_end(&sleep_list);)
	{

		struct thread *cur_thread = list_entry(item, struct thread, elem);
		if (cur_thread->wakeup_ticks <= curr_tick)
		{

			item = list_remove(item); // csw - list_remove는 아이템 삭제 후 다음 아이템을 반환함
			thread_unblock(cur_thread);
			preempt_priority();
		}
		else
		{
			item = list_next(item);
		}
	}
	intr_set_level(old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name(void)
{
	return thread_current()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current(void)
{
	struct thread *t = running_thread();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT(is_thread(t));
	ASSERT(t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t thread_tid(void)
{
	return thread_current()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void thread_exit(void)
{
	ASSERT(!intr_context());

#ifdef USERPROG
	process_exit();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable();
	do_schedule(THREAD_DYING);
	NOT_REACHED();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void thread_yield(void)
{
	struct thread *curr = thread_current();
	enum intr_level old_level;

	ASSERT(!intr_context());

	// struct thread *first_thread = list_entry(list_begin(&ready_list), struct thread, elem); // csw - list_entry 매크로는 list 내부 아이템을 스레드로 바꾸는 방법으로 추정됨

	old_level = intr_disable();
	if (curr != idle_thread)
	{
		// list_push_back (&ready_list, &curr->elem);
		list_insert_ordered(&ready_list, &curr->elem, compare_priority, NULL);
	}
	do_schedule(THREAD_READY);
	intr_set_level(old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void thread_set_priority(int new_priority)
{
	if (thread_mlfqs)
	{
		return;
	}

	struct thread *curr_thread = thread_current();

	curr_thread->original_priority = new_priority;
	curr_thread->priority = new_priority;

	if (!list_empty(&curr_thread->donors))
	{
		struct thread *max_donor = list_entry(list_max(&curr_thread->donors, compare_priority, NULL), struct thread, donor_elem);
		if (max_donor->priority > curr_thread->priority)
		{ // csw - max_donor->priority > curr_thread->priority 조건 없어도 테스트 통과됐음
			curr_thread->priority = max_donor->priority;
		}
	}

	preempt_priority();
}

void preempt_priority()
{
	struct thread *curr_thread = thread_current();
	if (curr_thread == idle_thread)
	{
		return;
	}
	if (list_empty(&ready_list))
	{
		return;
	}
	struct thread *first_thread = list_entry(list_front(&ready_list), struct thread, elem);
	if (!intr_context() && curr_thread->priority < first_thread->priority)
	{
		thread_yield();
	}
}

/* Returns the current thread's priority. */
int thread_get_priority(void)
{
	return thread_current()->priority;
}

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED)
{
	// csw - 여기서 인터럽트 관련 코드 없어도 지장없었음
	// enum intr_level old_level = intr_disable ();
	thread_current()->nice = nice;
	// intr_set_level (old_level);
}

/* Returns the current thread's nice value. */
int thread_get_nice(void)
{
	// csw - 여기서 인터럽트 관련 코드 없어도 지장없었음
	// enum intr_level old_level = intr_disable ();
	int nice = thread_current()->nice;
	// intr_set_level (old_level);
	return nice;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void)
{
	return round_to_nearest(100 * load_avg);
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void)
{
	return round_to_nearest(100 * thread_current()->recent_cpu);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle(void *idle_started_ UNUSED)
{
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current();
	sema_up(idle_started);

	for (;;)
	{
		/* Let someone else run. */
		intr_disable();
		thread_block();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread(thread_func *function, void *aux)
{
	ASSERT(function != NULL);

	intr_enable(); /* The scheduler runs with interrupts off. */
	function(aux); /* Execute the thread function. */
	thread_exit(); /* If function() returns, kill the thread. */
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread(struct thread *t, const char *name, int priority)
{
	ASSERT(t != NULL);
	ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT(name != NULL);

	memset(t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy(t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
	t->priority = priority;
	t->original_priority = priority;
	t->nice = 0;
	t->recent_cpu = 0;
	list_init(&t->donors);
	t->magic = THREAD_MAGIC;
	// list_push_back (&all_list, &t->all_elem);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run(void)
{
	if (list_empty(&ready_list))
		return idle_thread;
	else
		return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void do_iret(struct intr_frame *tf)
{
	__asm __volatile(
		"movq %0, %%rsp\n"
		"movq 0(%%rsp),%%r15\n"
		"movq 8(%%rsp),%%r14\n"
		"movq 16(%%rsp),%%r13\n"
		"movq 24(%%rsp),%%r12\n"
		"movq 32(%%rsp),%%r11\n"
		"movq 40(%%rsp),%%r10\n"
		"movq 48(%%rsp),%%r9\n"
		"movq 56(%%rsp),%%r8\n"
		"movq 64(%%rsp),%%rsi\n"
		"movq 72(%%rsp),%%rdi\n"
		"movq 80(%%rsp),%%rbp\n"
		"movq 88(%%rsp),%%rdx\n"
		"movq 96(%%rsp),%%rcx\n"
		"movq 104(%%rsp),%%rbx\n"
		"movq 112(%%rsp),%%rax\n"
		"addq $120,%%rsp\n"
		"movw 8(%%rsp),%%ds\n"
		"movw (%%rsp),%%es\n"
		"addq $32, %%rsp\n"
		"iretq"
		: : "g"((uint64_t)tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch(struct thread *th)
{
	uint64_t tf_cur = (uint64_t)&running_thread()->tf;
	uint64_t tf = (uint64_t)&th->tf;
	ASSERT(intr_get_level() == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile(
		/* Store registers that will be used. */
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		/* Fetch input once */
		"movq %0, %%rax\n"
		"movq %1, %%rcx\n"
		"movq %%r15, 0(%%rax)\n"
		"movq %%r14, 8(%%rax)\n"
		"movq %%r13, 16(%%rax)\n"
		"movq %%r12, 24(%%rax)\n"
		"movq %%r11, 32(%%rax)\n"
		"movq %%r10, 40(%%rax)\n"
		"movq %%r9, 48(%%rax)\n"
		"movq %%r8, 56(%%rax)\n"
		"movq %%rsi, 64(%%rax)\n"
		"movq %%rdi, 72(%%rax)\n"
		"movq %%rbp, 80(%%rax)\n"
		"movq %%rdx, 88(%%rax)\n"
		"pop %%rbx\n" // Saved rcx
		"movq %%rbx, 96(%%rax)\n"
		"pop %%rbx\n" // Saved rbx
		"movq %%rbx, 104(%%rax)\n"
		"pop %%rbx\n" // Saved rax
		"movq %%rbx, 112(%%rax)\n"
		"addq $120, %%rax\n"
		"movw %%es, (%%rax)\n"
		"movw %%ds, 8(%%rax)\n"
		"addq $32, %%rax\n"
		"call __next\n" // read the current rip.
		"__next:\n"
		"pop %%rbx\n"
		"addq $(out_iret -  __next), %%rbx\n"
		"movq %%rbx, 0(%%rax)\n" // rip
		"movw %%cs, 8(%%rax)\n"	 // cs
		"pushfq\n"
		"popq %%rbx\n"
		"mov %%rbx, 16(%%rax)\n" // eflags
		"mov %%rsp, 24(%%rax)\n" // rsp
		"movw %%ss, 32(%%rax)\n"
		"mov %%rcx, %%rdi\n"
		"call do_iret\n"
		"out_iret:\n"
		: : "g"(tf_cur), "g"(tf) : "memory");
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status)
{
	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(thread_current()->status == THREAD_RUNNING);
	while (!list_empty(&destruction_req))
	{
		struct thread *victim = list_entry(list_pop_front(&destruction_req), struct thread, elem);
		// list_remove(&victim->all_elem);
		palloc_free_page(victim);
	}
	thread_current()->status = status;
	schedule();
}

static void
schedule(void)
{
	struct thread *curr = running_thread();
	struct thread *next = next_thread_to_run();

	ASSERT(intr_get_level() == INTR_OFF);
	ASSERT(curr->status != THREAD_RUNNING);
	ASSERT(is_thread(next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate(next);
#endif

	if (curr != next)
	{
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread)
		{
			ASSERT(curr != next);
			list_push_back(&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch(next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid(void)
{
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire(&tid_lock);
	tid = next_tid++;
	lock_release(&tid_lock);

	return tid;
}

/* 두 스레드의 wakeup_tick 값을 비교하는 함수 a의 tick이 b의 tick보다 작으면 1(true), 크면 0(false) */
bool compare_ticks(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	struct thread *thread_a = list_entry(a, struct thread, elem);
	struct thread *thread_b = list_entry(b, struct thread, elem);
	return thread_a->local_tick < thread_b->local_tick;
}

// 내림차순 정렬 만드는 함수. a의 우선순위가 b의 우선순위보다 크면 1(true) 리턴. 반대의 경우 0(false) 리턴
bool compare_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	struct thread *thread_a = list_entry(a, struct thread, elem);
	struct thread *thread_b = list_entry(b, struct thread, elem);
	return thread_a->priority > thread_b->priority;
}

// 현재 실행 중인 스레드의 우선순위가 ready list의 스레드보다 낮다면 CPU를 양보(yield)하는 함수
void preemption_priority(void) /* project 1 priority */
{
	// 현재 실행 중인 스레드가 idle 스레드인 경우 아무 작업도 필요하지 않으므로 함수 종료
	// ready list가 비어 있는지 확인하고, 비어 있다면 다른 스레드가 대기 중이 아니므로 함수 종료
	if (thread_current() == idle_thread || list_empty(&ready_list))
	{
		return;
	}

	// ready list에서 가장 우선순위가 높은 스레드를 가리키는 포인터를 얻어옴
	struct list_elem *first = list_front(&ready_list);
	struct thread *first_t = list_entry(first, struct thread, elem);

	// 현재 실행 중인 스레드의 우선순위가 ready list의 첫 번째 스레드의 우선순위보다 낮은지 확인
	// 만약 그렇다면, 현재 스레드의 우선순위가 더 낮으므로 다른 스레드에게 CPU를 양보
	if (!list_empty(&ready_list) && thread_current()->priority < first_t->priority)
	{
		thread_yield(); // CPU 양보
	}
}

/**
 * @brief donate_priority 함수는 대기 중인 락의 소유자에게 현재 스레드의 우선순위를 기부합니다.
 *        최대 반복 횟수까지 대기 중인 락을 따라가며 우선순위 기부를 처리합니다.
 */
void donate_priority(void)
{
	int depth;
	struct thread *curr_thread = thread_current();

	// 대기 중인 락의 소유자에게 우선순위를 기부
	// while (curr_thread->wait_on_lock != NULL) // 이렇게 해도 문제 없음
	for (depth = 0; depth < MAX_NESTED_DEPTH; depth++) // MAX_NESTED_DEPTH를 설정하는 이유: 무한한 우선순위 기부 상황 방지
	{
		if (curr_thread->wait_on_lock == NULL)
		{
			// 더 이상 대기 중인 락이 없으면 반복 종료
			break;
		}
		else
		{
			// 대기 중인 락의 소유자에게 우선순위를 기부
			struct thread *holder = curr_thread->wait_on_lock->holder;
			if (holder->priority < curr_thread->priority)
			{
				// 대기 중인 락의 소유자의 우선순위를 현재 스레드의 우선순위로 업데이트
				holder->priority = curr_thread->priority;
			}

			// 대기 중인 락의 소유자를 현재 스레드로 설정하여 다음 반복을 위해 준비
			curr_thread = holder;
		}
	}
}

/**
 * @brief remove_donation 함수는 현재 스레드에게 기부된 스레드 중에서 주어진 lock에 대한 기부를 제거합니다.
 *        기부된 각 스레드를 순회하면서 해당 lock을 기다리는 스레드를 찾고, 그 스레드의 기부를 제거합니다.
 *
 * @param lock 기부를 제거할 lock
 */
void remove_donation(struct lock *lock)
{
	struct list_elem *e;
	struct thread *curr_thread = thread_current(); // thread_current() == lock->holder

	// 현재 스레드에게 기부된 모든 스레드를 순회
	for (e = list_begin(&curr_thread->donations); e != list_end(&curr_thread->donations); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, donation_elem); // 리스트의 요소를 스레드로 변환
		if (t->wait_on_lock == lock)									// 해당 스레드가 지정된 lock을 기다리고 있는지 확인
		{																// wait_on_lock이 이번에 relrease하는 lock이라면
			list_remove(&t->donation_elem);								// 해당 스레드의 기부를 제거(donation_elem 리스트에서 제거)
		}
	}
}

// refresh_priority 함수는 현재 스레드의 우선순위를 갱신하는 함수입니다.
// 현재 스레드의 원래 우선순위로 되돌리고, 다른 스레드로부터의 우선순위 기부가 있는 경우,
// 가장 높은 우선순위를 현재 스레드의 우선순위로 설정합니다.
void refresh_priority(void)
{
	struct thread *curr_thread = thread_current();

	curr_thread->priority = curr_thread->original_priority; // 현재 donation 받은 우선순위를 원래 자신의 우선순위로 바꾸기

	if (!list_empty(&curr_thread->donations))						// 현재 스레드에게 기부된 우선순위가 있는지 확인
	{																// donations list가 비어 있지 않다면(아직 우선순위를 줄 스레드가 있다면)
		list_sort(&curr_thread->donations, compare_priority, NULL); // donations 내림차순으로 정렬(가장 큰 우선순위 맨 앞으로)

		struct thread *front = list_entry(list_front(&curr_thread->donations), struct thread, donation_elem); // 가장 높은 우선순위를 가진 스레드를 가져옴
		if (front->priority > curr_thread->priority)														  // 가장 높은 우선순위가 현재 스레드의 우선순위보다 높으면
		{
			curr_thread->priority = front->priority; // 현재 스레드의 우선순위를 가장 높은 우선순위로 업데이트
		}
	}
}

/* 4BSD */

/* 스레드의 우선순위를 계산하는 함수.
   t->priority = PRI_MAX - (t->recent_cpu / 4) - (t->nice * 2) */
void mlfqs_calculate_priority(struct thread *t)
{
	t->priority = PRI_MAX - CONVERT_FP_TO_INT_NEAR(t->recent_cpu / 4) - (t->nice * 2);
}

/* 스레드의 최근 CPU 사용량을 계산하는 함수.
   decay = (2 * load_avg) / (2 * load_avg + 1)
   t->recent_cpu = decay * t->recent_cpu + t->nice */
void mlfqs_calculate_recent_cpu(struct thread *t)
{
	int decay = DIV_FP((load_avg * 2), ADD_FP_INT((load_avg * 2), 1));
	t->recent_cpu = ADD_FP_INT(MUL_FP(decay, t->recent_cpu), t->nice);
}

/* 평균 부하량(load_avg)을 계산하는 함수.
   load_avg = (59 / 60) * load_avg + (1 / 60) * ready_threads */
void mlfqs_calculate_load_avg(void)
{
	// int ready_threads = list_size(&ready_list);
	int ready_threads;

	/* 현재 실행 중인 스레드가 idle_thread인지 확인
       idle_thread는 CPU가 유휴 상태임을 나타냅니다. */
    if (thread_current() == idle_thread)
        /* CPU가 유휴 상태인 경우, ready_list에 있는 스레드 수를 그대로 사용 */
        ready_threads = list_size(&ready_list);
    else
        /* CPU가 유휴 상태가 아닌 경우, 현재 실행 중인 스레드도 준비 상태로 간주
           따라서, ready_list에 있는 스레드 수에 1을 더함 */
        ready_threads = list_size(&ready_list) + 1;
	
	// load_avg = MUL_FP(DIV_FP(CONVERT_INT_TO_FP(59), CONVERT_INT_TO_FP(60)), load_avg) + DIV_FP(CONVERT_INT_TO_FP(1), CONVERT_INT_TO_FP(60)) * ready_threads;
	// 위와 같음
	load_avg = MUL_FP((CONVERT_INT_TO_FP(59)/ 60), load_avg) + (CONVERT_INT_TO_FP(1) / 60) * ready_threads;
}

/* 최근 CPU 사용량을 증가시키는 함수.
   idle 스레드가 아닌 경우 현재 실행 중인 스레드의 recent_cpu를 1 증가시킴 */
void mlfqs_increase_recent_cpu(void)
{
	if (thread_current() != idle_thread)
	{
		// printf("not idle\n");
		thread_current()->recent_cpu = ADD_FP_INT(thread_current()->recent_cpu, 1);
	}
}

/* 모든 스레드의 우선순위를 재계산하는 함수. */
void mlfqs_recalculate_priority(void)
{
	struct list_elem *e;

	for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, all_elem);
		mlfqs_calculate_priority(t);
	}
}

/* 모든 스레드의 최근 CPU 사용량을 재계산하는 함수. */
void mlfqs_recalculate_recent_cpu(void)
{
	struct list_elem *e;

	for (e = list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
	{
		struct thread *t = list_entry(e, struct thread, all_elem);
		mlfqs_calculate_recent_cpu(t);
	}
}
