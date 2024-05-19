/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void sema_init(struct semaphore *sema, unsigned value)
{
	ASSERT(sema != NULL);

	sema->value = value;
	list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void sema_down(struct semaphore *sema)
{
	enum intr_level old_level;

	ASSERT(sema != NULL);
	ASSERT(!intr_context());

	old_level = intr_disable();
	while (sema->value == 0)
	{
		// list_push_back(&sema->waiters, &thread_current()->elem);
		list_insert_ordered(&sema->waiters, &thread_current()->elem, cmp_priority, NULL); // 우선순위 정렬 추가된 코드
		thread_block();
	}

	sema->value--;
	intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema)
{
	enum intr_level old_level;
	bool success;

	ASSERT(sema != NULL);

	old_level = intr_disable();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level(old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore *sema)
{
	// waiter list를 우선순위에 따라 정렬한다.
	// waiter list의 스레드 우선 순위를 변경하는 경우를 고려하라.

	enum intr_level old_level;

	ASSERT(sema != NULL);

	old_level = intr_disable(); // 인터럽트 비활성화

	if (!list_empty(&sema->waiters))
	{
		// waiters list 우선순위 순서로 정렬
		list_sort(&sema->waiters, cmp_priority, NULL);
		thread_unblock(list_entry(list_pop_front(&sema->waiters), struct thread, elem));
	}

	sema->value++;			   // value 1증가
	preemption_priority();	   // 선점 추가한 코드
	intr_set_level(old_level); // 인터럽트 활성화
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void)
{
	struct semaphore sema[2];
	int i;

	printf("Testing semaphores...");
	sema_init(&sema[0], 0);
	sema_init(&sema[1], 0);
	thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up(&sema[0]);
		sema_down(&sema[1]);
	}
	printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper(void *sema_)
{
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down(&sema[0]);
		sema_up(&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
/* LOCK을 초기화합니다. LOCK은 주어진 시간에 최대 한 개의 스레드만이 소유할 수 있습니다.
   우리의 락은 "재귀적"이지 않습니다. 즉, 현재 락을 보유하고 있는 스레드가 그 락을 획득하려고
   시도하는 것은 오류입니다.

   락은 초기 값이 1인 세마포어의 특수화입니다. 락과 세마포어의 차이점은 두 가지입니다.
	첫째, 세마포어는 1보다 큰 값을 가질 수 있지만, 락은 한 번에 한 개의 스레드만이 소유할 수 있습니다.
   둘째, 세마포어는 소유자가 없습니다. 즉, 한 스레드가 세마포어를 "다운"할 수 있고
   그 다음에 다른 스레드가 "업"할 수 있지만, 락에서는 같은 스레드가 락을 획득하고 해제해야 합니다.
   이러한 제한이 부담스러울 때, 락 대신에 세마포어를 사용하는 것이 좋은 신호입니다,. */
void lock_init(struct lock *lock)
{
	ASSERT(lock != NULL);

	lock->holder = NULL;
	sema_init(&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
/* LOCK을 획득합니다. 필요한 경우 사용 가능해질 때까지 대기합니다.
   이 락은 현재 스레드에 의해 이미 보유되어 있지 않아야 합니다.

   이 함수는 sleep 상태가 될 수 있으므로, 인터럽트 핸들러 내에서는 호출되어서는 안 됩니다.
   이 함수는 인터럽트가 비활성화된 상태에서 호출될 수 있지만,
   sleep 상태가 필요한 경우 인터럽트가 다시 켜집니다. */
void lock_acquire(struct lock *lock)
{
	// mlfqs 추가
	if (thread_mlfqs)
	{
		ASSERT(lock != NULL);
		ASSERT(!intr_context());
		ASSERT(!lock_held_by_current_thread(lock));

		sema_down(&lock->semaphore);
		lock->holder = thread_current();
		return;
	}

	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(!lock_held_by_current_thread(lock));

	struct thread *cur = thread_current(); // 락을 요청한 스레드를 가져온다.
	// 락의 연결 정보 저장 (nest 코드)
	if (lock->holder != NULL)
	{
		cur->wait_on_lock = lock; // 락 연결정보 저장

		// multiple 추가된 코드
		list_push_back(&lock->holder->donations, &cur->d_elem);

		// 제일 처음의 락 소유자가 나올때까지 우선순위 기부
		while (cur->wait_on_lock != NULL)
		{
			// 요청한 스레드의 우선순위가 높으면 기부
			if (cur->priority > cur->wait_on_lock->holder->priority)
			{
				cur->wait_on_lock->holder->priority = cur->priority;
			}

			// 다음 연결된 락소유자 찾기
			cur = cur->wait_on_lock->holder;
		}
	}

	sema_down(&lock->semaphore);
	thread_current()->wait_on_lock = NULL;
	lock->holder = thread_current();
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock *lock)
{
	bool success;

	ASSERT(lock != NULL);
	ASSERT(!lock_held_by_current_thread(lock));

	success = sema_try_down(&lock->semaphore);
	if (success)
		lock->holder = thread_current();
	return success;
}

// lock을 해지했을 때 대기 리스트에서 해당 스레드를 삭제하기 위한 함수
// 현재 스레드의 대기 리스트(donations)를 확인하여 해지할 lock을 보유하고 있는 스레드 삭제
void remove_with_lock(struct lock *lock)
{
	struct thread *t = thread_current();
	struct list_elem *curr = list_begin(&t->donations);
	struct thread *curr_thread = NULL;

	while (curr != list_end(&t->donations))
	{
		curr_thread = list_entry(curr, struct thread, d_elem);

		if (curr_thread->wait_on_lock == lock)
		{
			list_remove(&curr_thread->d_elem);
		}
		curr = list_next(curr);
	}
}

// 우선순위 업데이트 함수
void refresh_priority(void)
{
	struct thread *t = thread_current();
	t->priority = t->origin_priority;

	if (list_empty(&t->donations))
	{
		return;
	}

	list_sort(&t->donations, cmp_priority, NULL);

	struct list_elem *max_elem = list_front(&t->donations);
	struct thread *max_thread = list_entry(max_elem, struct thread, d_elem);

	if (t->priority < max_thread->priority)
	{
		t->priority = max_thread->priority;
	}
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
/* 현재 스레드가 소유하고 있는 LOCK을 해제합니다.
   이것은 lock_release 함수입니다.
   인터럽트 핸들러는 락을 획득할 수 없으므로,
인터럽트 핸들러 내에서 락을 해제하려고 시도하는 것은 의미가 없습니다. */
void lock_release(struct lock *lock)
{

	// mlfqs 추가
	if (thread_mlfqs)
	{
		ASSERT(lock != NULL);
		ASSERT(lock_held_by_current_thread(lock));

		lock->holder = NULL;
		sema_up(&lock->semaphore);
		return;
	}

	ASSERT(lock != NULL);
	ASSERT(lock_held_by_current_thread(lock));

	// 락을 해제하고, 업데이트해줌.
	remove_with_lock(lock);
	refresh_priority();
	lock->holder = NULL;

	sema_up(&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
/* 현재 스레드가 LOCK을 보유하고 있으면 true를 반환하고,
 그렇지 않으면 false를 반환합니다.
 (다른 스레드가 락을 보유하고 있는지 테스트하는 것은 경쟁 조건이
 될 수 있음을 참고하세요.) */
bool lock_held_by_current_thread(const struct lock *lock)
{
	ASSERT(lock != NULL);

	return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem
{
	struct list_elem elem;		/* List element. */
	struct semaphore semaphore; /* This semaphore. */
};

// cond_wait에서 비교해주는 함수
bool cmp_sema_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
	struct semaphore_elem *sema_a = list_entry(a, struct semaphore_elem, elem);
	struct semaphore_elem *sema_b = list_entry(b, struct semaphore_elem, elem);

	struct list *waiters_a = &(sema_a->semaphore.waiters);
	struct list *waiters_b = &(sema_b->semaphore.waiters);

	struct thread *thread_a = list_entry(list_begin(waiters_a), struct thread, elem);
	struct thread *thread_b = list_entry(list_begin(waiters_b), struct thread, elem);

	return thread_a->priority > thread_b->priority;
}

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond)
{
	ASSERT(cond != NULL);

	list_init(&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
/* 원자적으로 LOCK을 해제하고 COND가 다른 코드에 의해 신호를 받을 때까지 대기합니다.
   COND가 신호를 받은 후에는 반환하기 전에 LOCK을 다시 획득합니다. 이 함수를 호출하기 전에 LOCK이 보유되어 있어야 합니다.

   이 함수에 의해 구현된 모니터는 "Mesa" 스타일이며, "Hoare" 스타일이 아닙니다. 즉, 신호를 보내고 받는 것은 원자적인 연산이 아닙니다.
   따라서 일반적으로 호출자는 대기가 완료된 후에 조건을 다시 확인하고 필요한 경우 다시 대기해야 합니다.

   주어진 조건 변수는 단 하나의 락과만 연관되지만, 하나의 락은 여러 개의 조건 변수와 연관될 수 있습니다. 즉, 락에서 조건 변수로의 일대다 매핑이 있습니다.

   이 함수는 sleep 상태가 될 수 있으므로, 인터럽트 핸들러 내에서는 호출되어서는 안 됩니다.
   이 함수는 인터럽트가 비활성화된 상태에서 호출될 수 있지만, sleep 상태가 필요한 경우 인터럽트가 다시 켜집니다. */
void cond_wait(struct condition *cond, struct lock *lock)
{
	struct semaphore_elem waiter;

	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	sema_init(&waiter.semaphore, 0);
	// list_push_back(&cond->waiters, &waiter.elem); // 기존 코드
	list_insert_ordered(&cond->waiters, &waiter.elem, cmp_sema_priority, NULL); // 우선순위 정렬 추가된 코드

	lock_release(lock);
	sema_down(&waiter.semaphore);
	lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal(struct condition *cond, struct lock *lock UNUSED)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);
	ASSERT(!intr_context());
	ASSERT(lock_held_by_current_thread(lock));

	if (!list_empty(&cond->waiters))
	{
		// waiters list 우선순위 순서로 정렬
		list_sort(&cond->waiters, cmp_sema_priority, NULL);
		sema_up(&list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)->semaphore);
	}
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock)
{
	ASSERT(cond != NULL);
	ASSERT(lock != NULL);

	while (!list_empty(&cond->waiters))
		cond_signal(cond, lock);
}
