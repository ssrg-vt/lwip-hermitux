/*
 * Copyright (c) 2011, Stefan Lankes, RWTH Aachen University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the University nor the names of its contributors
 *      may be used to endorse or promote products derived from this
 *      software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <hermit/stddef.h>
#include <hermit/time.h>
#include <hermit/logging.h>

#include "lwip/opt.h"
#include "lwip/debug.h"
#include "lwip/sys.h"
#include "lwip/stats.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/err.h"

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

#if SYS_LIGHTWEIGHT_PROT && !NO_SYS
#if MAX_CORES > 1
static spinlock_irqsave_t lwprot_lock;
#endif
#endif

// forward declaration of a helper function
static void __rand_init(void);

/** Returns the current time in milliseconds,
 * may be the same as sys_jiffies or at least based on it. */
u32_t sys_now(void)
{
	return (get_clock_tick() / TIMER_FREQ) * 1000;
}

u32_t sys_jiffies(void)
{
	return (get_clock_tick() / TIMER_FREQ) * 1000;
}

#if !NO_SYS

/* sys_init(): init needed system resources
 * Note: At the moment there are none
 */
void sys_init(void)
{
#if SYS_LIGHTWEIGHT_PROT
#if MAX_CORES > 1
	spinlock_irqsave_init(&lwprot_lock);
#endif
#endif
	__rand_init();
}

extern int32_t boot_processor;

/* sys_thread_new(): Spawns a new thread with given attributes as supported
 * Note: In HermitCore this is realized as kernel tasks
 */
sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread, void *arg,
		int stacksize, int prio)
{
	int err;
	sys_thread_t id;

	LWIP_UNUSED_ARG(name);
	LWIP_UNUSED_ARG(stacksize);

	err = create_kernel_task_on_core(&id, (entry_point_t)thread, arg, prio, boot_processor);
	LOG_INFO("sys_thread_new: create_kernel_task err %d, id = %u, prio = %d\n", err, id, prio);

	return id;
}

/* sys_sem_free(): destroy's given semaphore
 * and releases system resources.
 * This semaphore also gets invalid.
 */
void sys_sem_free(sys_sem_t* sem)
{
	if (BUILTIN_EXPECT(sem != NULL, 1)) {
		sem->valid = FALSE;
		SYS_STATS_DEC(sem.used);
		sem_destroy(&sem->sem);
	}
}

/* sys_sem_valid(): returns if semaphore is valid 
 * at the moment
 */
int sys_sem_valid(sys_sem_t* sem)
{
	if (BUILTIN_EXPECT(sem == NULL, 0))
		return FALSE;
	return sem->valid;
}

/* sys_sem_new(): creates a new semaphre with given count.
 * This semaphore becomes valid
 */
err_t sys_sem_new(sys_sem_t* s, u8_t count)
{
	int err;

	if (BUILTIN_EXPECT(!s, 0))
		return ERR_VAL;

	err = sem_init(&s->sem, count);
	if (err < 0)
		return ERR_VAL;

	SYS_STATS_INC_USED(sem);
	s->valid = TRUE;

	return ERR_OK;
}

/* sys_sem_set_invalid(): this semapohore becomes invalid
 * Note: this does not mean it is destroyed
 */
void sys_sem_set_invalid(sys_sem_t * sem)
{
	sem->valid = FALSE;
}

/* sys_sem_signal(): this semaphore is signaled
 *
 */
void sys_sem_signal(sys_sem_t* sem)
{
	sem_post(&sem->sem);
}

/* sys_arch_sem_wait): wait for the given semaphore for
 * a given timeout
 * Note: timeout = 0 means wait forever
 */
u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout)
{
	int err;

	err = sem_wait(&sem->sem, timeout);
	if (!err)
		return 0;

	return SYS_ARCH_TIMEOUT;
}

/* sys_mbox_valid() : returns if the given mailbox
 * is valid
 */
int sys_mbox_valid(sys_mbox_t * mbox)
{
	if (BUILTIN_EXPECT(mbox == NULL, 0))
		return FALSE;
	return mbox->valid;
}

/* sys_arch_mbox_fetch(): wait for the given mailbox for a specified
 * amount of time.
 * Note: timeout = 0 means wait forever
 */
u32_t sys_arch_mbox_fetch(sys_mbox_t * mbox, void **msg, u32_t timeout)
{
	int err;

	err = mailbox_ptr_fetch(&mbox->mailbox, msg, timeout);
	//LWIP_DEBUGF(SYS_DEBUG, ("sys_arch_mbox_fetch: %d\n", err));
	if (!err)
		return 0;

	return SYS_ARCH_TIMEOUT;
}

/* sys_mbox_free() : free the given mailbox, release the system resources
 * and set mbox to invalid
 */
void sys_mbox_free(sys_mbox_t* mbox)
{
	if (BUILTIN_EXPECT(mbox != NULL, 1)) {
		mbox->valid = FALSE;
		SYS_STATS_DEC(mbox.used);
		mailbox_ptr_destroy(&mbox->mailbox);
	}
}

/* sys_arch_mbox_tryfetch(): poll for new data in mailbox
 *
 */
u32_t sys_arch_mbox_tryfetch(sys_mbox_t* mbox, void** msg)
{
	int ret = mailbox_ptr_tryfetch(&mbox->mailbox, msg);
	if (ret)
		return SYS_MBOX_EMPTY;
	return 0;
}

/* sys_mbox_new(): create a new mailbox with a minimum size of "size"
 *
 */
err_t sys_mbox_new(sys_mbox_t* mb, int size)
{
	int err;
	
	//LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_new: create mailbox with the minimum size: %d\n", size));
	if (BUILTIN_EXPECT(!mb, 0))
		return ERR_VAL;

	mb->valid = TRUE;
	SYS_STATS_INC_USED(mbox);
	err = mailbox_ptr_init(&mb->mailbox);
	if (err)
		return ERR_MEM;
	return ERR_OK;
}

/* sys_mbox_set_invalid(): set the given mailbox to invald
 * Note: system resources are NOT freed
 */
void sys_mbox_set_invalid(sys_mbox_t* mbox)
{
	mbox->valid = FALSE;
}

/* sys_mbox_trypost(): try to post data to the mailbox
 *
 */
err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
	int err;

	err = mailbox_ptr_trypost(&mbox->mailbox, msg);
	if (err != 0) {
		LWIP_DEBUGF(SYS_DEBUG, ("sys_mbox_trypost: %d\n", err));
		return ERR_MEM;
	}

	return ERR_OK;
}

/* sys_mbox_post(): post new data to the mailbox
 *
 */
void sys_mbox_post(sys_mbox_t* mbox, void* msg)
{
	mailbox_ptr_post(&mbox->mailbox, msg);
}

/* sys_mutex_lock(): lock the given mutex
 * Note: There is no specific mutex in 
 * HermitCore so we use a semaphore with
 * 1 element
 */
void sys_mutex_lock(sys_mutex_t* mutex)
{
	sem_wait(mutex, 0);
}

/* sys_mutex_unlock(): unlock the given mutex
 *
 */
void sys_mutex_unlock(sys_mutex_t* mutex)
{
	sem_post(mutex);
}

/* sys_mutex_new(): create a new mutex
 *
 */
err_t sys_mutex_new(sys_mutex_t * m)
{
	if (BUILTIN_EXPECT(!m, 0))
		return ERR_VAL;
	SYS_STATS_INC_USED(mutex);
	sem_init(m, 1);
	return ERR_OK;
}

#if SYS_LIGHTWEIGHT_PROT
#if MAX_CORES > 1
sys_prot_t sys_arch_protect(void)
{
	spinlock_irqsave_lock(&lwprot_lock);
	return ERR_OK;
}

void sys_arch_unprotect(sys_prot_t pval)
{
	LWIP_UNUSED_ARG(pval);
	spinlock_irqsave_unlock(&lwprot_lock);
}
#endif
#endif

int* __getreent(void);

static inline int* libc_errno(void)
{
	return __getreent();
}

#if LWIP_SOCKET

int hermit_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	LOG_INFO("before lwip accept %d\n", s);
	int fd = lwip_accept(s & ~LWIP_FD_BIT, addr, addrlen);
	LOG_INFO("after lwip accept %d\n", s);

	//if (fd < 0)
	//{
	//	*libc_errno() = errno;
	//	return -1;
	//}

	if(fd < 0)
		return fd;

	return fd | LWIP_FD_BIT;
}

int hermit_bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	int ret = lwip_bind(s & ~LWIP_FD_BIT, name, namelen);

#if 0
	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
	int ret = lwip_getpeername(s & ~LWIP_FD_BIT, name, namelen);

#if 0
	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_close(int s)
{
	int ret = lwip_close(s & ~LWIP_FD_BIT);

#if 0
	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
	int ret = lwip_getsockname(s & ~LWIP_FD_BIT, name, namelen);

#if 0
	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	int ret = lwip_getsockopt(s & ~LWIP_FD_BIT, level, optname, optval, optlen);

#if 0
	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_setsockopt(int s, int level, int optname, const void *optval, socklen_t optlen)
{
	int ret = lwip_setsockopt(s & ~LWIP_FD_BIT, level, optname, optval, optlen);

#if 0
	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	int ret = lwip_connect(s & ~LWIP_FD_BIT, name, namelen);

#if 0
	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_listen(int s, int backlog)
{
	int ret = lwip_listen(s & ~LWIP_FD_BIT, backlog);

#if 0
	if (ret)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_recv(int s, void *mem, size_t len, int flags)
{
	int ret = lwip_recv(s & ~LWIP_FD_BIT, mem, len, flags);

#if 0
	if (ret < 0)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_recvfrom(int s, void *mem, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen)
{
	int ret = lwip_recvfrom(s & ~LWIP_FD_BIT, mem, len, flags, from, fromlen);

#if 0
	if (ret < 0)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_send(int s, const void *dataptr, size_t size, int flags)
{
	int ret = lwip_send(s & ~LWIP_FD_BIT, dataptr, size, flags);

#if 0
	if (ret < 0)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_sendto(int s, const void *dataptr, size_t size, int flags, const struct sockaddr *to, socklen_t tolen)
{
	int ret = lwip_sendto(s & ~LWIP_FD_BIT, dataptr, size, flags, to, tolen);

#if 0
	if (ret < 0)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	return ret;
}

int hermit_socket(int domain, int type, int protocol)
{
	int fd = lwip_socket(domain, type, protocol);
	kprintf("internal socket: %d\n", fd);

#if 0
	if (fd < 0)
	{
		*libc_errno() = errno;
		return -1;
	}
#endif

	if(fd < 0)
		return fd;

	return fd | LWIP_FD_BIT;
}

#define FD_SETSIZE 8192

typedef struct {
		unsigned long fds_bits[FD_SETSIZE / 8 / sizeof(long)];
} fd_setx;

/* Use the same code as musl to access the fd_sets */
#define FDX_ZERO(s) do { int __i; unsigned long *__b=(s)->fds_bits; for(__i=sizeof (fd_set)/sizeof (long); __i; __i--) *__b++=0; } while(0)
#define FDX_SET(d, s)   ((s)->fds_bits[(d)/(8*sizeof(long))] |= (1UL<<((d)%(8*sizeof(long)))))
#define FDX_CLR(d, s)   ((s)->fds_bits[(d)/(8*sizeof(long))] &= ~(1UL<<((d)%(8*sizeof(long)))))
#define FDX_ISSET(d, s) !!((s)->fds_bits[(d)/(8*sizeof(long))] & (1UL<<((d)%(8*sizeof(long)))))

int hermit_select(int maxfdp1, fd_setx *readset, fd_setx *writeset, fd_setx *exceptset, struct timeval *timeout)
{
	int ret, i;
	fd_setx rs, ws, es;

	FDX_ZERO(&rs); FDX_ZERO(&ws); FDX_ZERO(&es);

//	LOG_INFO("hermit_select: maxfdp1: %d\n", maxfdp1);

	for(i=LWIP_FD_BIT; i<maxfdp1; i++) {
		if(readset && FDX_ISSET(i, readset)) {
//			LOG_INFO(" fd read set map %d -> %d\n", i, i & ~LWIP_FD_BIT);
//			FDX_CLR(i, readset);
			FDX_SET(i & ~LWIP_FD_BIT, &rs);
		}

		if(writeset && FDX_ISSET(i, writeset)) {
//			LOG_INFO(" fd write set map %d -> %d\n", i, i & ~LWIP_FD_BIT);
//			FDX_CLR(i, writeset);
			FDX_SET(i & ~LWIP_FD_BIT, &ws);
		}

		if(exceptset && FDX_ISSET(i, exceptset)) {
//			LOG_INFO(" fd except set map %d -> %d\n", i, i & ~LWIP_FD_BIT);
//			FDX_CLR(i, exceptset);
			FDX_SET(i & ~LWIP_FD_BIT, &es);
		}
	}

	ret = lwip_select(maxfdp1-LWIP_FD_BIT, &rs, &ws, &es, timeout);

	if(readset)
		FDX_ZERO(readset);
	if(writeset)
		FDX_ZERO(writeset);
	if(exceptset)
		FDX_ZERO(exceptset);

//	LOG_INFO(" <--- select\n");

#if 0
	if (ret < 0) {
		*libc_errno() = errno;
		return -1;
	}
#endif

	if(ret < 0)
		return ret;

	for(i=0; i<maxfdp1-LWIP_FD_BIT; i++) {
		if(readset && FDX_SET(i, &rs)) {
			LOG_INFO(" fd read set map back %d -> %d\n", i, i | LWIP_FD_BIT);
//			FDX_CLR(i, readset);
			FDX_SET(i | LWIP_FD_BIT, readset);
		}

		if(writeset && FDX_SET(i, &ws)) {
//			LOG_INFO(" fd write set map back %d -> %d\n", i, i | LWIP_FD_BIT);
//			FDX_CLR(i, writeset);
			FDX_SET(i | LWIP_FD_BIT, writeset);
		}

		if(exceptset && FDX_SET(i, &es)) {
//			LOG_INFO(" fd except set map back %d -> %d\n", i, i | LWIP_FD_BIT);
//			FDX_CLR(i, exceptset);
			FDX_SET(i | LWIP_FD_BIT, exceptset);
		}

	}

	// check if another task is already ready
	sys_yield();

	return ret;
}

int hermit_fcntl(int s, int cmd, int val)
{
	return lwip_fcntl(s & ~LWIP_FD_BIT, cmd, val);
}

int hermit_shutdown(int socket, int how)
{
	return lwip_shutdown(socket & ~LWIP_FD_BIT, how);
}

#if LWIP_DNS

// TODO: replace dummy function
int hermit_gethostname(char *name, size_t len)
{
	//strncpy(name, "hermit", len);
	
	return sys_gethostname(name, len);

//	return 0;
}

struct hostent *hermit_gethostbyname(const char* name)
{
	return lwip_gethostbyname(name);
}

int hermit_gethostbyname_r(const char *name, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
	return lwip_gethostbyname_r(name, ret, buf, buflen, result, h_errnop);
}

int hermit_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
	return lwip_getaddrinfo(node, service, hints, res);
}

void hermit_freeaddrinfo(struct addrinfo *res)
{
	lwip_freeaddrinfo(res);
}

#endif /* LWIP_DNS */

#endif /* LWIP_SOCKET */

#endif /* !NO_SYS */

/* Pseudo-random generator based on Minimal Standard by
   Lewis, Goodman, and Miller in 1969.
 
   I[j+1] = a*I[j] (mod m)

   where a = 16807
         m = 2147483647

   Using Schrage's algorithm, a*I[j] (mod m) can be rewritten as:
  
     a*(I[j] mod q) - r*{I[j]/q}      if >= 0
     a*(I[j] mod q) - r*{I[j]/q} + m  otherwise

   where: {} denotes integer division 
          q = {m/a} = 127773 
          r = m (mod a) = 2836

   note that the seed value of 0 cannot be used in the calculation as
   it results in 0 itself
*/

#define RAND_MAX	0x7fffffff

static unsigned int rand_seed = 0;
static spinlock_irqsave_t rand_lock = SPINLOCK_IRQSAVE_INIT;

static void __rand_init(void)
{
	rand_seed = get_rdtsc() % 127;
}

static inline int __rand(unsigned int *seed)
{
        long k;
        long s = (long)(*seed);
        if (s == 0)
          s = 0x12345987;
        k = s / 127773;
        s = 16807 * (s - k * 127773) - 2836 * k;
        if (s < 0)
          s += 2147483647;
        (*seed) = (unsigned int)s;
        return (int)(s & RAND_MAX);
}

int lwip_rand(void)
{
	int r;

#ifdef __x86_64__
	if (has_rdrand()) {
		r = rdrand() % RAND_MAX;
		return r;
	}
#endif

	spinlock_irqsave_lock(&rand_lock);
	r = __rand(&rand_seed);
	spinlock_irqsave_unlock(&rand_lock);

	return r;
}

#if LWIP_NETCONN_SEM_PER_THREAD
static __thread sys_sem_t* netconn_sem = NULL;

sys_sem_t* sys_arch_netconn_sem_get(void)
{
	return netconn_sem;
}

void sys_arch_netconn_sem_alloc(void)
{
	sys_sem_t *sem;
	err_t err;

	if (netconn_sem != NULL)
		return;

	sem = netconn_sem = (sys_sem_t*)kmalloc(sizeof(sys_sem_t));
	LWIP_ASSERT("failed to allocate memory for TLS semaphore", sem != NULL);
	err = sys_sem_new(sem, 0);
	LWIP_ASSERT("failed to initialise TLS semaphore", err == ERR_OK);
	LOG_INFO("Task %d creates a netconn semaphore at %p\n", per_core(current_task)->id, netconn_sem);
}

void sys_arch_netconn_sem_free(void)
{
	if (netconn_sem != NULL)
		kfree(netconn_sem);
}
#endif /* LWIP_NETCONN_SEM_PER_THREAD */

