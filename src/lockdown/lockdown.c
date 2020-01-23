/*
 * ziga.rojec@fe.uni-lj.si
 * August 2019
 * Lockdown program for running untrusted code on a server.
 * 
 * This program is based on opensource project Geordi, the IRC C++ bot.
 * https://github.com/Eelis/geordi/tree/master/src/lockdown
 * 
 * This version is rewriten for usage in pure C. 
 * Works only in Lunux of course. 
 * 
 */

#include <stdio.h>
#include <signal.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <seccomp.h>
#include <sys/prctl.h>
#define _GNU_SOURCE
#include <linux/sched.h>        // CLONE_THREAD etc. macros




void e(char const * const what) { fprintf(stderr, "%s\n", what); }

void limitResource3(int resource, rlim_t  soft, rlim_t hard)
{
	struct rlimit rl = { soft, hard };
	if (setrlimit(resource, &rl) != 0) e("setrlimit");
}

void limitResource2(int resource, rlim_t l)
{
	limitResource3(resource, l, l);
}


typedef struct{
    int action;
    int syscall;
}rule;

#define NOFRULES 60
rule rules[NOFRULES] = {
    {SCMP_SYS(read),            SCMP_ACT_ALLOW},
    {SCMP_SYS(readv),           SCMP_ACT_ALLOW},
    {SCMP_SYS(pread64),         SCMP_ACT_ALLOW},
    {SCMP_SYS(write),           SCMP_ACT_ALLOW},
    {SCMP_SYS(writev),          SCMP_ACT_ALLOW},
    {SCMP_SYS(pwrite64),        SCMP_ACT_ALLOW},
    {SCMP_SYS(access),          SCMP_ACT_ALLOW},
    {SCMP_SYS(stat),            SCMP_ACT_ALLOW},
    {SCMP_SYS(fstat),           SCMP_ACT_ALLOW},
    {SCMP_SYS(open),            SCMP_ACT_ALLOW},
    {SCMP_SYS(openat),          SCMP_ACT_ALLOW},
    {SCMP_SYS(lseek),           SCMP_ACT_ALLOW},
    {SCMP_SYS(close),           SCMP_ACT_ALLOW},
    {SCMP_SYS(exit_group),      SCMP_ACT_ALLOW},
    {SCMP_SYS(execve),          SCMP_ACT_ALLOW},
    {SCMP_SYS(brk),             SCMP_ACT_ALLOW},
    {SCMP_SYS(mmap),            SCMP_ACT_ALLOW},
    {SCMP_SYS(mremap),          SCMP_ACT_ALLOW},
    {SCMP_SYS(arch_prctl),      SCMP_ACT_ALLOW},
    {SCMP_SYS(readlink),        SCMP_ACT_ALLOW},
    {SCMP_SYS(mprotect),        SCMP_ACT_ALLOW}, /* Needed by glibc's malloc, though curiously only when allocation fails (e.g. due to resource limits). */
    {SCMP_SYS(getcwd),          SCMP_ACT_ALLOW},
    {SCMP_SYS(gettimeofday),    SCMP_ACT_ALLOW},
    {SCMP_SYS(getdents),        SCMP_ACT_ALLOW},
    {SCMP_SYS(set_tid_address), SCMP_ACT_ALLOW},
    {SCMP_SYS(fallocate),       SCMP_ACT_ALLOW},
    {SCMP_SYS(clock_gettime),   SCMP_ACT_ALLOW},
    {SCMP_SYS(exit),            SCMP_ACT_ALLOW},
    {SCMP_SYS(sched_yield),     SCMP_ACT_ALLOW},
    {SCMP_SYS(pipe),            SCMP_ACT_ALLOW},
    {SCMP_SYS(pipe2),           SCMP_ACT_ALLOW},
    {SCMP_SYS(getdents64),      SCMP_ACT_ALLOW},
    {SCMP_SYS(lstat),           SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(geteuid),         SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(gettid),          SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(getpid),          SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(getrusage),       SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(socket),          SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(getrlimit),       SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(tgkill),          SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(ioctl),           SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(chmod),           SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(shmdt),           SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(sysinfo),         SCMP_ACT_ERRNO(EPERM)},
    {SCMP_SYS(futex),           SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(madvise),         SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(fstatfs),         SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(fcntl),           SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(mkdir),           SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(symlink),         SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(setitimer),       SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(unlink),          SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(dup2),            SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(munmap),          SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(umask),           SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(vfork),           SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(rt_sigprocmask),  SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(set_robust_list), SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(sigaltstack),     SCMP_ACT_ERRNO(0)},
    {SCMP_SYS(prlimit64),        SCMP_ACT_ERRNO(0)},    
    };



int main( int argc, char *argv[] )  {
	if( argc == 2 ) {
		printf("The filename supplied is %s\n", argv[1]);
	}
	else if( argc > 2 ) {
		printf("Too many arguments supplied.\n");
	}
	else {
		printf("One argument (filename) expected.\n");
	}
	struct rlimit old_lim;
	
	
	alarm(2);
	close(fileno(stdin));
	for (int fd = fileno(stderr); fd != 1024; ++fd) close(fd);
	dup2(fileno(stdout), fileno(stderr));   
	
	limitResource3(RLIMIT_CPU, 2, 3);
	limitResource2(RLIMIT_AS, 12*1024*1024);
	limitResource2(RLIMIT_DATA, 12*1024*1024);
	limitResource2(RLIMIT_FSIZE, 10*1024*1024);
	limitResource2(RLIMIT_LOCKS, 0);
	limitResource2(RLIMIT_MEMLOCK, 0);
	limitResource2(RLIMIT_NPROC, 16);
	
	scmp_filter_ctx const ctx = seccomp_init(SCMP_ACT_TRAP);
    if (!ctx) e("seccomp_init");
    
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1,
        SCMP_CMP(0, SCMP_CMP_MASKED_EQ, CLONE_THREAD, CLONE_THREAD)) != 0)
        e("seccomp_rule_add");

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 1,
        SCMP_CMP(0, SCMP_CMP_NE, SIGALRM)) != 0)
        e("seccomp_rule_add");
    
    for(int i = 0; i < NOFRULES; i++){
        if (seccomp_rule_add(ctx, rules[i].syscall, rules[i].action, 0) != 0) e("seccomp_rule_add");    
    }
	
	execv(argv[1], argv + 1);
	
	return 0;
}
