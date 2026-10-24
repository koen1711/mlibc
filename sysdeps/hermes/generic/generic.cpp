#include <abi-bits/errno.h>
#include <abi-bits/fcntl.h>
#include <bits/ensure.h>
#include <bits/syscall.h>
#include <limits.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/tcb.hpp>
#include <mlibc/thread.hpp>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#if __MLIBC_POSIX_OPTION && !MLIBC_BUILDING_RTLD
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>
#endif

#include "syscallnos.h"

#define ARCH_SET_FS 0x1002

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1

#define CLONE_VM 0x00000100
#define CLONE_FS 0x00000200
#define CLONE_FILES 0x00000400
#define CLONE_SIGHAND 0x00000800
#define CLONE_THREAD 0x00010000
#define CLONE_SYSVSEM 0x00040000
#define CLONE_SETTLS 0x00080000
#define CLONE_PARENT_SETTID 0x00100000

#define TCGETS 0x5401
#define TCSETS 0x5402
#define TCSETSW 0x5403
#define TCSETSF 0x5404
#define TCSBRK 0x5409
#define TCFLSH 0x540B
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414

#define PR_SET_NAME 15

extern "C" int __mlibc_spawn_thread(int flags, void *stack, void *pid_out, void *child_tid, void *tcb);
extern "C" void __mlibc_signal_restore(void);

namespace mlibc {

namespace {

using sc_word_t = __sc_word_t;

inline sc_word_t sc_cast(long x) { return x; }
inline sc_word_t sc_cast(const void *x) { return reinterpret_cast<sc_word_t>(x); }

inline sc_word_t do_nargs_syscall(int sc) {
	return __do_syscall0(sc);
}
inline sc_word_t do_nargs_syscall(int sc, sc_word_t a1) {
	return __do_syscall1(sc, a1);
}
inline sc_word_t do_nargs_syscall(int sc, sc_word_t a1, sc_word_t a2) {
	return __do_syscall2(sc, a1, a2);
}
inline sc_word_t do_nargs_syscall(int sc, sc_word_t a1, sc_word_t a2, sc_word_t a3) {
	return __do_syscall3(sc, a1, a2, a3);
}
inline sc_word_t do_nargs_syscall(int sc, sc_word_t a1, sc_word_t a2, sc_word_t a3, sc_word_t a4) {
	return __do_syscall4(sc, a1, a2, a3, a4);
}
inline sc_word_t do_nargs_syscall(int sc, sc_word_t a1, sc_word_t a2, sc_word_t a3, sc_word_t a4,
		sc_word_t a5) {
	return __do_syscall5(sc, a1, a2, a3, a4, a5);
}
inline sc_word_t do_nargs_syscall(int sc, sc_word_t a1, sc_word_t a2, sc_word_t a3, sc_word_t a4,
		sc_word_t a5, sc_word_t a6) {
	return __do_syscall6(sc, a1, a2, a3, a4, a5, a6);
}

template<typename... T>
sc_word_t do_syscall(int sc, T... args) {
	return do_nargs_syscall(sc, sc_cast(args)...);
}

// Syscalls return -errno on failure.
int sc_error(sc_word_t ret) {
	if (static_cast<unsigned long>(ret) > -4096UL)
		return -ret;
	return 0;
}

int sc_status(sc_word_t ret) {
	return sc_error(ret);
}

} // namespace

void Sysdeps<LibcPanic>::operator()() {
	sysdep<LibcLog>("!!! mlibc panic !!!");
	sysdep<Exit>(-1);
	__builtin_trap();
}

void Sysdeps<LibcLog>::operator()(const char *msg) {
	ssize_t unused;
	sysdep<Write>(2, msg, strlen(msg), &unused);
	sysdep<Write>(2, "\n", 1, &unused);
}

pid_t Sysdeps<FutexTid>::operator()() {
	return do_syscall(SYS_gettid);
}

int Sysdeps<Isatty>::operator()(int fd) {
	char buf[64];
	return sc_status(do_syscall(SYS_ioctl, fd, TCGETS, buf));
}

int Sysdeps<Write>::operator()(int fd, void const *buf, size_t size, ssize_t *ret) {
	auto r = do_syscall(SYS_write, fd, buf, size);
	if (int e = sc_error(r))
		return e;
	if (ret)
		*ret = r;
	return 0;
}

int Sysdeps<Read>::operator()(int fd, void *buf, size_t size, ssize_t *ret) {
	auto r = do_syscall(SYS_read, fd, buf, size);
	if (int e = sc_error(r))
		return e;
	*ret = r;
	return 0;
}

int Sysdeps<Pread>::operator()(int fd, void *buf, size_t n, off_t off, ssize_t *ret) {
	auto r = do_syscall(SYS_pread64, fd, buf, n, off);
	if (int e = sc_error(r))
		return e;
	*ret = r;
	return 0;
}

int Sysdeps<Open>::operator()(const char *path, int flags, mode_t mode, int *fd) {
	auto r = do_syscall(SYS_openat, AT_FDCWD, path, flags, mode);
	if (int e = sc_error(r))
		return e;
	*fd = r;
	return 0;
}

int Sysdeps<Flock>::operator()(int fd, int options) {
	return sc_status(do_syscall(SYS_flock, fd, options));
}

int Sysdeps<OpenDir>::operator()(const char *path, int *handle) {
	return sysdep<Open>(path, O_DIRECTORY | O_RDONLY, 0, handle);
}

int Sysdeps<ReadEntries>::operator()(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
	auto r = do_syscall(SYS_getdents64, handle, buffer, max_size);
	if (int e = sc_error(r))
		return e;
	*bytes_read = r;
	return 0;
}

int Sysdeps<Close>::operator()(int fd) {
	return sc_status(do_syscall(SYS_close, fd));
}

int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
	auto r = do_syscall(SYS_lseek, fd, offset, whence);
	if (int e = sc_error(r))
		return e;
	*new_offset = r;
	return 0;
}

int Sysdeps<Stat>::operator()(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf) {
	if (fsfdt == fsfd_target::path)
		fd = AT_FDCWD;
	else if (fsfdt == fsfd_target::fd)
		flags |= AT_EMPTY_PATH;
	else
		__ensure(fsfdt == fsfd_target::fd_path);
	if (!path)
		path = "";
	return sc_status(do_syscall(SYS_newfstatat, fd, path, statbuf, flags));
}

int Sysdeps<VmMap>::operator()(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	if (offset % 4096)
		return EINVAL;
	auto r = do_syscall(SYS_mmap, hint, size, prot, flags, fd, offset);
	if (int e = sc_error(r))
		return e;
	*window = (void *)r;
	return 0;
}

int Sysdeps<VmUnmap>::operator()(void *pointer, size_t size) {
	return sc_status(do_syscall(SYS_munmap, pointer, size));
}

int Sysdeps<VmProtect>::operator()(void *pointer, size_t size, int prot) {
	return sc_status(do_syscall(SYS_mprotect, pointer, size, prot));
}

int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
	return sysdep<VmMap>(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, pointer);
}

int Sysdeps<AnonFree>::operator()(void *pointer, size_t size) {
	return sysdep<VmUnmap>(pointer, size);
}

int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
	struct timespec ts = {};
	if (int e = sc_error(do_syscall(SYS_clock_gettime, clock, &ts)))
		return e;
	*secs = ts.tv_sec;
	*nanos = ts.tv_nsec;
	return 0;
}

int Sysdeps<ClockGetres>::operator()(int clock, time_t *secs, long *nanos) {
	struct timespec ts = {};
	if (int e = sc_error(do_syscall(SYS_clock_getres, clock, &ts)))
		return e;
	*secs = ts.tv_sec;
	*nanos = ts.tv_nsec;
	return 0;
}

int Sysdeps<Sleep>::operator()(time_t *secs, long *nanos) {
	struct timespec req = {.tv_sec = *secs, .tv_nsec = *nanos};
	struct timespec rem = {};
	if (int e = sc_error(do_syscall(SYS_nanosleep, &req, &rem)))
		return e;
	*secs = rem.tv_sec;
	*nanos = rem.tv_nsec;
	return 0;
}

int Sysdeps<TcbSet>::operator()(void *pointer) {
	return sc_status(do_syscall(SYS_arch_prctl, ARCH_SET_FS, pointer));
}

void Sysdeps<Exit>::operator()(int status) {
	do_syscall(SYS_exit_group, status);
	__builtin_trap();
}

void Sysdeps<ThreadExit>::operator()() {
	do_syscall(SYS_exit, 0);
	__builtin_trap();
}

int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const struct timespec *time) {
	return sc_status(do_syscall(SYS_futex, pointer, FUTEX_WAIT, expected, time));
}

int Sysdeps<FutexWake>::operator()(int *pointer, bool all) {
	return sc_status(do_syscall(SYS_futex, pointer, FUTEX_WAKE, all ? INT_MAX : 1));
}

int Sysdeps<Rmdir>::operator()(const char *path) {
	return sc_status(do_syscall(SYS_unlinkat, AT_FDCWD, path, AT_REMOVEDIR));
}

int Sysdeps<Unlinkat>::operator()(int dirfd, const char *path, int flags) {
	return sc_status(do_syscall(SYS_unlinkat, dirfd, path, flags));
}

int Sysdeps<Rename>::operator()(const char *path, const char *new_path) {
	return sc_status(do_syscall(SYS_renameat, AT_FDCWD, path, AT_FDCWD, new_path));
}

int Sysdeps<Sigprocmask>::operator()(int how, const sigset_t *set, sigset_t *old) {
	return sc_status(do_syscall(SYS_rt_sigprocmask, how, set, old, sizeof(uint64_t)));
}

int Sysdeps<Fork>::operator()(pid_t *child) {
	auto r = do_syscall(SYS_fork);
	if (int e = sc_error(r))
		return e;
	*child = r;
	return 0;
}

int Sysdeps<Waitpid>::operator()(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid) {
	auto r = do_syscall(SYS_wait4, pid, status, flags, ru);
	if (int e = sc_error(r))
		return e;
	*ret_pid = r;
	return 0;
}

int Sysdeps<Execve>::operator()(const char *path, char *const argv[], char *const envp[]) {
	return sc_status(do_syscall(SYS_execve, path, argv, envp));
}

void Sysdeps<Yield>::operator()() {
	do_syscall(SYS_sched_yield);
}

pid_t Sysdeps<GetPid>::operator()() {
	return do_syscall(SYS_getpid);
}

int Sysdeps<Kill>::operator()(pid_t pid, int sig) {
	return sc_status(do_syscall(SYS_kill, pid, sig));
}

#if !MLIBC_BUILDING_RTLD

int Sysdeps<Clone>::operator()(void *tcb, pid_t *pid_out, void *stack) {
	unsigned long flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
		| CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID;
	auto ret = __mlibc_spawn_thread(flags, stack, pid_out, nullptr, tcb);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<Sigaction>::operator()(int signum, const struct sigaction *act, struct sigaction *oldact) {
	struct ksigaction {
		void (*handler)(int);
		unsigned long flags;
		void (*restorer)(void);
		uint64_t mask;
	};

	struct ksigaction kernel_act, kernel_oldact;
	if (act) {
		kernel_act.handler = act->sa_handler;
		kernel_act.flags = static_cast<unsigned long>(static_cast<unsigned int>(act->sa_flags)) | SA_RESTORER;
		kernel_act.restorer = __mlibc_signal_restore;
		memcpy(&kernel_act.mask, &act->sa_mask, sizeof(kernel_act.mask));
	}

	auto ret = do_syscall(SYS_rt_sigaction, signum, act ? &kernel_act : nullptr,
			oldact ? &kernel_oldact : nullptr, sizeof(kernel_act.mask));
	if (int e = sc_error(ret))
		return e;

	if (oldact) {
		memset(oldact, 0, sizeof(*oldact));
		oldact->sa_handler = kernel_oldact.handler;
		oldact->sa_flags = kernel_oldact.flags;
		oldact->sa_restorer = kernel_oldact.restorer;
		memcpy(&oldact->sa_mask, &kernel_oldact.mask, sizeof(kernel_oldact.mask));
	}
	return 0;
}

#if __MLIBC_POSIX_OPTION

int Sysdeps<Readv>::operator()(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_read) {
	auto r = do_syscall(SYS_readv, fd, iovs, iovc);
	if (int e = sc_error(r))
		return e;
	*bytes_read = r;
	return 0;
}

int Sysdeps<Writev>::operator()(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_written) {
	auto r = do_syscall(SYS_writev, fd, iovs, iovc);
	if (int e = sc_error(r))
		return e;
	if (bytes_written)
		*bytes_written = r;
	return 0;
}

int Sysdeps<Pwrite>::operator()(int fd, const void *buf, size_t n, off_t off, ssize_t *bytes_written) {
	auto r = do_syscall(SYS_pwrite64, fd, buf, n, off);
	if (int e = sc_error(r))
		return e;
	*bytes_written = r;
	return 0;
}

int Sysdeps<Access>::operator()(const char *path, int mode) {
	return sc_status(do_syscall(SYS_faccessat, AT_FDCWD, path, mode, 0));
}

int Sysdeps<Faccessat>::operator()(int dirfd, const char *pathname, int mode, int flags) {
	return sc_status(do_syscall(SYS_faccessat2, dirfd, pathname, mode, flags));
}

int Sysdeps<Dup>::operator()(int fd, int flags, int *newfd) {
	auto r = flags ? do_syscall(SYS_fcntl, fd, F_DUPFD_CLOEXEC, 0) : do_syscall(SYS_dup, fd);
	if (int e = sc_error(r))
		return e;
	*newfd = r;
	return 0;
}

int Sysdeps<Dup2>::operator()(int fd, int flags, int newfd) {
	if (fd == newfd && !flags) {
		auto r = do_syscall(SYS_fcntl, fd, F_GETFD, 0);
		return sc_error(r);
	}
	return sc_status(do_syscall(SYS_dup3, fd, newfd, flags));
}

int Sysdeps<Readlink>::operator()(const char *path, void *buf, size_t bufsiz, ssize_t *len) {
	auto r = do_syscall(SYS_readlinkat, AT_FDCWD, path, buf, bufsiz);
	if (int e = sc_error(r))
		return e;
	*len = r;
	return 0;
}

int Sysdeps<Readlinkat>::operator()(int dirfd, const char *path, void *buffer, size_t max_size, ssize_t *length) {
	auto r = do_syscall(SYS_readlinkat, dirfd, path, buffer, max_size);
	if (int e = sc_error(r))
		return e;
	*length = r;
	return 0;
}

int Sysdeps<Truncate>::operator()(const char *path, off_t length) {
	return sc_status(do_syscall(SYS_truncate, path, length));
}

int Sysdeps<Ftruncate>::operator()(int fd, size_t size) {
	return sc_status(do_syscall(SYS_ftruncate, fd, size));
}

int Sysdeps<Openat>::operator()(int dirfd, const char *path, int flags, mode_t mode, int *fd) {
	auto r = do_syscall(SYS_openat, dirfd, path, flags, mode);
	if (int e = sc_error(r))
		return e;
	*fd = r;
	return 0;
}

int Sysdeps<Socket>::operator()(int domain, int type, int protocol, int *fd) {
	auto r = do_syscall(SYS_socket, domain, type, protocol);
	if (int e = sc_error(r))
		return e;
	*fd = r;
	return 0;
}

int Sysdeps<MsgSend>::operator()(int fd, const struct msghdr *msg, int flags, ssize_t *length) {
	const_cast<msghdr *>(msg)->__pad0 = 0;
	const_cast<msghdr *>(msg)->__pad1 = 0;
	for (auto cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
		cmsg->__pad = 0;

	auto r = do_syscall(SYS_sendmsg, fd, msg, flags);
	if (int e = sc_error(r))
		return e;
	*length = r;
	return 0;
}

int Sysdeps<Sendto>::operator()(int fd, const void *buffer, size_t size, int flags, const struct sockaddr *sock_addr,
		socklen_t addr_length, ssize_t *length) {
	auto r = do_syscall(SYS_sendto, fd, buffer, size, flags, sock_addr, addr_length);
	if (int e = sc_error(r))
		return e;
	*length = r;
	return 0;
}

int Sysdeps<MsgRecv>::operator()(int fd, struct msghdr *msg, int flags, ssize_t *length) {
	msg->__pad0 = 0;
	msg->__pad1 = 0;

	auto r = do_syscall(SYS_recvmsg, fd, msg, flags);
	if (int e = sc_error(r))
		return e;
	*length = r;
	return 0;
}

int Sysdeps<Recvfrom>::operator()(int fd, void *buffer, size_t size, int flags, struct sockaddr *sock_addr,
		socklen_t *addr_length, ssize_t *length) {
	auto r = do_syscall(SYS_recvfrom, fd, buffer, size, flags, sock_addr, addr_length);
	if (int e = sc_error(r))
		return e;
	*length = r;
	return 0;
}

int Sysdeps<Listen>::operator()(int fd, int backlog) {
	return sc_status(do_syscall(SYS_listen, fd, backlog));
}

gid_t Sysdeps<GetGid>::operator()() {
	return do_syscall(SYS_getgid);
}

gid_t Sysdeps<GetEgid>::operator()() {
	return do_syscall(SYS_getegid);
}

uid_t Sysdeps<GetUid>::operator()() {
	return do_syscall(SYS_getuid);
}

uid_t Sysdeps<GetEuid>::operator()() {
	return do_syscall(SYS_geteuid);
}

pid_t Sysdeps<GetTid>::operator()() {
	return do_syscall(SYS_gettid);
}

pid_t Sysdeps<GetPpid>::operator()() {
	return do_syscall(SYS_getppid);
}

int Sysdeps<GetPgid>::operator()(pid_t pid, pid_t *pgid) {
	auto r = do_syscall(SYS_getpgid, pid);
	if (int e = sc_error(r))
		return e;
	*pgid = r;
	return 0;
}

int Sysdeps<GetSid>::operator()(pid_t pid, pid_t *sid) {
	auto r = do_syscall(SYS_getsid, pid);
	if (int e = sc_error(r))
		return e;
	*sid = r;
	return 0;
}

int Sysdeps<SetPgid>::operator()(pid_t pid, pid_t pgid) {
	return sc_status(do_syscall(SYS_setpgid, pid, pgid));
}

int Sysdeps<SetUid>::operator()(uid_t uid) {
	return sc_status(do_syscall(SYS_setuid, uid));
}

int Sysdeps<SetGid>::operator()(gid_t gid) {
	return sc_status(do_syscall(SYS_setgid, gid));
}

int Sysdeps<GetGroups>::operator()(size_t size, gid_t *list, int *ret) {
	auto r = do_syscall(SYS_getgroups, size, list);
	if (int e = sc_error(r))
		return e;
	*ret = r;
	return 0;
}

int Sysdeps<SetSid>::operator()(pid_t *sid) {
	auto r = do_syscall(SYS_setsid);
	if (int e = sc_error(r))
		return e;
	*sid = r;
	return 0;
}

int Sysdeps<Pselect>::operator()(int num_fds, fd_set *read_set, fd_set *write_set, fd_set *except_set,
		const struct timespec *timeout, const sigset_t *sigmask, int *num_events) {
	struct timespec local_timeout;
	if (timeout)
		local_timeout = *timeout;

	// pselect6 takes the mask and its size through a pointer: there are only six argument registers
	struct {
		const sigset_t *sigmask;
		size_t ss_len;
	} data = {sigmask, sizeof(uint64_t)};

	auto r = do_syscall(SYS_pselect6, num_fds, read_set, write_set, except_set,
			timeout ? &local_timeout : nullptr, sigmask ? &data : nullptr);
	if (int e = sc_error(r))
		return e;
	*num_events = r;
	return 0;
}

int Sysdeps<GetRusage>::operator()(int scope, struct rusage *usage) {
	return sc_status(do_syscall(SYS_getrusage, scope, usage));
}

int Sysdeps<GetRlimit>::operator()(int resource, struct rlimit *limit) {
	return sc_status(do_syscall(SYS_prlimit64, 0, resource, nullptr, limit));
}

int Sysdeps<SetRlimit>::operator()(int resource, const struct rlimit *limit) {
	return sc_status(do_syscall(SYS_prlimit64, 0, resource, limit, nullptr));
}

int Sysdeps<GetCwd>::operator()(char *buffer, size_t size) {
	return sc_status(do_syscall(SYS_getcwd, buffer, size));
}

int Sysdeps<Chdir>::operator()(const char *path) {
	return sc_status(do_syscall(SYS_chdir, path));
}

int Sysdeps<Fchdir>::operator()(int fd) {
	return sc_status(do_syscall(SYS_fchdir, fd));
}

int Sysdeps<Mkdir>::operator()(const char *path, mode_t mode) {
	return sc_status(do_syscall(SYS_mkdirat, AT_FDCWD, path, mode));
}

int Sysdeps<Mkdirat>::operator()(int dirfd, const char *path, mode_t mode) {
	return sc_status(do_syscall(SYS_mkdirat, dirfd, path, mode));
}

int Sysdeps<Link>::operator()(const char *old_path, const char *new_path) {
	return sc_status(do_syscall(SYS_link, old_path, new_path));
}

int Sysdeps<Symlink>::operator()(const char *target_path, const char *link_path) {
	return sc_status(do_syscall(SYS_symlink, target_path, link_path));
}

int Sysdeps<Renameat>::operator()(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
	return sc_status(do_syscall(SYS_renameat, olddirfd, old_path, newdirfd, new_path));
}

int Sysdeps<Fcntl>::operator()(int fd, int request, va_list args, int *result) {
	auto arg = va_arg(args, unsigned long);
	auto r = do_syscall(SYS_fcntl, fd, request, arg);
	if (int e = sc_error(r))
		return e;
	*result = r;
	return 0;
}

void Sysdeps<Sync>::operator()() {
	do_syscall(SYS_sync);
}

int Sysdeps<Fsync>::operator()(int fd) {
	return sc_status(do_syscall(SYS_fsync, fd));
}

int Sysdeps<Fdatasync>::operator()(int fd) {
	return sc_status(do_syscall(SYS_fdatasync, fd));
}

int Sysdeps<Chmod>::operator()(const char *pathname, mode_t mode) {
	return sc_status(do_syscall(SYS_fchmodat, AT_FDCWD, pathname, mode));
}

int Sysdeps<Fchmod>::operator()(int fd, mode_t mode) {
	return sc_status(do_syscall(SYS_fchmod, fd, mode));
}

int Sysdeps<Fchmodat>::operator()(int fd, const char *pathname, mode_t mode, int flags) {
	if (flags)
		return EOPNOTSUPP;
	return sc_status(do_syscall(SYS_fchmodat, fd, pathname, mode));
}

int Sysdeps<Utimensat>::operator()(int dirfd, const char *pathname, const struct timespec times[2], int flags) {
	return sc_status(do_syscall(SYS_utimensat, dirfd, pathname, times, flags));
}

int Sysdeps<Tcgetattr>::operator()(int fd, struct termios *attr) {
	return sc_status(do_syscall(SYS_ioctl, fd, TCGETS, attr));
}

int Sysdeps<Tcsetattr>::operator()(int fd, int optional_action, const struct termios *attr) {
	int req;
	switch (optional_action) {
		case TCSANOW: req = TCSETS; break;
		case TCSADRAIN: req = TCSETSW; break;
		case TCSAFLUSH: req = TCSETSF; break;
		default: return EINVAL;
	}
	return sc_status(do_syscall(SYS_ioctl, fd, req, attr));
}

int Sysdeps<Tcflush>::operator()(int fd, int queue) {
	return sc_status(do_syscall(SYS_ioctl, fd, TCFLSH, queue));
}

int Sysdeps<Tcdrain>::operator()(int fd) {
	return sc_status(do_syscall(SYS_ioctl, fd, TCSBRK, 1));
}

int Sysdeps<Tcgetwinsize>::operator()(int fd, struct winsize *winsz) {
	return sc_status(do_syscall(SYS_ioctl, fd, TIOCGWINSZ, winsz));
}

int Sysdeps<Tcsetwinsize>::operator()(int fd, const struct winsize *winsz) {
	return sc_status(do_syscall(SYS_ioctl, fd, TIOCSWINSZ, winsz));
}

int Sysdeps<Pipe>::operator()(int *fds, int flags) {
	return sc_status(do_syscall(SYS_pipe2, fds, flags));
}

int Sysdeps<Socketpair>::operator()(int domain, int type_and_flags, int proto, int *fds) {
	return sc_status(do_syscall(SYS_socketpair, domain, type_and_flags, proto, fds));
}

int Sysdeps<Poll>::operator()(struct pollfd *fds, nfds_t count, int timeout, int *num_events) {
	auto r = do_syscall(SYS_poll, fds, count, timeout);
	if (int e = sc_error(r))
		return e;
	*num_events = r;
	return 0;
}

int Sysdeps<Ppoll>::operator()(struct pollfd *fds, nfds_t count, const struct timespec *ts, const sigset_t *mask,
		int *num_events) {
	auto r = do_syscall(SYS_ppoll, fds, count, ts, mask, sizeof(uint64_t));
	if (int e = sc_error(r))
		return e;
	*num_events = r;
	return 0;
}

int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *arg, int *result) {
	auto r = do_syscall(SYS_ioctl, fd, request, arg);
	if (int e = sc_error(r))
		return e;
	if (result)
		*result = r;
	return 0;
}

int Sysdeps<GetSockopt>::operator()(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict size) {
	return sc_status(do_syscall(SYS_getsockopt, fd, layer, number, buffer, size));
}

int Sysdeps<SetSockopt>::operator()(int fd, int layer, int number, const void *buffer, socklen_t size) {
	return sc_status(do_syscall(SYS_setsockopt, fd, layer, number, buffer, size));
}

int Sysdeps<Shutdown>::operator()(int sockfd, int how) {
	return sc_status(do_syscall(SYS_shutdown, sockfd, how));
}

int Sysdeps<ThreadSigmask>::operator()(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
	return sysdep<Sigprocmask>(how, set, retrieve);
}

int Sysdeps<Sigtimedwait>::operator()(const sigset_t *__restrict set, siginfo_t *__restrict info,
		const struct timespec *__restrict timeout, int *out_signal) {
	auto r = do_syscall(SYS_rt_sigtimedwait, set, info, timeout, sizeof(uint64_t));
	if (int e = sc_error(r))
		return e;
	*out_signal = r;
	return 0;
}

int Sysdeps<Accept>::operator()(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length, int flags) {
	auto r = do_syscall(SYS_accept4, fd, addr_ptr, addr_length, flags);
	if (int e = sc_error(r))
		return e;
	*newfd = r;
	return 0;
}

int Sysdeps<Bind>::operator()(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
	return sc_status(do_syscall(SYS_bind, fd, addr_ptr, addr_length));
}

int Sysdeps<Connect>::operator()(int fd, const struct sockaddr *addr_ptr, socklen_t addr_length) {
	return sc_status(do_syscall(SYS_connect, fd, addr_ptr, addr_length));
}

int Sysdeps<Sockname>::operator()(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
		socklen_t *actual_length) {
	if (int e = sc_error(do_syscall(SYS_getsockname, fd, addr_ptr, &max_addr_length)))
		return e;
	*actual_length = max_addr_length;
	return 0;
}

int Sysdeps<Peername>::operator()(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
		socklen_t *actual_length) {
	if (int e = sc_error(do_syscall(SYS_getpeername, fd, addr_ptr, &max_addr_length)))
		return e;
	*actual_length = max_addr_length;
	return 0;
}

int Sysdeps<GetHostname>::operator()(char *buffer, size_t bufsize) {
	struct utsname uname_buf;
	if (int e = sysdep<Uname>(&uname_buf))
		return e;
	auto node_len = strlen(uname_buf.nodename);
	if (node_len >= bufsize)
		return ENAMETOOLONG;
	memcpy(buffer, uname_buf.nodename, node_len + 1);
	return 0;
}

int Sysdeps<GetEntropy>::operator()(void *buffer, size_t length) {
	auto p = static_cast<char *>(buffer);
	while (length) {
		auto r = do_syscall(SYS_getrandom, p, length, 0);
		if (int e = sc_error(r)) {
			if (e == EINTR)
				continue;
			return e;
		}
		p += r;
		length -= r;
	}
	return 0;
}

int Sysdeps<Umask>::operator()(mode_t mode, mode_t *old) {
	*old = do_syscall(SYS_umask, mode);
	return 0;
}

int Sysdeps<Tgkill>::operator()(int tgid, int tid, int sig) {
	return sc_status(do_syscall(SYS_tgkill, tgid, tid, sig));
}

int Sysdeps<Sigaltstack>::operator()(const stack_t *ss, stack_t *oss) {
	return sc_status(do_syscall(SYS_sigaltstack, ss, oss));
}

int Sysdeps<Sigsuspend>::operator()(const sigset_t *set) {
	return sc_status(do_syscall(SYS_rt_sigsuspend, set, sizeof(uint64_t)));
}

int Sysdeps<Sigpending>::operator()(sigset_t *set) {
	return sc_status(do_syscall(SYS_rt_sigpending, set, sizeof(uint64_t)));
}

int Sysdeps<Madvise>::operator()(void *addr, size_t length, int advice) {
	return sc_status(do_syscall(SYS_madvise, addr, length, advice));
}

int Sysdeps<Msync>::operator()(void *addr, size_t length, int flags) {
	return sc_status(do_syscall(SYS_msync, addr, length, flags));
}

int Sysdeps<GetItimer>::operator()(int which, struct itimerval *curr_value) {
	return sc_status(do_syscall(SYS_getitimer, which, curr_value));
}

int Sysdeps<SetItimer>::operator()(int which, const struct itimerval *new_value, struct itimerval *old_value) {
	return sc_status(do_syscall(SYS_setitimer, which, new_value, old_value));
}

int Sysdeps<Times>::operator()(struct tms *tms, clock_t *out) {
	auto r = do_syscall(SYS_times, tms);
	if (int e = sc_error(r))
		return e;
	*out = r;
	return 0;
}

int Sysdeps<Uname>::operator()(struct utsname *buf) {
	return sc_status(do_syscall(SYS_uname, buf));
}

int Sysdeps<Pause>::operator()() {
	if (int e = sc_error(do_syscall(SYS_pause)))
		return e;
	return EINTR;
}

int Sysdeps<ThreadSetname>::operator()(void *tcb, const char *name) {
	if (strlen(name) > 15)
		return ERANGE;
	if (tcb != get_current_tcb())
		return ENOSYS;
	return sc_status(do_syscall(SYS_prctl, PR_SET_NAME, name, 0, 0, 0));
}

int Sysdeps<Sysconf>::operator()(int num, long *ret) {
	switch (num) {
		case _SC_OPEN_MAX: {
			struct rlimit rl;
			if (int e = sysdep<GetRlimit>(RLIMIT_NOFILE, &rl))
				return e;
			*ret = rl.rlim_cur == RLIM_INFINITY ? -1 : static_cast<long>(rl.rlim_cur);
			return 0;
		}
		case _SC_NPROCESSORS_CONF:
		case _SC_NPROCESSORS_ONLN: {
			cpu_set_t set;
			memset(&set, 0, sizeof(set));
			if (int e = sysdep<GetAffinity>(0, sizeof(set), &set))
				return e;
			long count = 0;
			auto bytes = reinterpret_cast<const unsigned char *>(&set);
			for (size_t i = 0; i < sizeof(set); i++)
				count += __builtin_popcount(bytes[i]);
			*ret = count;
			return 0;
		}
		case _SC_PHYS_PAGES:
		case _SC_AVPHYS_PAGES: {
			// Linux struct sysinfo
			struct {
				long uptime;
				unsigned long loads[3];
				unsigned long totalram;
				unsigned long freeram;
				unsigned long sharedram;
				unsigned long bufferram;
				unsigned long totalswap;
				unsigned long freeswap;
				unsigned short procs;
				unsigned short pad;
				unsigned long totalhigh;
				unsigned long freehigh;
				unsigned int mem_unit;
				char reserved[256];
			} info = {};
			if (int e = sc_error(do_syscall(SYS_sysinfo, &info)))
				return e;
			unsigned long unit = info.mem_unit ? info.mem_unit : 1;
			unsigned long bytes = (num == _SC_PHYS_PAGES ? info.totalram : info.freeram) * unit;
			*ret = static_cast<long>(bytes / 4096);
			return 0;
		}
		default:
			return EINVAL;
	}
}

int Sysdeps<GetAffinity>::operator()(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
	auto r = do_syscall(SYS_sched_getaffinity, pid, cpusetsize, mask);
	if (int e = sc_error(r))
		return e;
	return 0;
}

int Sysdeps<GetThreadaffinity>::operator()(pid_t tid, size_t cpusetsize, cpu_set_t *mask) {
	return sysdep<GetAffinity>(tid, cpusetsize, mask);
}

int Sysdeps<InetConfigured>::operator()(bool *ipv4, bool *ipv6) {
	*ipv4 = true;
	*ipv6 = false;
	return 0;
}

#endif // __MLIBC_POSIX_OPTION

#endif // !MLIBC_BUILDING_RTLD

} // namespace mlibc
