#include <abi-bits/errno.h>
#include <bits/ensure.h>
#include <bits/syscall.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/tcb.hpp>
#include <string.h>
#include <sys/mman.h>

// Keep in sync with enum syscall_numbers in src/kernel/drivers/syscalls/syscalls.h.
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_CLOSE 3
#define SYS_LSEEK 6
#define SYS_MMAP 9
#define SYS_MUNMAP 11
#define SYS_CLOCK_GETTIME 288
#define SYS_EXIT 60
#define SYS_ARCH_PRCTL 158

#define ARCH_SET_FS 0x1002

#define STUB()                                 \
	({                                         \
		__ensure(!"STUB function was called"); \
		__builtin_unreachable();               \
	})

namespace mlibc {

namespace {

// Syscalls return -errno on failure.
int sc_error(long ret) {
	if (ret < 0 && ret > -4096)
		return -ret;
	return 0;
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

int Sysdeps<Isatty>::operator()(int) {
	return 0;
}

int Sysdeps<Write>::operator()(int fd, void const *buf, size_t size, ssize_t *ret) {
	auto r = __do_syscall3(SYS_WRITE, fd, (__sc_word_t)buf, size);
	if (int e = sc_error(r))
		return e;
	*ret = r;
	return 0;
}

int Sysdeps<Read>::operator()(int fd, void *buf, size_t size, ssize_t *ret) {
	auto r = __do_syscall3(SYS_READ, fd, (__sc_word_t)buf, size);
	if (int e = sc_error(r))
		return e;
	*ret = r;
	return 0;
}

int Sysdeps<Open>::operator()(const char *path, int flags, mode_t mode, int *fd) {
	auto r = __do_syscall3(SYS_OPEN, (__sc_word_t)path, flags, mode);
	if (int e = sc_error(r))
		return e;
	*fd = r;
	return 0;
}

int Sysdeps<Close>::operator()(int fd) {
	return sc_error(__do_syscall1(SYS_CLOSE, fd));
}

int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
	auto r = __do_syscall3(SYS_LSEEK, fd, offset, whence);
	if (int e = sc_error(r))
		return e;
	*new_offset = r;
	return 0;
}

int Sysdeps<VmMap>::operator()(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	auto r = __do_syscall6(SYS_MMAP, (__sc_word_t)hint, size, prot, flags, fd, offset);
	if (int e = sc_error(r))
		return e;
	*window = (void *)r;
	return 0;
}

int Sysdeps<VmUnmap>::operator()(void *pointer, size_t size) {
	return sc_error(__do_syscall2(SYS_MUNMAP, (__sc_word_t)pointer, size));
}

int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
	return sysdep<VmMap>(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0, pointer);
}

int Sysdeps<AnonFree>::operator()(void *pointer, size_t size) {
	return sysdep<VmUnmap>(pointer, size);
}

int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
	struct timespec ts;
	if (int e = sc_error(__do_syscall2(SYS_CLOCK_GETTIME, clock, (__sc_word_t)&ts)))
		return e;
	*secs = ts.tv_sec;
	*nanos = ts.tv_nsec;
	return 0;
}

int Sysdeps<TcbSet>::operator()(void *pointer) {
	return sc_error(__do_syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, (__sc_word_t)pointer));
}

void Sysdeps<Exit>::operator()(int status) {
	__do_syscall1(SYS_EXIT, status);
	__builtin_unreachable();
}

int Sysdeps<FutexWake>::operator()(int *, bool) {
	STUB();
}

int Sysdeps<FutexWait>::operator()(int *, int, timespec const *) {
	STUB();
}

} // namespace mlibc
