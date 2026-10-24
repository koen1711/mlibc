#include <bits/syscall.h>
#include <errno.h>

extern "C" long __do_syscall_ret(unsigned long ret) {
	if (ret > -4096UL) {
		errno = -ret;
		return -1;
	}
	return ret;
}

using sc_word_t = __sc_word_t;

sc_word_t __do_syscall0(long sc) {
	sc_word_t ret;
	asm volatile ("syscall" : "=a"(ret) : "a"(sc) : "rcx", "r11", "memory");
	return ret;
}

sc_word_t __do_syscall1(long sc,
		sc_word_t arg1) {
	sc_word_t ret;
	asm volatile ("syscall" : "=a"(ret) :
			"a"(sc),
			"D"(arg1)
			: "rcx", "r11", "memory");
	return ret;
}

sc_word_t __do_syscall2(long sc,
		sc_word_t arg1, sc_word_t arg2) {
	sc_word_t ret;
	asm volatile ("syscall" : "=a"(ret) :
			"a"(sc),
			"D"(arg1),
			"S"(arg2)
			: "rcx", "r11", "memory");
	return ret;
}

sc_word_t __do_syscall3(long sc,
		sc_word_t arg1, sc_word_t arg2, sc_word_t arg3) {
	sc_word_t ret;
	asm volatile ("syscall" : "=a"(ret) :
			"a"(sc),
			"D"(arg1),
			"S"(arg2),
			"d"(arg3)
			: "rcx", "r11", "memory");
	return ret;
}

sc_word_t __do_syscall4(long sc,
		sc_word_t arg1, sc_word_t arg2, sc_word_t arg3,
		sc_word_t arg4) {
	register sc_word_t arg4_reg asm("r10") = arg4;
	sc_word_t ret;
	asm volatile ("syscall" : "=a"(ret) :
			"a"(sc),
			"D"(arg1),
			"S"(arg2),
			"d"(arg3),
			"r"(arg4_reg)
			: "rcx", "r11", "memory");
	return ret;
}

sc_word_t __do_syscall5(long sc,
		sc_word_t arg1, sc_word_t arg2, sc_word_t arg3,
		sc_word_t arg4, sc_word_t arg5) {
	register sc_word_t arg4_reg asm("r10") = arg4;
	register sc_word_t arg5_reg asm("r8") = arg5;
	sc_word_t ret;
	asm volatile ("syscall" : "=a"(ret) :
			"a"(sc),
			"D"(arg1),
			"S"(arg2),
			"d"(arg3),
			"r"(arg4_reg),
			"r"(arg5_reg)
			: "rcx", "r11", "memory");
	return ret;
}

sc_word_t __do_syscall6(long sc,
		sc_word_t arg1, sc_word_t arg2, sc_word_t arg3,
		sc_word_t arg4, sc_word_t arg5, sc_word_t arg6) {
	register sc_word_t arg4_reg asm("r10") = arg4;
	register sc_word_t arg5_reg asm("r8") = arg5;
	register sc_word_t arg6_reg asm("r9") = arg6;
	sc_word_t ret;
	asm volatile ("syscall" : "=a"(ret) :
			"a"(sc),
			"D"(arg1),
			"S"(arg2),
			"d"(arg3),
			"r"(arg4_reg),
			"r"(arg5_reg),
			"r"(arg6_reg)
			: "rcx", "r11", "memory");
	return ret;
}
