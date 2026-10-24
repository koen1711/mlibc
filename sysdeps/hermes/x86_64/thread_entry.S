#include "mlibc-asm/helpers.h"

.section .text

PROC_START(__mlibc_spawn_thread)
	xor %eax, %eax
	/* clone(flags, stack, parent_tid, child_tid, tls): only rcx needs to move to r10 */
	mov %rcx, %r10
	mov $56, %rax
	syscall
	test %eax, %eax
	jnz 1f
	xor %ebp, %ebp
	pop %rdi
	pop %rsi
	call __mlibc_enter_thread
	hlt
1:
	ret
PROC_END(__mlibc_spawn_thread)

GNU_STACK_NOTE()
