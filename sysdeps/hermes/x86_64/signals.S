#include "mlibc-asm/helpers.h"

.section .text

PROC_START(__mlibc_signal_restore)
	mov $15, %rax
	syscall
	ud2
PROC_END(__mlibc_signal_restore)

GNU_STACK_NOTE()
