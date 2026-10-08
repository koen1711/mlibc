.section .text
.global _start
_start:
	xor %rbp, %rbp
	mov %rsp, %rdi
	mov $main, %rsi
	call __mlibc_entry
	ud2

.section .note.GNU-stack,"",%progbits
