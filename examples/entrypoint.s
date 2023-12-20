.section .text._start;
.globl _start;
_start:
	.option push;
    	.option norelax;
    	la gp, __global_pointer$;
    	.option pop;
	la sp, 0x00200400

    	jal ra, __start;
	j _sys_halt

__start:
	addi	sp,sp,-32	# allocate 32 bytes on the stack
	sw	ra,28(sp)	# store ra on the stack
	sw	s0,24(sp)	# store s0 on the stack
	addi	s0,sp,32	# store old stack pointer into s0
	call	runcontract	# call runcontract with x=a0
	sw	a0,-24(s0)	# store a0=y (return value from runcontract) on the stack
	lw	ra,28(sp)	# load original ra from stack
	lw	s0,24(sp)	# load original s0 from stack
	addi	sp,sp,32	# deallocate 32 bytes from stack
	jr	ra		# return

_sys_halt:
	add	a1,sp,24
	li      t0,0
	ecall
