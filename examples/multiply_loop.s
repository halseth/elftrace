	.file	"multiply_loop.c"
	.option nopic
	.attribute arch, "rv32i2p1_m2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
	.text
	.align	2
	.globl	runcontract
	.type	runcontract, @function
runcontract:
	addi	sp,sp,-48
	sw	s0,44(sp)
	addi	s0,sp,48
	sw	a0,-36(s0)
	sw	zero,-20(s0)
	j	.L2
.L3:
	lw	a5,-36(s0)
	slli	a5,a5,1
	sw	a5,-36(s0)
	lw	a5,-20(s0)
	addi	a5,a5,1
	sw	a5,-20(s0)
.L2:
	lw	a4,-20(s0)
	li	a5,7
	ble	a4,a5,.L3
	lw	a5,-36(s0)
	mv	a0,a5
	lw	s0,44(sp)
	addi	sp,sp,48
	jr	ra
	.size	runcontract, .-runcontract
	.ident	"GCC: () 13.2.0"
