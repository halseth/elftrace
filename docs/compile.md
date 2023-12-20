# Setup toolchain
For compilation using GCC, set up the RISCV32 toolchain from
https://github.com/halseth/docker-riscv.

# Compile
We'll start by creating a simple C-function that we'll eventually compile down
to Bitcoin script:

```C
int runcontract(int x) {
        int i = 0;
        while (i < 8) {
                x = x + x;
                i = i + 1;
        }

        return x;
}
```

In this rather simple toy example function, the input is doubled 8 times and
returnd. In other words `f(x) = x * 256`.

Name it `multiply_loop.c` (you'll find all these files in the examples folder)
and compile it using the RISCV compiler:

```bash
$ riscv32-unknown-elf-gcc -S multiply_loop.c
```

This will output an assembly file:
```asm
$ cat multiply_loop.s
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
```

In itself this is not enough for a complete program, so we add some boilerplate
code to call this function:

```asm
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
```

Note that this assumes the value passed to the our function is loaded into
register `a0`. Similarly the result will be found in `a0` after execution
halts.

Name this file `entrypoint.s` and compile them together:

```bash
riscv32-unknown-elf-gcc -nostdlib entrypoint.s multiply_loop.s -o multiply.elf
```

Note that we don't want the clutter of the standard library to be included.

Let's take a look at the final executable:

```bash
$ riscv32-unknown-elf-objdump -d multiply.elf

multiply.elf:     file format elf32-littleriscv


Disassembly of section .text:

00010074 <_start>:
   10074:	00002197          	auipc	gp,0x2
   10078:	89c18193          	add	gp,gp,-1892 # 11910 <__global_pointer$>
   1007c:	00200137          	lui	sp,0x200
   10080:	40010113          	add	sp,sp,1024 # 200400 <__global_pointer$+0x1eeaf0>
   10084:	008000ef          	jal	1008c <__start>
   10088:	02c0006f          	j	100b4 <_sys_halt>

0001008c <__start>:
   1008c:	fe010113          	add	sp,sp,-32
   10090:	00112e23          	sw	ra,28(sp)
   10094:	00812c23          	sw	s0,24(sp)
   10098:	02010413          	add	s0,sp,32
   1009c:	024000ef          	jal	100c0 <runcontract>
   100a0:	fea42423          	sw	a0,-24(s0)
   100a4:	01c12083          	lw	ra,28(sp)
   100a8:	01812403          	lw	s0,24(sp)
   100ac:	02010113          	add	sp,sp,32
   100b0:	00008067          	ret

000100b4 <_sys_halt>:
   100b4:	01810593          	add	a1,sp,24
   100b8:	00000293          	li	t0,0
   100bc:	00000073          	ecall

000100c0 <runcontract>:
   100c0:	fd010113          	add	sp,sp,-48
   100c4:	02812623          	sw	s0,44(sp)
   100c8:	03010413          	add	s0,sp,48
   100cc:	fca42e23          	sw	a0,-36(s0)
   100d0:	fe042623          	sw	zero,-20(s0)
   100d4:	01c0006f          	j	100f0 <runcontract+0x30>
   100d8:	fdc42783          	lw	a5,-36(s0)
   100dc:	00179793          	sll	a5,a5,0x1
   100e0:	fcf42e23          	sw	a5,-36(s0)
   100e4:	fec42783          	lw	a5,-20(s0)
   100e8:	00178793          	add	a5,a5,1
   100ec:	fef42623          	sw	a5,-20(s0)
   100f0:	fec42703          	lw	a4,-20(s0)
   100f4:	00700793          	li	a5,7
   100f8:	fee7d0e3          	bge	a5,a4,100d8 <runcontract+0x18>
   100fc:	fdc42783          	lw	a5,-36(s0)
   10100:	00078513          	mv	a0,a5
   10104:	02c12403          	lw	s0,44(sp)
   10108:	03010113          	add	sp,sp,48
   1010c:	00008067          	ret
```

## Trace
Now we will take the executable we just created and trace it.

```bash
$ cargo run -- ./examples/multiply.elf 2
```

This will run the program on the RISC Zero ZKVM with input x=2, and produce an
execution trace. It will the use this trace to build a merkleized state for
each instruction, and output Bitcoin scripts that can verify the state
transitions done for each step of the computation.

Let's take a look at the files found in the `trace` folder:
```bash
$ ls trace/
ins_0001_pc_10074_commitment.txt
ins_0001_pc_10074_tags.json
ins_0001_pc_10074_witness.txt
ins_0002_pc_10078_commitment.txt
ins_0002_pc_10078_tags.json
ins_0002_pc_10078_witness.txt
...
pc_10074_script.txt
pc_10078_script.txt
pc_1007c_script.txt
pc_10080_script.txt
pc_10084_script.txt
...
pc_10108_script.txt
pc_1010c_script.txt
```

The `pc_*_script.txt` files are Bitcoin tapscripts that uses
OP_CHECKCONTRACTVERIFY to verify an executed VM step against a start and end
state commitment.

Each step of the computation resulted in a 
- commitment: this will be the hash of the start merkle root + the end merkle
  root. This commits to the full VM memory before and after the executed step.
- tags: this is a helper file for Tapsim, useful to annotate elements when
  debugging the script.
- witness: this is the witness that must be provided in order to execute the
  script. This contains mostly of merkle proofs into the merkleized state.

# Verify
State transition verification is done by having the commitment be added as a
tweak to the taproot key, then spending from this output using the correct
witness.

For example using tapsim (you must have [Tapsim](https://github.com/halseth/tapsim) as well as the tool `tweak` installed):
```bash
tapsim execute --script "trace/pc_1008c_script.txt" --witness "trace/ins_0006_pc_1008c_witness.txt" --tagfile "trace/ins_0006_pc_1008c_tags.json" --colwidth=80 --rows=45 --inputkey "`tweak --merkle "\`cat trace/ins_0006_pc_1008c_commitment.txt\`" --key "nums" | sed -n 4p | awk -F" " '{print $2}'`"
```
