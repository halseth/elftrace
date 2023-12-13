# Setup toolchain
TODO

# Compile

We'll start by creating a simple C-function that we'll eventually compile down to Bitcoin script:

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

Name it `multiply_loop.c` (you'll find all these files in the examples folder)
and compile it:

```bash
$ riscv32-unknown-elf-gcc -S multiply_loop.c
```

This will output an assembly file. Now some boilerplate to call this function:

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
	sw	    ra,28(sp)	# store ra on the stack
	sw	    s0,24(sp)	# store s0 on the stack
	addi	s0,sp,32	# store old stack pointer into s0
	li	    a0,2		# load 2 into a0
	call	runcontract	# call runcontract with a0=x=2
	sw	    a0,-24(s0)	# store a0=y (return value from runcontract) on the stack
	li	    a0,0		# load 0 into a0
	lw	    ra,28(sp)	# load original ra from stack
	lw	    s0,24(sp)	# load original s0 from stack
	addi	sp,sp,32	# deallocate 32 bytes from stack
	jr	    ra		    # return

_sys_halt:
	add	    a1,sp,24
	sll     a0,a0,0x8
	li      t0,0
	ecall
```

Note that this determines the value passed to our function, by loading 2 into
the a0 register.

Name this file `entrypoint.s` and compile:

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
   10078:	8a818193          	add	gp,gp,-1880 # 1191c <__global_pointer$>
   1007c:	00200137          	lui	sp,0x200
   10080:	40010113          	add	sp,sp,1024 # 200400 <__global_pointer$+0x1eeae4>
   10084:	008000ef          	jal	1008c <__start>
   10088:	0340006f          	j	100bc <_sys_halt>

0001008c <__start>:
   1008c:	fe010113          	add	sp,sp,-32
   10090:	00112e23          	sw	ra,28(sp)
   10094:	00812c23          	sw	s0,24(sp)
   10098:	02010413          	add	s0,sp,32
   1009c:	00200513          	li	a0,2
   100a0:	02c000ef          	jal	100cc <runcontract>
   100a4:	fea42423          	sw	a0,-24(s0)
   100a8:	00000513          	li	a0,0
   100ac:	01c12083          	lw	ra,28(sp)
   100b0:	01812403          	lw	s0,24(sp)
   100b4:	02010113          	add	sp,sp,32
   100b8:	00008067          	ret

000100bc <_sys_halt>:
   100bc:	01810593          	add	a1,sp,24
   100c0:	00851513          	sll	a0,a0,0x8
   100c4:	00000293          	li	t0,0
   100c8:	00000073          	ecall

000100cc <runcontract>:
   100cc:	fd010113          	add	sp,sp,-48
   100d0:	02812623          	sw	s0,44(sp)
   100d4:	03010413          	add	s0,sp,48
   100d8:	fca42e23          	sw	a0,-36(s0)
   100dc:	fe042623          	sw	zero,-20(s0)
   100e0:	01c0006f          	j	100fc <runcontract+0x30>
   100e4:	fdc42783          	lw	a5,-36(s0)
   100e8:	00179793          	sll	a5,a5,0x1
   100ec:	fcf42e23          	sw	a5,-36(s0)
   100f0:	fec42783          	lw	a5,-20(s0)
   100f4:	00178793          	add	a5,a5,1
   100f8:	fef42623          	sw	a5,-20(s0)
   100fc:	fec42703          	lw	a4,-20(s0)
   10100:	00700793          	li	a5,7
   10104:	fee7d0e3          	bge	a5,a4,100e4 <runcontract+0x18>
   10108:	fdc42783          	lw	a5,-36(s0)
   1010c:	00078513          	mv	a0,a5
   10110:	02c12403          	lw	s0,44(sp)
   10114:	03010113          	add	sp,sp,48
   10118:	00008067          	ret
```

### Trace
Now we will take the executable we just created and trace it.

```bash
$ cargo run -- ./examples/multiply.elf
```

This will run the program on the RISC Zero ZKVM and produce an execution trace.
It will the use this trace to build a merkleized state for each instruction,
and output Bitcoin scripts that can verify the state transitions done for each
step of the computation.

Let's take a look at the files found in the `trace` folder:
```bash
$ ls trace/
ins_0001_commitment.txt
ins_0001_script.txt
ins_0001_tags.json
ins_0001_witness.txt
ins_0002_commitment.txt
ins_0002_script.txt
ins_0002_tags.json
ins_0002_witness.txt
ins_0003_commitment.txt
ins_0003_script.txt
ins_0003_tags.json
ins_0003_witness.txt
...
ins_006a_commitment.txt
ins_006a_script.txt
ins_006a_tags.json
ins_006a_witness.txt
ins_006b_commitment.txt
ins_006b_script.txt
ins_006b_tags.json
ins_006b_witness.txt
```

Each step of the computation resulted in a 
    - commitment: this will be the hash of the start merkle root + the end
      merkle root. This commits to the full VM memory before and after the
      executed step.
    - script: this is the Bitcoin tapscript that uses OP_CHECKCONTRACTVERIFY to
      verify the executed VM step against the commitment.
    - tags: this is a helper file for Tapsim, useful to annotate elements when
      debugging the script.
    - witness: this is the witness that must be provided in order to execute
      the script. This contains mostly of merkle proofs into the merkleized
      state.

# Verify
State transition verification is done by having the commitment be added as a
tweak to the taproot key, then spending from this output using the correct
witness.

For example using tapsim:
```bash
tapsim execute --script "trace/ins_0034_script.txt"  --witness "trace/ins_0034_witness.txt" --tagfile "trace/ins_0034_tags.json" --colwidth=80 --rows=45 --inputkey "`tweak --merkle "\`cat trace/ins_0034_commitment.txt\`" --key "nums" | sed -n 4p | awk -F" " '{print $2}'`"
```
