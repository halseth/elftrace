#![allow(unused)]
#![allow(unused_imports)]
#![allow(unused_variables)]
use risc0_zkvm_platform::memory::SYSTEM;
use risc0_zkvm_platform::syscall::reg_abi::REG_MAX;
use risc0_zkvm_platform::WORD_SIZE;
use rrs_lib::instruction_formats::{BType, IType, ITypeShamt, JType, RType, SType, UType};
use rrs_lib::{
    instruction_formats, instruction_string_outputter::InstructionStringOutputter,
    process_instruction, InstructionProcessor,
};

pub struct BitcoinInstructionProcessor {
    /// PC of the instruction being output. Used to generate disassembly of instructions with PC
    /// relative fields (such as BEQ and JAL).
    pub insn_pc: u32,

    pub start_addr: u32,
    pub mem_len: u32,
}

impl BitcoinInstructionProcessor {
    fn addr_to_merkle(&self, addr: u32) -> Vec<bool> {
        let index = (addr - self.start_addr) / WORD_SIZE as u32;

        // TODO: why minus 1?
        let bits = 32 - self.mem_len.leading_zeros() - 1;
        println!(
            "index is {:b} number of bits {} (mem_len: {:b})",
            index, bits, self.mem_len
        );
        println!(
            "BitcoinInstrictionProcessor: addr {}-> index {:b}",
            addr, index
        );

        // Binary of index will be path down to leaf.
        let mut v: Vec<bool> = vec![];
        for b in (0..bits).map(|n| (index >> n) & 1) {
            v.push(b != 0);
        }

        v
    }

    pub fn reg_addr(reg: usize) -> u32 {
        (SYSTEM.start() + reg * WORD_SIZE) as u32
    }

    fn merkle_inclusion(path: &Vec<bool>) -> String {
        let mut scr = format!(
            "
        # On stack is element checked for inclusion, and path.
        # Hash element
        OP_SHA256
        "
        );

        // Use vector to traverse the tree.
        for right in path {
            if *right {
                scr += "OP_SWAP\n"
            }

            scr += "OP_CAT OP_SHA256\n"
        }

        scr
    }
}

impl InstructionProcessor for BitcoinInstructionProcessor {
    type InstructionResult = String;

    fn process_add(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sub(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sll(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_slt(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sltu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_xor(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_srl(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sra(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_or(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_and(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_addi(&mut self, dec_insn: IType) -> Self::InstructionResult {
        println!("pc is {:b}", self.insn_pc);
        let pc_addr = Self::reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);
        for b in pc_path {
            println!("bit: {}", b);
        }

        let rd_addr = Self::reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        let rs1_addr = Self::reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        format!(
            "
        # top stack elements are start and end  merkle roots, check that they matches commitment.
        OP_2DUP OP_CAT OP_SHA256
        OP_0 # index
        OP_0 # nums key
        81 # current taptree
        OP_1 # flags, check input
        OP_CHECKCONTRACTVERIFY

        # push roots to alt stack
        OP_TOALTSTACK OP_TOALTSTACK

        # put pc on stack, check that it committed to in he root
        {}

        # on stack is merkle proof for pc register. We already know the location in RAM, so only
        # nodes are needed.
        {}

        # Check that it matches start root.
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_DUP
        OP_TOALTSTACK
        OP_SWAP
        OP_TOALTSTACK
        OP_EQUALVERIFY

        # increment pc+4 and verify it againt root
        {}
        {}
        # Check that it matches end root.
        OP_FROMALTSTACK
        OP_DUP
        OP_TOALTSTACK
        OP_EQUALVERIFY

        # load register(s) from root

        # rs value on stack
        OP_DUP
        OP_TOALTSTACK

        # verify rs value against start root.
        {}

        OP_FROMALTSTACK # rs val
        OP_FROMALTSTACK # end root
        OP_FROMALTSTACK # startroot

        OP_DUP
        OP_TOALTSTACK
        OP_SWAP OP_TOALTSTACK
        OP_SWAP OP_TOALTSTACK

        OP_EQUALVERIFY


        # perform addition
        {} #imm
        OP_FROMALTSTACK
        OP_ADD

        # verify result against end root
        {}

        OP_FROMALTSTACK
        OP_DUP
        OP_TOALTSTACK
        OP_EQUALVERIFY

        OP_1
",
            //
            //        # load rd from end root
            //        OP_DUP
            //        {}
            //
            //        # check addiion it matches rd
            //        OP_FROMALTSTACK
            //        OP_EQUALVERIFY
            //
            //        # increment pc and verify it againt root
            //        OP_4
            //        OP_ADD
            //        OP_DUP
            //        {}
            //
            //        # If this all checks out, state transition was valid.
            //        OP_1
            //        ",
            hex::encode(self.insn_pc.to_le_bytes()),
            pc_incl,
            hex::encode((self.insn_pc + 4).to_le_bytes()),
            pc_incl,
            rs1_incl,
            dec_insn.imm,
            rd_incl,
            //dec_insn.imm, rd_incl, pc_incl,
        )
    }

    fn process_slli(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        todo!()
    }

    fn process_slti(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sltui(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_xori(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_srli(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        todo!()
    }

    fn process_srai(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        todo!()
    }

    fn process_ori(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_andi(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_lui(&mut self, dec_insn: UType) -> Self::InstructionResult {
        todo!()
    }

    fn process_auipc(&mut self, dec_insn: UType) -> Self::InstructionResult {
        todo!()
    }

    fn process_beq(&mut self, dec_insn: BType) -> Self::InstructionResult {
        todo!()
    }

    fn process_bne(&mut self, dec_insn: BType) -> Self::InstructionResult {
        todo!()
    }

    fn process_blt(&mut self, dec_insn: BType) -> Self::InstructionResult {
        todo!()
    }

    fn process_bltu(&mut self, dec_insn: BType) -> Self::InstructionResult {
        todo!()
    }

    fn process_bge(&mut self, dec_insn: BType) -> Self::InstructionResult {
        todo!()
    }

    fn process_bgeu(&mut self, dec_insn: BType) -> Self::InstructionResult {
        todo!()
    }

    fn process_lb(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_lbu(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_lh(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_lhu(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_lw(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sb(&mut self, dec_insn: SType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sh(&mut self, dec_insn: SType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sw(&mut self, dec_insn: SType) -> Self::InstructionResult {
        todo!()
    }

    fn process_jal(&mut self, dec_insn: JType) -> Self::InstructionResult {
        todo!()
    }

    fn process_jalr(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }

    fn process_mul(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_mulh(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_mulhu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_mulhsu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_div(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_divu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_rem(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_remu(&mut self, dec_insn: RType) -> Self::InstructionResult {
        todo!()
    }

    fn process_fence(&mut self, dec_insn: IType) -> Self::InstructionResult {
        todo!()
    }
}
