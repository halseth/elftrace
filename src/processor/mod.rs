#![allow(unused)]
#![allow(unused_imports)]
#![allow(unused_variables)]
use bitcoin::script::write_scriptint;
use risc0_zkvm_platform::memory::{GUEST_MAX_MEM, GUEST_MIN_MEM, SYSTEM};
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
    pub pre_tree: fast_merkle::Tree,
    pub post_tree: fast_merkle::Tree,
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

    fn addr_to_index(addr: usize) -> usize {
        (addr - GUEST_MIN_MEM) / WORD_SIZE
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

    fn to_script_num(b: [u8; 4]) -> Vec<u8> {
        let w = u32::from_le_bytes(b);

        let mut script_num: [u8; 8] = [0; 8];
        let n = write_scriptint(&mut script_num, w as i64);

        script_num[..n].to_vec()
    }
}

pub struct Script {
    pub script: String,
    pub witness: Vec<String>,
}

impl InstructionProcessor for BitcoinInstructionProcessor {
    type InstructionResult = Script;

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

        let pc_start = Self::to_script_num((self.insn_pc).to_le_bytes());
        println!("converting pc {} for script->{}", hex::encode((self.insn_pc).to_le_bytes()), hex::encode(pc_start.clone()));
        let pc_end = Self::to_script_num((self.insn_pc + 4).to_le_bytes());
        let imm = Self::to_script_num(dec_insn.imm.to_le_bytes());

        let rd_addr = Self::reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        let rs1_addr = Self::reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        let script = format!(
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
            hex::encode(pc_start.clone()),
            pc_incl,
            hex::encode(pc_end.clone()),
            pc_incl,
            rs1_incl,
            hex::encode(imm),
            rd_incl,
            //dec_insn.imm, rd_incl, pc_incl,
        );

        let start_root = self.pre_tree.root();
        let end_root = self.post_tree.root();

        let pc_index = Self::addr_to_index(pc_addr as usize);
        let start_pc_proof = self.pre_tree.proof(pc_index, pc_start.clone()).unwrap();

        println!("proof that PC is {}:", hex::encode(pc_start));
        for p in start_pc_proof.clone() {
            println!("{}:", hex::encode(p));
        }

        let end_pc_proof = self.post_tree.proof(pc_index, pc_end).unwrap();

        let rs1_index = Self::addr_to_index(rs1_addr as usize);
        let rs1_val = self.pre_tree.get_leaf(rs1_index);
        let rs1_proof = self.pre_tree.proof(rs1_index, rs1_val.clone()).unwrap();

        let rd_index = Self::addr_to_index(rd_addr as usize);
        let rd_val = self.post_tree.get_leaf(rd_index);
        let rd_proof = self.post_tree.proof(rd_index, rd_val).unwrap();

        // We'll reverse it later.
        let mut witness = vec![hex::encode(start_root), hex::encode(end_root)];

        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        for p in end_pc_proof {
            witness.push(hex::encode(p))
        }

        witness.push(hex::encode(rs1_val));
        for p in rs1_proof {
            witness.push(hex::encode(p))
        }

        for p in rd_proof {
            witness.push(hex::encode(p))
        }

        Script {
            script: script,
            witness: witness.into_iter().rev().collect(),
        }
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
