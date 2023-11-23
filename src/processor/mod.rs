#![allow(unused)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use bitcoin::script::{read_scriptint, write_scriptint};
use risc0_zkvm_platform::memory::{GUEST_MAX_MEM, GUEST_MIN_MEM, SYSTEM};
use risc0_zkvm_platform::syscall::reg_abi::REG_MAX;
use risc0_zkvm_platform::WORD_SIZE;
use rrs_lib::instruction_formats::{BType, IType, ITypeShamt, JType, RType, SType, UType};
use rrs_lib::{
    instruction_formats, instruction_string_outputter::InstructionStringOutputter,
    process_instruction, InstructionProcessor,
};
use std::fmt::format;

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
    fn num_bits(&self) -> u32 {
        32 - self.mem_len.leading_zeros() - 1
    }

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

    fn register_inclusion_script(&self, reg: usize, root_pos: u32) -> String {
        let addr = Self::reg_addr(reg);
        let path = self.addr_to_merkle(addr);
        let incl = Self::merkle_inclusion(&path);

        let mut script = format!(
            "
        # on stack is merkle proof for pc register. We already know the location in RAM, so only
        # nodes are needed.
        {}
        ",
            incl,
        );

        for _ in (0..root_pos) {
            script = format!(
                "{}
        OP_FROMALTSTACK",
                script
            );
        }

        script = format!(
            "{}
OP_DUP
        ",
            script
        );
        for _ in (0..root_pos) {
            script = format!(
                "{}
        OP_SWAP OP_TOALTSTACK",
                script
            );
        }

        script = format!(
            "{}
        # Check that it matches root.
        OP_EQUALVERIFY
        ",
            script
        );


        script
    }

    fn to_script_num(w: u32) -> Vec<u8> {
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

        let pc_start = Self::to_script_num(self.insn_pc);
        println!(
            "converting pc {} for script->{}",
            hex::encode((self.insn_pc).to_le_bytes()),
            hex::encode(pc_start.clone())
        );
        let pc_end = Self::to_script_num(self.insn_pc + 4);
        let imm = Self::to_script_num(dec_insn.imm as u32);

        let rd_addr = Self::reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        let rs1_addr = Self::reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        // TODO: cannot just put end root in witness, must build it from start root.
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
            hex::encode(pc_start.clone()),
            pc_incl,
            hex::encode(pc_end.clone()),
            pc_incl,
            rs1_incl,
            hex::encode(imm),
            rd_incl,
        );

        // TODO: must verify no other memory location has been changed

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
        println!("dec_insn={:?}", dec_insn);
        println!("pc is {:b}", self.insn_pc);
        let pc_addr = Self::reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);
        for b in pc_path {
            println!("bit: {}", b);
        }

        let pc_start = Self::to_script_num(self.insn_pc);
        println!(
            "converting pc {} for script->{}",
            hex::encode((self.insn_pc).to_le_bytes()),
            hex::encode(pc_start.clone())
        );
        let pc_end = Self::to_script_num(self.insn_pc + 4);
        let imm = Self::to_script_num(dec_insn.imm as u32);

        let rs1_addr = Self::reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        let rs2_addr = Self::reg_addr(dec_insn.rs2);
        let rs2_path = self.addr_to_merkle(rs2_addr);
        let rs2_incl = Self::merkle_inclusion(&rs2_path);

        let rs2_index = Self::addr_to_index(rs2_addr as usize);
        let rs2_val = self.pre_tree.get_leaf(rs2_index);
        println!(
            "rs2={}, rs2_addr={} rs2_val={}",
            dec_insn.rs2,
            rs2_addr,
            hex::encode(rs2_val.clone())
        );

        // get value in rs1 and convert from scriptint.
        let rs1_index = Self::addr_to_index(rs1_addr as usize);
        println!("rs1addr={}, index={}", rs1_addr, rs1_index);
        let rs1_val = self.pre_tree.get_leaf(rs1_index);

        let mem = read_scriptint(&rs1_val).unwrap();

        // Value at rs1+imm will be memory address to store to.
        let sw_addr = mem + (dec_insn.imm as i64);
        println!(
            "rs1val={}, mem={} imm={}, sw_addr={}",
            hex::encode(rs1_val.clone()),
            mem,
            dec_insn.imm,
            sw_addr
        );
        let sw_index = Self::addr_to_index(sw_addr as usize);
        let sw_path = self.addr_to_merkle(sw_addr as u32);

        let start_root = self.pre_tree.root();
        let end_root = self.post_tree.root();

        let mut script = format!(
            "
                # top stack elements is the start root, push it to altstack for later
                OP_TOALTSTACK
        "
        );

        // Verify start PC, rs1 and rs2
        script = format!(
            "{}
        {} # pc

        # pc inclusion
        {}

        # rs2 on stack
        OP_DUP OP_TOALTSTACK
        # rs2 inclusion inclusion
        {}

        # rs1 on stack
        OP_DUP OP_TOALTSTACK
        # rs1 inclusion inclusion
        {}
        ",
            script,
            hex::encode(pc_start.clone()),
            self.register_inclusion_script(REG_MAX, 1),
            self.register_inclusion_script(dec_insn.rs2, 2),
            self.register_inclusion_script(dec_insn.rs1, 3),
        );

        let mut script = format!(
            "{}
        # on witness is binary encoding of memory index (including imm), calculate rs1 from it to
        #check that it matches.
        OP_0
",
            script
        );

        let bits = self.num_bits();
        for b in (0..bits) {
            let n = 1 << b;
            let script_num = Self::to_script_num(n);
            script = format!(
                "{}
                OP_SWAP
                OP_IF
                {} OP_ADD
                OP_ENDIF
            ",
                script,
                hex::encode(script_num)
            );
        }

        let offset = Self::to_script_num(GUEST_MIN_MEM as u32);

        script = format!(
            "{}
                # now check that the number from binary equals the opcode memory address
                # multiply by 4
                OP_DUP OP_ADD
                OP_DUP OP_ADD

                # add address offset.
                {} OP_ADD

                #subtract imm
                {} OP_SUB
                OP_FROMALTSTACK # rs1 from altstck
                OP_EQUALVERIFY
                OP_1
            ",
            script,
            hex::encode(offset),
            hex::encode(imm),
        );

        let mut witness = vec![hex::encode(start_root)];

        let pc_index = Self::addr_to_index(pc_addr as usize);
        let start_pc_proof = self.pre_tree.proof(pc_index, pc_start.clone()).unwrap();
        let rs2_proof = self.pre_tree.proof(rs2_index, rs2_val.clone()).unwrap();
        let rs1_proof = self.pre_tree.proof(rs1_index, rs1_val.clone()).unwrap();

        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        fn witness_encode(data: Vec<u8>) -> String {
            if data.len() == 0 {
                return "<>".to_string();
            }

            hex::encode(data)
        }

        witness.push(format!("{}", witness_encode(rs2_val)));
        for p in rs2_proof.clone() {
            witness.push(hex::encode(p))
        }

        witness.push(format!("{}", hex::encode(rs1_val)));
        for p in rs1_proof.clone() {
            witness.push(hex::encode(p))
        }

        for b in sw_path {
            if b {
                witness.push("01".to_string());
            } else {
                witness.push("<>".to_string());
            }
        }
        // NEXT: prove rs1 pre-tree inclusion.

        //        for p in start_pc_proof.clone() {
        //            witness.push(hex::encode(p))
        //        }
        //
        //        for p in end_pc_proof {
        //            witness.push(hex::encode(p))
        //        }
        //
        //        witness.push(hex::encode(rs1_val));
        //        for p in rs1_proof {
        //            witness.push(hex::encode(p))
        //        }
        //
        //        for p in rd_proof {
        //            witness.push(hex::encode(p))
        //        }

        Script {
            script: script,
            witness: witness.into_iter().rev().collect(),
        }
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
