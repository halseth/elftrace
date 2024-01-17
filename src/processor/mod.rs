#![allow(unused)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use bitcoin::script::{read_scriptint, write_scriptint};
use risc0_zkvm_platform::memory::{GUEST_MAX_MEM, GUEST_MIN_MEM, SYSTEM};
use risc0_zkvm_platform::syscall::reg_abi::{REG_MAX, REG_ZERO};
use risc0_zkvm_platform::WORD_SIZE;
use rrs_lib::instruction_formats::{BType, IType, ITypeShamt, JType, RType, SType, UType};
use rrs_lib::{
    instruction_formats, instruction_string_outputter::InstructionStringOutputter,
    process_instruction, InstructionProcessor,
};
use std::collections::HashMap;
use std::fmt::format;
use std::iter::Map;

fn to_script_num<T: Into<i64>>(w: T) -> Vec<u8> {
    let mut script_num: [u8; 8] = [0; 8];
    let n = write_scriptint(&mut script_num, w.into());

    script_num[..n].to_vec()
}

// TODO: used 4 byte array instead?
fn to_mem_repr(w: u32) -> Vec<u8> {
    let bits = 32;
    //let w = u32::from_le_bytes(b);

    let mut v: Vec<u8> = vec![];
    for b in (0..bits).map(|n| (w >> n) & 1) {
        if b == 0 {
            v.push(0);
        } else {
            v.push(1);
        }
    }

    v
}

fn from_mem_repr(v: Vec<u8>) -> u32 {
    let bits = 32;
    let mut w = 0u32;

    for i in (0..bits) {
        if v[i] == 1 {
            w += 1u32 << i;
        }
    }

    w
}

fn push_altstack(script: &String) -> String {
    format!(
        "{}
                # top stack elements is the start root, push it to altstack for later
                OP_TOALTSTACK
        ",
        script,
    )
}

// input: [a31 b31 ... a1 b1 a0 b0]
// output: [c31 ... c1 c0]
// where c=a+b
fn add_u32_two_compl() -> String {
    let mut s = "".to_string();

    s += "
    OP_0 #dummy carry
    ";
    for i in (0..32) {
        s = format!(
            "
            {}

            OP_ADD # add carry
            OP_ADD # add next bit

            OP_DUP
            OP_2
            OP_GREATERTHANOREQUAL
            OP_IF
              OP_2
              OP_SUB
              OP_1 # carry bit
            OP_ELSE
              OP_0 # carry bit
            OP_ENDIF

            OP_SWAP

            # bit to alt stack
            OP_TOALTSTACK

            # carry bit on stack
        ",
            s
        );
    }

    s = format!(
        "
            {}
            OP_DROP # drop carry bit
        ",
        s
    );

    for i in (0..32) {
        s = format!(
            "
            {}
            OP_FROMALTSTACK
        ",
            s
        );
    }

    s
}

//input : [c0 c1 .. c30 c31]
//output: [c31|c30...c1|c0]
fn cat_32_bits(copy_to_alt: bool) -> String {
    let mut s = "".to_string();
    if copy_to_alt {
        s = format!(
            "
            {}
        OP_DUP OP_TOALTSTACK
        ",
            s
        );
    }

    s = format!(
        "
            {}
        # if 0 bit, change it to 00 byte before cat
        OP_DUP
        OP_NOTIF
          OP_DROP
          00
        OP_ENDIF
        ",
        s
    );

    for i in (0..31) {
        s = format!(
            "
            {}
        OP_SWAP
        ",
            s
        );

        if copy_to_alt {
            s = format!(
                "
            {}
        OP_DUP OP_TOALTSTACK
        ",
                s
            );
        }
        s = format!(
            "
            {}

        # if 0 bit, change it to 00 byte before cat
        OP_DUP
        OP_NOTIF
          OP_DROP
          00
        OP_ENDIF

        OP_CAT
        ",
            s
        );
    }

    s
}

pub fn reg_addr(reg: usize) -> u32 {
    (SYSTEM.start() + reg * WORD_SIZE) as u32
}

fn witness_encode(data: Vec<u8>) -> String {
    // if data.len() != 4 {
    //     panic!("not 4")
    // }

    let mut s: String = "".to_string();
    for d in data.iter().rev() {
        s += format!("{} ", witness_encode_bit(*d)).as_str();
    }

    s
}

fn push_bit(b: u8) -> String {
    if b == 0 {
        return "OP_0".to_string();
    }

    if b == 1 {
        return "OP_1".to_string();
    }

    panic!("non-bit value");
}

fn zip_with_altstack(data: Vec<u8>) -> String {
    let mut s: String = "".to_string();
    for d in data.iter().rev() {
        s = format!(
            "
            {}
            {}
            OP_FROMALTSTACK
            ",
            s,
            push_bit(*d),
        );
    }

    s
}


fn witness_encode_bit(b: u8) -> String {
    if b == 0 {
        return "<>".to_string();
    }

    if b == 1 {
        return "01".to_string();
    }

    panic!("non-bit value");
}


fn cat_encode(data: Vec<u8>) -> String {
    // if data.len() != 4 {
    //     panic!("not 4")
    // }

    let mut s: String = "".to_string();
    for d in data {
        s += format!("{:02x}", d).as_str();
    }

    s
}

fn addr_to_index(addr: usize) -> usize {
    (addr - GUEST_MIN_MEM) / WORD_SIZE
}

pub struct BitcoinInstructionProcessor {
    pub str: String,

    /// PC of the instruction being output. Used to generate disassembly of instructions with PC
    /// relative fields (such as BEQ and JAL).
    pub insn_pc: u32,

    pub start_addr: u32,
    pub mem_len: u32,
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

    // Checks inclusion, replaces pc with pc+4.
    // stack:
    // [rem] <pc inclusion proof>
    // alt stack: current root on top
    //
    // output:
    // stack: [rem] <new root>
    fn increment_pc(&self, script: String) -> String {
        let pc_start = to_mem_repr(self.insn_pc);
        let pc_end = to_mem_repr(self.insn_pc + 4);

        // Verify start PC and amend to pc+4,
        format!(
            "{}
        {} # pc
        {} # pc+4

        # pc inclusion
        {}
        ",
            script,
            hex::encode(pc_start),
            hex::encode(pc_end),
            self.amend_register(REG_MAX, 1),
        )
    }

    fn add_pc(&self, script: String, imm: i32) -> String {
        let pc_start = to_mem_repr(self.insn_pc);
        let pc_end = to_mem_repr((self.insn_pc as i32 + imm) as u32);

        // Verify start PC and amend to pc+imm,
        format!(
            "{}
        {} # pc
        {} # pc+imm

        # pc inclusion
        {}
        ",
            script,
            hex::encode(pc_start.clone()),
            hex::encode(pc_end.clone()),
            self.amend_register(REG_MAX, 1),
        )
    }

    // checks start and end state againsst input commitment
    // stack: <end root>
    // altstack: <start root> at pos [root_pos-1]
    // NOTE: everything else on the alt stack will be dropped, as this is expected to be the last part of the script.
    // output:
    // stack: OP_1
    fn verify_commitment(&self, script: String, root_pos: u32) -> String {
        let mut script = script;
        for _ in (0..root_pos - 1) {
            script = format!(
                "{}
        OP_FROMALTSTACK OP_DROP
",
                script,
            );
        }

        format!(
            "{}
       # check input commitment
       OP_FROMALTSTACK
        OP_SWAP
        OP_CAT
        OP_SHA256
        OP_0 # index
        OP_0 # nums key
        OP_1NEGATE # current taptree
        OP_1 # flags, check input
        OP_CHECKCONTRACTVERIFY
         OP_1
",
            script,
        )
    }

    // Checks inclusion, replaces leaf with new data.
    // stack:
    // [rem] <old leaf> <new leaf>
    // alt stack: current root at position [root_pos-1]
    //
    // output:
    // stack: [rem] <new root>
    fn amend_register(&self, reg: usize, root_pos: u32) -> String {
        let mut script = format!("");

        // For zero register, result should always be zero.
        if reg == REG_ZERO {
            script = format!(
                "{}
            # pop value and set zero instead,
            OP_DROP
            0000000000000000000000000000000000000000000000000000000000000000
        ",
                script,
            );
        }

        let addr = reg_addr(reg);
        let path = self.addr_to_merkle(addr);
        let incl = Self::merkle_inclusion(&path);

        script = format!(
            "{}
            # hash new leaf
            OP_SHA256 OP_TOALTSTACK

            # hash old leaf
            OP_SHA256
        ",
            script,
        );

        for p in path {
            script = format!(
                "{}
# Use merkle sibling together with new leaf on alt stack to find new merkle
# node and push it to the altstack.
OP_2DUP OP_DROP # duplicate sibling
OP_FROMALTSTACK # get new node from alt stack",
                script
            );

            if p {
                script = format!(
                    "{}
OP_SWAP # swap direcion
        ",
                    script
                );
            }

            script = format!(
                "{}
OP_CAT OP_SHA256 OP_TOALTSTACK # combine to get new node to altstack
        ",
                script
            );

            if p {
                script = format!(
                    "{}
OP_SWAP # swap direcion
        ",
                    script
                );
            }
            script = format!(
                "{}
# Do the same with the current merkle leaf.
OP_CAT OP_SHA256
        ",
                script
            );
        }

        // On alt stack: <old root> <new root>
        // on stack: <old root>

        // get old root on top
        script = format!(
            "{}
        OP_FROMALTSTACK # new root from alt stack
        OP_SWAP
",
            script
        );

        for _ in (0..root_pos) {
            script = format!(
                "{}
        OP_FROMALTSTACK # current element from alt stack",
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

        // On alt stack: <old root> <new root>
        // on stack: <old root> <old root>
        script = format!(
            "{}
OP_EQUALVERIFY # verify old root
        ",
            script
        );

        script
    }

    // Checks inclusion, replaces leaf with new data.
    // stack:
    // [rem] <left/right child> <0: traverse left/1:traverse right> ... <old leaf> <new leaf>
    // alt stack: root at position [root_pos-1]
    // output:
    // stack: [rem] <new root>
    // alt stack: [rem] <path bits>
    fn amend_path(&self, num_levels: u32, root_pos: u32) -> String {
        let mut script = format!(
            "
            # hash new leaf
            OP_SHA256 OP_TOALTSTACK

            # hash old leaf
            OP_SHA256
        "
        );

        for i in (0..num_levels) {
            script = format!(
                "{}
# Use merkle sibling together with new leaf on alt stack to find new merkle
# node and push it to the altstack.
OP_3DUP OP_DROP OP_FROMALTSTACK # duplicate sibling and direction, get new node from alt stack
OP_SWAP
OP_DUP OP_TOALTSTACK # duplicate path
OP_IF OP_SWAP OP_ENDIF OP_CAT OP_SHA256 OP_TOALTSTACK # combine to get new node to altstack

# Do the same with the current merkle leaf.
OP_SWAP OP_IF OP_SWAP OP_ENDIF OP_CAT OP_SHA256
",
                script
            );
        }

        // On alt stack: <old root> <new root>
        // on stack: <old root>
        script = format!(
            "{}
OP_FROMALTSTACK # get new root from alt stack
OP_SWAP # put old root on top
        ",
            script
        );

        for _ in (0..root_pos) {
            script = format!(
                "{}
        OP_FROMALTSTACK # current element from alt stack",
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
OP_EQUALVERIFY # verify old root
        ",
            script
        );

        script
    }

    fn verify_path_inclusion(&self, num_levels: u32, root_pos: u32) -> String {
        let mut script = format!(
            "
            # hash leaf
            OP_SHA256
        "
        );

        for i in (0..num_levels) {
            script = format!(
                "{}
OP_SWAP # bit on top
OP_DUP OP_TOALTSTACK # duplicate path bit

# Calc merkle node
OP_IF OP_SWAP OP_ENDIF OP_CAT OP_SHA256
",
                script
            );
        }

        for _ in (0..root_pos) {
            script = format!(
                "{}
        OP_FROMALTSTACK # current element from alt stack",
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
OP_EQUALVERIFY # verify root
        ",
            script
        );

        script
    }

    // checks inclusion of register in root on alt stack
    // stack: [rem] <value>
    // alt stack: root at position [root_pos-1]
    // output:
    // stack: [rem]
    fn register_inclusion_script(&self, reg: usize, root_pos: u32) -> String {
        let addr = reg_addr(reg);
        let path = self.addr_to_merkle(addr);
        let incl = Self::merkle_inclusion(&path);

        let mut script = format!(
            "
        # on stack is merkle proof for register. We already know the location in RAM, so only
        # nodes are needed.
        {}
        ",
            incl,
        );

        for _ in (0..root_pos) {
            script = format!(
                "{}
        OP_FROMALTSTACK # current element from alt stack",
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

    //    fn to_script_num(w: i64) -> Vec<u8> {
    //        let mut script_num: [u8; 8] = [0; 8];
    //        let n = write_scriptint(&mut script_num, w);
    //
    //        script_num[..n].to_vec()
    //    }
}

pub trait WitnessGenerator {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>);
}

struct WitnessAddi {
    insn_pc: u32,
    dec_insn: IType,
}

impl WitnessGenerator for WitnessAddi {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let start_root = pre_tree.root();
        add_tag(start_root.to_vec(), "start_root");
        let end_root = end_root;
        add_tag(end_root.to_vec(), "end_root");

        let pc_addr = reg_addr(REG_MAX);

        let pc_start = to_mem_repr(self.insn_pc);
        println!(
            "converting pc {} for script->{}",
            hex::encode((self.insn_pc).to_le_bytes()),
            hex::encode(pc_start.clone())
        );
        let pc_end = to_mem_repr(self.insn_pc + 4);
        let imm = to_mem_repr(self.dec_insn.imm as u32);

        add_tag(imm.clone(), "imm");
        add_tag(pc_start.clone(), "pc_start");
        add_tag(pc_end.clone(), "pc_end");

        let rd_addr = reg_addr(self.dec_insn.rd);
        let rs1_addr = reg_addr(self.dec_insn.rs1);
        let start_root = pre_tree.root();

        let rs1_index = addr_to_index(rs1_addr as usize);
        let rs1_val = pre_tree.get_leaf(rs1_index);
        add_tag(rs1_val.clone(), "rs1_val");
        let rs1_proof = pre_tree.proof(rs1_index, rs1_val.clone()).unwrap();

        // We'll reverse it later.
        let mut witness = vec![hex::encode(start_root)];
        //let mut witness = vec![hex::encode(start_root), hex::encode(end_root)];

        witness.push(format!("{}", witness_encode(rs1_val.clone())));
        for p in rs1_proof {
            witness.push(hex::encode(p))
        }

        let rs_val = from_mem_repr(rs1_val);

        // Value at rs1+imm will be memory address to store to.
        let rd_index = addr_to_index(rd_addr as usize);
        let pre_rd_val = pre_tree.get_leaf(rd_index);
        add_tag(pre_rd_val.clone(), "pre_rd_val");

        let rd_val = rs_val as i64 + (self.dec_insn.imm as i64);
        let rd_mem = to_mem_repr(rd_val as u32);
        add_tag(rd_mem.clone(), "rd_val");

        let rd_proof = pre_tree.proof(rd_index, pre_rd_val.clone()).unwrap();
        witness.push(format!("{}", cat_encode(pre_rd_val.clone())));
        for p in rd_proof {
            witness.push(hex::encode(p))
        }

        if self.dec_insn.rd != REG_ZERO {
            pre_tree.set_leaf(rd_index, rd_mem.clone());
            pre_tree.commit();
        }

        let pc_index = addr_to_index(pc_addr as usize);
        let start_pc_proof = pre_tree.proof(pc_index, pc_start.clone()).unwrap();

        //        println!("proof that PC is {}:", hex::encode(pc_start.clone()));
        //        for p in start_pc_proof.clone() {
        //            println!("{}:", hex::encode(p));
        //        }

        pre_tree.set_leaf(pc_index, pc_end.clone());
        pre_tree.commit();

        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        let end_root_str = hex::encode(pre_tree.root());
        let post_root = hex::encode(end_root);
        if end_root_str != post_root {
            panic!("end root mismatch: {} vs {}", end_root_str, post_root);
        }

        (witness.into_iter().rev().collect(), tags)
    }
}
struct WitnessSlli {
    insn_pc: u32,
    dec_insn: ITypeShamt,
}

impl WitnessGenerator for crate::processor::WitnessSlli {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let start_root = pre_tree.root();
        add_tag(start_root.to_vec(), "start_root");
        add_tag(end_root.to_vec(), "end_root");

        let rs1_addr = reg_addr(self.dec_insn.rs1);
        let rs1_index = addr_to_index(rs1_addr as usize);
        let rs1_val = pre_tree.get_leaf(rs1_index);
        add_tag(rs1_val.clone(), "rs1_val");
        let rs1_proof = pre_tree.proof(rs1_index, rs1_val.clone()).unwrap();

        // We'll reverse it later.
        let mut witness = vec![hex::encode(start_root)];
        //let mut witness = vec![hex::encode(start_root), hex::encode(end_root)];

        witness.push(format!("{}", witness_encode(rs1_val.clone())));
        for p in rs1_proof {
            witness.push(hex::encode(p))
        }

        let rs_val = read_scriptint(&rs1_val).unwrap();

        let rd_addr = reg_addr(self.dec_insn.rd);
        let rd_index = addr_to_index(rd_addr as usize);
        let pre_rd_val = pre_tree.get_leaf(rd_index);
        add_tag(pre_rd_val.clone(), "pre_rd_val");

        let rd_val = rs_val << self.dec_insn.shamt;
        let rd_mem = to_script_num(rd_val);
        add_tag(rd_mem.clone(), "rd_val");

        let rd_proof = pre_tree.proof(rd_index, pre_rd_val.clone()).unwrap();
        witness.push(format!("{}", witness_encode(pre_rd_val.clone())));
        for p in rd_proof {
            witness.push(hex::encode(p))
        }

        if self.dec_insn.rd != REG_ZERO {
            pre_tree.set_leaf(rd_index, rd_mem.clone());
            pre_tree.commit();
        }

        let pc_addr = reg_addr(REG_MAX);
        let pc_index = addr_to_index(pc_addr as usize);
        let pc_start = to_script_num(self.insn_pc);
        let start_pc_proof = pre_tree.proof(pc_index, pc_start.clone()).unwrap();

        //        println!("proof that PC is {}:", hex::encode(pc_start));
        //        for p in start_pc_proof.clone() {
        //            println!("{}:", hex::encode(p));
        //        }

        let pc_end = to_script_num(self.insn_pc + 4);
        pre_tree.set_leaf(pc_index, pc_end.clone());
        pre_tree.commit();

        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        let end_root_str = hex::encode(pre_tree.root());
        let post_root = hex::encode(end_root);
        if end_root_str != post_root {
            panic!("end root mismatch: {} vs {}", end_root_str, post_root);
        }

        (witness.into_iter().rev().collect(), tags)
    }
}
struct WitnessLui {
    insn_pc: u32,
    dec_insn: UType,
}

impl WitnessGenerator for crate::processor::WitnessLui {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let start_root = pre_tree.root();
        add_tag(start_root.to_vec(), "start_root");
        add_tag(end_root.to_vec(), "end_root");

        // We'll reverse it later.
        let mut witness = vec![hex::encode(start_root)];

        let rd_addr = reg_addr(self.dec_insn.rd);
        let rd_index = addr_to_index(rd_addr as usize);
        let pre_rd_val = pre_tree.get_leaf(rd_index);
        add_tag(pre_rd_val.clone(), "pre_rd_val");

        let res = self.dec_insn.imm as u32;
        let rd_val = to_script_num(res);

        add_tag(rd_val.clone(), "rd_val");

        let rd_proof = pre_tree.proof(rd_index, pre_rd_val.clone()).unwrap();
        witness.push(format!("{}", witness_encode(pre_rd_val.clone())));
        for p in rd_proof {
            witness.push(hex::encode(p))
        }

        if self.dec_insn.rd != REG_ZERO {
            pre_tree.set_leaf(rd_index, rd_val.clone());
            pre_tree.commit();
        }

        let pc_addr = reg_addr(REG_MAX);
        let pc_index = addr_to_index(pc_addr as usize);
        let pc_start = to_script_num(self.insn_pc);
        let start_pc_proof = pre_tree.proof(pc_index, pc_start.clone()).unwrap();
        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        let pc_end = to_script_num(self.insn_pc + 4);
        pre_tree.set_leaf(pc_index, pc_end.clone());
        let end_root_str = hex::encode(pre_tree.commit());
        let post_root = hex::encode(end_root);
        if end_root_str != post_root {
            panic!("end root mismatch: {} vs {}", end_root_str, post_root);
        }

        (witness.into_iter().rev().collect(), tags)
    }
}

struct WitnessAuipc {
    insn_pc: u32,
    dec_insn: UType,
}

impl WitnessGenerator for crate::processor::WitnessAuipc {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let start_root = pre_tree.root();
        add_tag(start_root.to_vec(), "start_root");
        add_tag(end_root.to_vec(), "end_root");

        // We'll reverse it later.
        let mut witness = vec![hex::encode(start_root)];

        // Value at rs1+imm will be memory address to store to.
        let rd_addr = reg_addr(self.dec_insn.rd);
        let rd_index = addr_to_index(rd_addr as usize);
        let pre_rd_val = pre_tree.get_leaf(rd_index);
        add_tag(pre_rd_val.clone(), "pre_rd_val");

        let res = self.insn_pc + (self.dec_insn.imm as u32);
        let rd_val = to_script_num(res);

        add_tag(rd_val.clone(), "rd_val");

        let rd_proof = pre_tree.proof(rd_index, pre_rd_val.clone()).unwrap();
        witness.push(format!("{}", witness_encode(pre_rd_val.clone())));
        for p in rd_proof {
            witness.push(hex::encode(p))
        }

        if self.dec_insn.rd != REG_ZERO {
            pre_tree.set_leaf(rd_index, rd_val.clone());
            pre_tree.commit();
        }

        let pc_addr = reg_addr(REG_MAX);
        let pc_index = addr_to_index(pc_addr as usize);
        let pc_start = to_script_num(self.insn_pc);
        let start_pc_proof = pre_tree.proof(pc_index, pc_start.clone()).unwrap();

        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        let pc_end = to_script_num(self.insn_pc + 4);
        pre_tree.set_leaf(pc_index, pc_end.clone());
        let end_root_str = hex::encode(pre_tree.commit());
        let post_root = hex::encode(end_root);
        if end_root_str != post_root {
            panic!("end root mismatch: {} vs {}", end_root_str, post_root);
        }

        (witness.into_iter().rev().collect(), tags)
    }
}
struct WitnessBge {
    insn_pc: u32,
    dec_insn: BType,
}

impl WitnessGenerator for crate::processor::WitnessBge {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let start_root = pre_tree.root();
        add_tag(start_root.to_vec(), "start_root");
        add_tag(end_root.to_vec(), "end_root");

        let rs1_addr = reg_addr(self.dec_insn.rs1);
        let rs1_index = addr_to_index(rs1_addr as usize);
        let rs1_val = pre_tree.get_leaf(rs1_index);
        add_tag(rs1_val.clone(), "rs1_val");
        let rs1_proof = pre_tree.proof(rs1_index, rs1_val.clone()).unwrap();

        // We'll reverse it later.
        let mut witness = vec![hex::encode(start_root)];
        //let mut witness = vec![hex::encode(start_root), hex::encode(end_root)];

        witness.push(format!("{}", witness_encode(rs1_val.clone())));
        for p in rs1_proof {
            witness.push(hex::encode(p))
        }

        let rs2_addr = reg_addr(self.dec_insn.rs2);
        let rs2_index = addr_to_index(rs2_addr as usize);
        let rs2_val = pre_tree.get_leaf(rs2_index);
        add_tag(rs2_val.clone(), "rs2_val");
        let rs2_proof = pre_tree.proof(rs2_index, rs2_val.clone()).unwrap();

        witness.push(format!("{}", witness_encode(rs2_val.clone())));
        for p in rs2_proof {
            witness.push(hex::encode(p))
        }

        let pc_addr = reg_addr(REG_MAX);
        let pc_index = addr_to_index(pc_addr as usize);
        let pc_start = to_script_num(self.insn_pc);
        let start_pc_proof = pre_tree.proof(pc_index, pc_start.clone()).unwrap();

        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        let rs2_num = read_scriptint(&rs2_val).unwrap();
        let rs1_num = read_scriptint(&rs1_val).unwrap();

        let mut pc_end = to_script_num(self.insn_pc + 4);
        let branch_pc = self.insn_pc.wrapping_add(self.dec_insn.imm as u32);
        println!("branch_pc={:x}", branch_pc);
        let branch_val = to_script_num(branch_pc);

        if rs1_num >= rs2_num {
            pc_end = branch_val.clone();
        }

        pre_tree.set_leaf(pc_index, pc_end.clone());
        pre_tree.commit();

        let end_root_str = hex::encode(pre_tree.root());
        let post_root = hex::encode(end_root);
        if end_root_str != post_root {
            panic!("end root mismatch: {} vs {}", end_root_str, post_root);
        }
        (witness.into_iter().rev().collect(), tags)
    }
}
struct WitnessLw {
    insn_pc: u32,
    dec_insn: IType,
    start_addr: u32,
    mem_len: u32,
}

impl WitnessLw {
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
}

impl WitnessGenerator for crate::processor::WitnessLw {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let start_root = pre_tree.root();
        add_tag(start_root.to_vec(), "start_root");
        add_tag(end_root.to_vec(), "end_root");

        println!(
            "executing sw. pre={} post={}",
            hex::encode(start_root),
            hex::encode(end_root)
        );

        let rd_addr = reg_addr(self.dec_insn.rd);
        let rd_index = addr_to_index(rd_addr as usize);
        let rd_val = pre_tree.get_leaf(rd_index);
        add_tag(rd_val.clone(), "rd_val");
        println!(
            "rd={}, rd_addr={} rd_val={}",
            self.dec_insn.rd,
            rd_addr,
            hex::encode(rd_val.clone())
        );

        let rs1_addr = reg_addr(self.dec_insn.rs1);
        let rs1_index = addr_to_index(rs1_addr as usize);
        let rs1_val = pre_tree.get_leaf(rs1_index);
        add_tag(rs1_val.clone(), "rs1_val");

        let mem = read_scriptint(&rs1_val).unwrap();

        // Value at rs1+imm will be memory address to load from.
        let lw_addr = mem + (self.dec_insn.imm as i64);
        println!(
            "rs1val={}, mem={} imm={}, sw_addr={}",
            hex::encode(rs1_val.clone()),
            mem,
            self.dec_insn.imm,
            lw_addr
        );
        let lw_index = addr_to_index(lw_addr as usize);
        let lw_path = self.addr_to_merkle(lw_addr as u32);

        let mut witness = vec![hex::encode(start_root)];

        let rs1_proof = pre_tree.proof(rs1_index, rs1_val.clone()).unwrap();

        witness.push(format!("{}", witness_encode(rs1_val.clone())));
        for p in rs1_proof.clone() {
            witness.push(hex::encode(p))
        }

        // Reveal old value of memory location in witness.
        let mem_val = pre_tree.get_leaf(lw_index);
        println!(
            "mem val={} lw_addr={}, lw_index={}",
            hex::encode(mem_val.clone()),
            lw_addr,
            lw_index,
        );

        witness.push(format!("{}", witness_encode(mem_val.clone())));

        let sw_proof = pre_tree.proof(lw_index, mem_val.clone()).unwrap();

        for (i, b) in lw_path.iter().enumerate() {
            if *b {
                witness.push("01".to_string());
            } else {
                witness.push("<>".to_string());
            }
            let p = sw_proof[i];
            witness.push(hex::encode(p))
        }

        let rd_proof = pre_tree.proof(rd_index, rd_val.clone()).unwrap();

        witness.push(format!("{}", witness_encode(rd_val.clone())));
        for p in rd_proof.clone() {
            witness.push(hex::encode(p))
        }

        pre_tree.set_leaf(rd_index, mem_val.clone());
        pre_tree.commit();

        let pc_addr = reg_addr(REG_MAX);
        let pc_index = addr_to_index(pc_addr as usize);
        let pc_start = to_script_num(self.insn_pc);
        let start_pc_proof = pre_tree.proof(pc_index, pc_start.clone()).unwrap();
        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        let pc_end = to_script_num(self.insn_pc + 4);
        pre_tree.set_leaf(pc_index, pc_end.clone());
        pre_tree.commit();

        let end_root_str = hex::encode(pre_tree.root());
        let post_root = hex::encode(end_root);
        if end_root_str != post_root {
            panic!("end root mismatch: {} vs {}", end_root_str, post_root);
        }

        (witness.into_iter().rev().collect(), tags)
    }
}
struct WitnessSw {
    insn_pc: u32,
    dec_insn: SType,
    start_addr: u32,
    mem_len: u32,
}

impl crate::processor::WitnessSw {
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
}

impl WitnessGenerator for crate::processor::WitnessSw {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let rs2_addr = reg_addr(self.dec_insn.rs2);
        let rs2_index = addr_to_index(rs2_addr as usize);
        let rs2_val = pre_tree.get_leaf(rs2_index);
        add_tag(rs2_val.clone(), "rs2_val");
        println!(
            "rs2={}, rs2_addr={} rs2_val={}",
            self.dec_insn.rs2,
            rs2_addr,
            hex::encode(rs2_val.clone())
        );

        let start_root = pre_tree.root();
        add_tag(start_root.to_vec(), "start_root");
        add_tag(end_root.to_vec(), "end_root");

        println!(
            "executing sw. pre={} post={}",
            hex::encode(start_root),
            hex::encode(end_root)
        );

        let rs1_addr = reg_addr(self.dec_insn.rs1);
        let rs1_index = addr_to_index(rs1_addr as usize);
        let rs1_val = pre_tree.get_leaf(rs1_index);
        add_tag(rs1_val.clone(), "rs1_val");

        let mem = read_scriptint(&rs1_val).unwrap();

        // Value at rs1+imm will be memory address to store to.
        let sw_addr = mem + (self.dec_insn.imm as i64);
        println!(
            "rs1val={}, mem={} imm={}, sw_addr={}",
            hex::encode(rs1_val.clone()),
            mem,
            self.dec_insn.imm,
            sw_addr
        );
        let sw_index = addr_to_index(sw_addr as usize);
        let sw_path = self.addr_to_merkle(sw_addr as u32);

        let mut witness = vec![hex::encode(start_root)];

        let rs2_addr = reg_addr(self.dec_insn.rs2);
        let rs2_index = addr_to_index(rs2_addr as usize);

        let rs2_proof = pre_tree.proof(rs2_index, rs2_val.clone()).unwrap();

        witness.push(format!("{}", witness_encode(rs2_val.clone())));
        for p in rs2_proof.clone() {
            witness.push(hex::encode(p))
        }

        let rs1_proof = pre_tree.proof(rs1_index, rs1_val.clone()).unwrap();
        witness.push(format!("{}", hex::encode(rs1_val)));
        for p in rs1_proof.clone() {
            witness.push(hex::encode(p))
        }

        // Reveal old value of memory location in witness.
        let pre_mem_val = pre_tree.get_leaf(sw_index);
        println!(
            "prememval={}, new mem val={} sw_addr={}, sw_index={}",
            hex::encode(pre_mem_val.clone()),
            hex::encode(rs2_val.clone()),
            sw_addr,
            sw_index,
        );

        witness.push(format!("{}", witness_encode(pre_mem_val.clone())));

        let sw_proof = pre_tree.proof(sw_index, pre_mem_val.clone()).unwrap();

        for (i, b) in sw_path.iter().enumerate() {
            if *b {
                witness.push("01".to_string());
            } else {
                witness.push("<>".to_string());
            }
            let p = sw_proof[i];
            witness.push(hex::encode(p))
        }

        pre_tree.set_leaf(sw_index, rs2_val.clone());
        pre_tree.commit();

        let pc_addr = reg_addr(REG_MAX);
        let pc_index = addr_to_index(pc_addr as usize);
        let pc_start = to_script_num(self.insn_pc);
        let start_pc_proof = pre_tree.proof(pc_index, pc_start.clone()).unwrap();
        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        let pc_end = to_script_num(self.insn_pc + 4);
        pre_tree.set_leaf(pc_index, pc_end.clone());
        pre_tree.commit();

        let end_root_str = hex::encode(pre_tree.root());
        let post_root = hex::encode(end_root);
        if end_root_str != post_root {
            panic!("end root mismatch: {} vs {}", end_root_str, post_root);
        }

        (witness.into_iter().rev().collect(), tags)
    }
}
struct WitnessJal {
    insn_pc: u32,
    dec_insn: JType,
}

impl WitnessGenerator for crate::processor::WitnessJal {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let start_root = pre_tree.root();
        add_tag(start_root.to_vec(), "start_root");
        add_tag(end_root.to_vec(), "end_root");

        // We'll reverse it later.
        let mut witness = vec![hex::encode(start_root)];

        let rd_addr = reg_addr(self.dec_insn.rd);
        let rd_index = addr_to_index(rd_addr as usize);
        let pre_rd_val = pre_tree.get_leaf(rd_index);
        let res = self.insn_pc + 4;
        let rd_val = to_script_num(res);

        add_tag(pre_rd_val.clone(), "pre_rd_val");
        add_tag(rd_val.clone(), "rd_val");

        let rd_proof = pre_tree.proof(rd_index, pre_rd_val.clone()).unwrap();
        witness.push(format!("{}", witness_encode(pre_rd_val.clone())));
        for p in rd_proof {
            witness.push(hex::encode(p))
        }

        if self.dec_insn.rd != REG_ZERO {
            pre_tree.set_leaf(rd_index, rd_val.clone());
            pre_tree.commit();
        }

        let pc_addr = reg_addr(REG_MAX);
        let pc_index = addr_to_index(pc_addr as usize);
        let pc_start = to_script_num(self.insn_pc);
        let pc_end = to_script_num(self.insn_pc + self.dec_insn.imm as u32);
        let start_pc_proof = pre_tree.proof(pc_index, pc_start.clone()).unwrap();
        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        pre_tree.set_leaf(pc_index, pc_end.clone());
        let end_root_str = hex::encode(pre_tree.commit());
        let post_root = hex::encode(end_root);
        if end_root_str != post_root {
            panic!("end root mismatch: {} vs {}", end_root_str, post_root);
        }

        (witness.into_iter().rev().collect(), tags)
    }
}

struct WitnessJalr {
    insn_pc: u32,
    dec_insn: IType,
}

impl WitnessGenerator for crate::processor::WitnessJalr {
    fn generate_witness(
        &self,
        pre_tree: &mut fast_merkle::Tree,
        end_root: [u8; 32],
    ) -> (Vec<String>, HashMap<String, String>) {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let start_root = pre_tree.root();
        add_tag(start_root.to_vec(), "start_root");
        add_tag(end_root.to_vec(), "end_root");

        let rs1_addr = reg_addr(self.dec_insn.rs1);
        let rs1_index = addr_to_index(rs1_addr as usize);
        let rs1_val = pre_tree.get_leaf(rs1_index);
        add_tag(rs1_val.clone(), "rs1_val");
        let rs1_proof = pre_tree.proof(rs1_index, rs1_val.clone()).unwrap();

        // We'll reverse it later.
        let mut witness = vec![hex::encode(start_root)];
        //let mut witness = vec![hex::encode(start_root), hex::encode(end_root)];

        witness.push(format!("{}", witness_encode(rs1_val.clone())));
        for p in rs1_proof {
            witness.push(hex::encode(p))
        }

        let rd_addr = reg_addr(self.dec_insn.rd);
        let rd_index = addr_to_index(rd_addr as usize);
        let rd_val = pre_tree.get_leaf(rd_index);
        add_tag(rd_val.clone(), "rd_val");
        let rd_proof = pre_tree.proof(rd_index, rd_val.clone()).unwrap();

        witness.push(format!("{}", witness_encode(rd_val.clone())));
        for p in rd_proof {
            witness.push(hex::encode(p))
        }

        let pc_end = to_script_num(self.insn_pc + 4);
        if self.dec_insn.rd != REG_ZERO {
            pre_tree.set_leaf(rd_index, pc_end.clone());
            pre_tree.commit();
        }

        let pc_addr = reg_addr(REG_MAX);
        let pc_index = addr_to_index(pc_addr as usize);
        let pc_start = to_script_num(self.insn_pc);
        let start_pc_proof = pre_tree.proof(pc_index, pc_start.clone()).unwrap();

        for p in start_pc_proof.clone() {
            witness.push(hex::encode(p))
        }

        let rs_val = read_scriptint(&rs1_val).unwrap();
        let branch_pc = (rs_val as u32).wrapping_add(self.dec_insn.imm as u32);
        println!("branch_pc={:x}", branch_pc);
        let branch_val = to_script_num(branch_pc);

        pre_tree.set_leaf(pc_index, branch_val.clone());
        pre_tree.commit();

        let end_root_str = hex::encode(pre_tree.root());
        let post_root = hex::encode(end_root);
        if end_root_str != post_root {
            panic!("end root mismatch: {} vs {}", end_root_str, post_root);
        }

        (witness.into_iter().rev().collect(), tags)
    }
}

pub struct Script {
    pub script: String,
    pub tags: HashMap<String, String>,
    pub witness_gen: Box<dyn WitnessGenerator>,
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
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let pc_addr = reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);

        let pc_start = to_mem_repr(self.insn_pc);
        let pc_end = to_mem_repr(self.insn_pc + 4);
        //let imm = dec_insn.imm.to_le_bytes().to_vec();

        let imm = to_mem_repr(dec_insn.imm as u32);

        add_tag(imm.clone(), "imm");
        add_tag(pc_start.clone(), "pc_start");
        add_tag(pc_end.clone(), "pc_end");
        let rd_addr = reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        let rs1_addr = reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        let mut script = push_altstack(&self.str);

        // rs on stack, verify against start root on alt stack.
        script = format!(
            "{}
        # rs as [u1;32]= [a0 a1 ... a30 a31] on stack
        # cat 32 bits
        {}

        # check rs inclusion
        {}

        ",
            script,
            cat_32_bits(true),
            self.register_inclusion_script(dec_insn.rs1, 33),
        );

        script = format!(
            "{}

            # zip 32-bits of imm  with rs bits
           {} #imm

           # perform addition
            {}

            # cat rd 32 bits
            {}

           # build new root
           {}

    # current root on stack
    OP_TOALTSTACK
",
            script,
            zip_with_altstack(imm.clone()),
            add_u32_two_compl(),
            cat_32_bits(false),
            self.amend_register(dec_insn.rd, 1),
        );

        // Increment pc
        script = self.increment_pc(script);
        script = self.verify_commitment(script, 2);

        Script {
            script,
            witness_gen: Box::new(WitnessAddi {
                insn_pc: self.insn_pc,
                dec_insn: dec_insn,
            }),
            tags,
        }
    }

    fn process_slli(&mut self, dec_insn: ITypeShamt) -> Self::InstructionResult {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        println!("pc is {:b}", self.insn_pc);
        let pc_addr = reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);
//        for b in pc_path {
//            println!("bit: {}", b);
//        }

        let pc_start = to_script_num(self.insn_pc);
        println!(
            "converting pc {} for script->{}",
            hex::encode((self.insn_pc).to_le_bytes()),
            hex::encode(pc_start.clone())
        );
        let pc_end = to_script_num(self.insn_pc + 4);

        add_tag(pc_start.clone(), "pc_start");
        add_tag(pc_end.clone(), "pc_end");

        let rd_addr = reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        let rs1_addr = reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        let mut script = push_altstack(&self.str);

        // rs on stack, verify against start root on alt stack.
        script = format!(
            "{}
        # rs on stack
        OP_DUP OP_TOALTSTACK
        # rs inclusion
        {}

        OP_FROMALTSTACK
        ",
            script,
            self.register_inclusion_script(dec_insn.rs1, 2),
        );

        // Shift the value by shamt positsion by doubling it.
        for i in (0..dec_insn.shamt) {
            script = format!(
                "{}
           # double value (==shift left)
            OP_DUP OP_ADD
",
                script,
            );
        }

        script = format!(
            "{}
        # rd on stack
        {}

        OP_TOALTSTACK
        ",
            script,
            self.amend_register(dec_insn.rs1, 1),
        );

        // Increment pc
        script = self.increment_pc(script);
        script = self.verify_commitment(script, 2);

        Script {
            script: script,
            witness_gen: Box::new(WitnessSlli {
                insn_pc: self.insn_pc,
                dec_insn: dec_insn,
            }),
            tags: tags,
        }
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
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let pc_addr = reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);

        let pc_start = to_script_num(self.insn_pc);
        let pc_end = to_script_num(self.insn_pc + 4);
        let imm = to_script_num(dec_insn.imm);

        add_tag(imm.clone(), "imm");
        add_tag(pc_start.clone(), "pc_start");
        add_tag(pc_end.clone(), "pc_end");

        let rd_addr = reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        // NOTE: for some reason imm is already shifted, not entirely sure why.
        let res = dec_insn.imm as u32;
        let rd_val = to_script_num(res);
        //let rd_val = imm.clone();

        println!(
            "rd_val={:x} (as scriptnum={}), pc={:x} imm={:x} imm<<12={:x}",
            res,
            hex::encode(rd_val.clone()),
            self.insn_pc,
            dec_insn.imm,
            (dec_insn.imm as u32) << 12,
        );

        let mut script = push_altstack(&self.str);

        // Prove inclusion of new value
        script = format!(
            "{}
                   {} # rd_val

                   # build root
                   {}

            # new root on stack
            OP_TOALTSTACK
        ",
            script,
            hex::encode(rd_val.clone()),
            self.amend_register(dec_insn.rd, 1),
        );

        // Increment pc
        script = self.increment_pc(script);
        script = self.verify_commitment(script, 2);

        Script {
            script: script,
            witness_gen: Box::new(WitnessLui {
                insn_pc: self.insn_pc,
                dec_insn: dec_insn,
            }),
            tags: tags,
        }
    }

    fn process_auipc(&mut self, dec_insn: UType) -> Self::InstructionResult {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let pc_addr = reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);

        let pc_start = to_script_num(self.insn_pc);
        let pc_end = to_script_num(self.insn_pc + 4);
        let imm = to_script_num(dec_insn.imm);

        add_tag(imm.clone(), "imm");
        add_tag(pc_start.clone(), "pc_start");
        add_tag(pc_end.clone(), "pc_end");

        let rd_addr = reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        // Since we know the PC and imm before executing this instruction, we can do the calculation here and hardcode the result in the script.
        //let res =self.insn_pc + (dec_insn.imm as u32) << 12;
        // NOTE: for some reason imm is already shifted, not entirely sure why.
        let res = self.insn_pc + (dec_insn.imm as u32);

        let rd_val = to_script_num(res);
        //let rd_val = imm.clone();

        println!(
            "rd_val={:x} (as scriptnum={}), pc={:x} imm={:x} imm<<12={:x}",
            res,
            hex::encode(rd_val.clone()),
            self.insn_pc,
            dec_insn.imm,
            (dec_insn.imm as u32) << 12,
        );

        let mut script = push_altstack(&self.str);

        // Prove inclusion of new value
        script = format!(
            "{}
                   {} # rd_val

                   # build root
                   {}

            # new root on stack
            OP_TOALTSTACK
        ",
            script,
            hex::encode(rd_val.clone()),
            self.amend_register(dec_insn.rd, 1),
        );

        // Increment pc
        script = self.increment_pc(script);
        script = self.verify_commitment(script, 2);

        Script {
            script: script,
            witness_gen: Box::new(WitnessAuipc {
                insn_pc: self.insn_pc,
                dec_insn: dec_insn,
            }),

            tags: tags,
        }
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
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        println!("pc is {:b}", self.insn_pc);
        let pc_addr = reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);

        let pc_start = to_script_num(self.insn_pc);
        println!(
            "converting pc {} for script->{}",
            hex::encode((self.insn_pc).to_le_bytes()),
            hex::encode(pc_start.clone())
        );

        let mut pc_end = to_script_num(self.insn_pc + 4);
        let imm = to_script_num(dec_insn.imm);

        add_tag(imm.clone(), "imm");
        add_tag(pc_start.clone(), "pc_start");
        add_tag(pc_end.clone(), "pc_end");

        //        println!(
        //            "branch_val={:x} (as scriptnum={}), pc={:x} imm={:x} imm<<12={:x}",
        //            res,
        //            hex::encode(rd_val.clone()),
        //            self.insn_pc,
        //            dec_insn.imm,
        //            (dec_insn.imm as u32) << 12,
        //        );
        println!("imm {:x} for script->{}", dec_insn.imm, hex::encode(imm),);

        let rs2_addr = reg_addr(dec_insn.rs2);
        let rs2_path = self.addr_to_merkle(rs2_addr);
        let rs2_incl = Self::merkle_inclusion(&rs2_path);

        let rs1_addr = reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        let mut script = push_altstack(&self.str);

        // rs1 on stack, verify against start root on alt stack.
        script = format!(
            "{}
                # rs1 on stack
                OP_DUP OP_TOALTSTACK
                # rs1 inclusion
                {}
                ",
            script,
            self.register_inclusion_script(dec_insn.rs1, 2),
        );

        // rs2 on stack, verify against start root on alt stack.
        script = format!(
            "{}
                # rs2 on stack
                OP_DUP OP_TOALTSTACK
                # rs2 inclusion
                {}
                ",
            script,
            self.register_inclusion_script(dec_insn.rs2, 3),
        );

        let branch_pc = self.insn_pc.wrapping_add(dec_insn.imm as u32);
        println!("branch_pc={:x}", branch_pc);
        let branch_val = to_script_num(branch_pc);

        script = format!(
            "{}
            {} # pc
            OP_FROMALTSTACK # rs2
            OP_FROMALTSTACK # rs1
            OP_SWAP
            OP_GREATERTHANOREQUAL # rs1 >= rs2
            OP_IF
                {} # pc+offset
            OP_ELSE
                {} # pc+4
            OP_ENDIF

            # pc inclusion
                   {}
        ",
            script,
            hex::encode(pc_start.clone()),
            hex::encode(branch_val.clone()),
            hex::encode(pc_end.clone()),
            self.amend_register(REG_MAX, 1),
        );

        script = self.verify_commitment(script, 1);

        Script {
            script: script,
            witness_gen: Box::new(WitnessBge {
                insn_pc: self.insn_pc,
                dec_insn: dec_insn,
            }),

            tags: tags,
        }
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
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        println!("dec_insn={:?}", dec_insn);
        println!("pc is {:b}", self.insn_pc);
        let pc_addr = reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);
//        for b in pc_path {
//            println!("bit: {}", b);
//        }

        let pc_start = to_script_num(self.insn_pc);
        add_tag(pc_start.clone(), "pc_start");
        println!(
            "converting pc {} for script->{}",
            hex::encode((self.insn_pc).to_le_bytes()),
            hex::encode(pc_start.clone())
        );
        let pc_end = to_script_num(self.insn_pc + 4);
        add_tag(pc_end.clone(), "pc_end");
        let imm = to_script_num(dec_insn.imm);

        let rs1_addr = reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        let rd_addr = reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        let rd_index = addr_to_index(rd_addr as usize);

        // get value in rs1 and convert from scriptint.
        let rs1_index = addr_to_index(rs1_addr as usize);
        println!("rs1addr={}, index={}", rs1_addr, rs1_index);

        let mut script = push_altstack(&self.str);

        // steps
        // 1. check value rs1 from witness against start root
        // 3. execute merkle proof on witness to check inclusion of rd at memory location
        // 2. build end root from rd
        // 4. Use the bits from the previous merkle proof to calculate the meory index
        // 5. check that the memory index matches rs+imm

        // rs2 on stack, verify against root on alt stack.
        script = format!(
            "{}
                # rs1 on stack
                OP_DUP OP_TOALTSTACK
                # rs1 inclusion
                {}
                ",
            script,
            self.register_inclusion_script(dec_insn.rs1, 2),
        );

        let bits = self.num_bits();
        script = format!(
            "{}
                    # rd on stack, verify merkle proof for memory location.
                OP_DUP OP_TOALTSTACK
        # rd inclusion
        {}
                ",
            script,
            self.verify_path_inclusion(bits, 3 + bits),
        );

        // On stack: new root
        // alt stack: bits
        script = format!(
                    "{}
                # on alt stack is binary encoding of memory index (including imm), calculate rs1 from it to
                #check that it matches.
                OP_0
        ",
                    script
                );

        for b in (0..bits).rev() {
            let n = 1 << b;
            let script_num = to_script_num(n);
            script = format!(
                "{}
            OP_FROMALTSTACK
                        OP_IF
                        {} OP_ADD
                        OP_ENDIF
                    ",
                script,
                hex::encode(script_num)
            );
        }

        let offset = to_script_num(GUEST_MIN_MEM as u32);

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

                        # get rs1 from alt stack
                        OP_FROMALTSTACK # rd
                        OP_FROMALTSTACK # rs1
                        OP_SWAP OP_TOALTSTACK
                        OP_EQUALVERIFY
                    ",
            script,
            hex::encode(offset.clone()),
            hex::encode(imm.clone()),
        );
        add_tag(offset.clone(), "address offset");
        add_tag(imm.clone(), "imm");

        // Build new root from rd
        script = format!(
            "{}
                    # old rd on stack, new rd on alt stack
                    OP_FROMALTSTACK # new rd

                   # build root
                   {}

            # new root on stack
            OP_TOALTSTACK
        ",
            script,
            self.amend_register(dec_insn.rd, 1),
        );

        // Increment pc
        script = self.increment_pc(script);
        script = self.verify_commitment(script, 2);

        Script {
            script: script,
            witness_gen: Box::new(WitnessLw {
                insn_pc: self.insn_pc,
                dec_insn: dec_insn,
                start_addr: self.start_addr,
                mem_len: self.mem_len,
            }),

            tags: tags,
        }
    }

    fn process_sb(&mut self, dec_insn: SType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sh(&mut self, dec_insn: SType) -> Self::InstructionResult {
        todo!()
    }

    fn process_sw(&mut self, dec_insn: SType) -> Self::InstructionResult {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        println!("dec_insn={:?}", dec_insn);
        println!("pc is {:b}", self.insn_pc);
        let pc_addr = reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);
//        for b in pc_path {
//            println!("bit: {}", b);
//        }

        let pc_start = to_script_num(self.insn_pc);
        add_tag(pc_start.clone(), "pc_start");
        println!(
            "converting pc {} for script->{}",
            hex::encode((self.insn_pc).to_le_bytes()),
            hex::encode(pc_start.clone())
        );
        let pc_end = to_script_num(self.insn_pc + 4);
        add_tag(pc_end.clone(), "pc_end");
        let imm = to_script_num(dec_insn.imm);

        let rs1_addr = reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        let rs2_addr = reg_addr(dec_insn.rs2);
        let rs2_path = self.addr_to_merkle(rs2_addr);
        let rs2_incl = Self::merkle_inclusion(&rs2_path);

        let rs2_index = addr_to_index(rs2_addr as usize);

        // get value in rs1 and convert from scriptint.
        let rs1_index = addr_to_index(rs1_addr as usize);
        println!("rs1addr={}, index={}", rs1_addr, rs1_index);

        let mut script = push_altstack(&self.str);

        // steps
        // 1. check value rs2 from witness against start root
        // 2. check value rs1 from witness against start root
        // 3. execute merkle proof on witness to build the new root with rs2 set at mempry location
        // 4. Use the bits from the previous merkle proof to calculate the meory index
        // 5. check that the memory index matches rs1+imm

        // rs2 on stack, verify against root on alt stack.
        script = format!(
            "{}
                # rs2 on stack
                OP_DUP OP_TOALTSTACK
                # rs2 inclusion
                {}
                ",
            script,
            self.register_inclusion_script(dec_insn.rs2, 2),
        );

        // verify rs1
        script = format!(
            "{}
                # rs1 on stack
                OP_DUP OP_TOALTSTACK
                # rs1 inclusion
                {}
        #OP_1
                ",
            script,
            self.register_inclusion_script(dec_insn.rs1, 3),
        );

        let bits = self.num_bits();
        script = format!(
            "{}
                    # get rs2 from alt stack, we will prove it is in the new root.
                    OP_FROMALTSTACK #rs1
                    OP_FROMALTSTACK #rs2
                    OP_SWAP OP_TOALTSTACK
        {}
                ",
            script,
            self.amend_path(bits, 2 + bits),
        );

        // On stack: new root
        // alt stack: bits
        script = format!(
                    "{}
                # on witness is binary encoding of memory index (including imm), calculate rs1 from it to
                #check that it matches.
                OP_0
        ",
                    script
                );

        for b in (0..bits).rev() {
            let n = 1 << b;
            let script_num = to_script_num(n);
            script = format!(
                "{}
            OP_FROMALTSTACK
                        OP_IF
                        {} OP_ADD
                        OP_ENDIF
                    ",
                script,
                hex::encode(script_num)
            );
        }

        let offset = to_script_num(GUEST_MIN_MEM as u32);

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

                        # get rs1 from alt stack
                        OP_FROMALTSTACK
                        OP_EQUALVERIFY
                    ",
            script,
            hex::encode(offset.clone()),
            hex::encode(imm.clone()),
        );
        add_tag(offset.clone(), "address offset");
        add_tag(imm.clone(), "imm");

        // new root on stack.
        script = push_altstack(&script);

        // Increment pc
        script = self.increment_pc(script);
        script = self.verify_commitment(script, 2);

        Script {
            script: script,
            witness_gen: Box::new(WitnessSw {
                insn_pc: self.insn_pc,
                dec_insn: dec_insn,
                start_addr: self.start_addr,
                mem_len: self.mem_len,
            }),
            tags: tags,
        }
    }

    fn process_jal(&mut self, dec_insn: JType) -> Self::InstructionResult {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        let pc_addr = reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);

        let pc_start = to_script_num(self.insn_pc);
        let pc_end = to_script_num(self.insn_pc + dec_insn.imm as u32);
        let imm = to_script_num(dec_insn.imm);

        add_tag(imm.clone(), "imm");
        add_tag(pc_start.clone(), "pc_start");
        add_tag(pc_end.clone(), "pc_end");

        let rd_addr = reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        // Since we know the PC and imm before executing this instruction, we can do the calculation here and hardcode the result in the script.
        //let res =self.insn_pc + (dec_insn.imm as u32) << 12;
        // NOTE: for some reason imm is already shifted, not entirely sure why.
        let res = self.insn_pc + 4;

        let rd_val = to_script_num(res);
        //let rd_val = imm.clone();

        println!(
            "rd_val={:x} (as scriptnum={}), pc={:x} imm={:x} imm<<12={:x}",
            res,
            hex::encode(rd_val.clone()),
            self.insn_pc,
            dec_insn.imm,
            (dec_insn.imm as u32) << 12,
        );

        let mut script = push_altstack(&self.str);

        let mut root_pos = 1;
        //h        if dec_insn.rd != REG_ZERO {
        // Prove inclusion of new value
        script = format!(
            "{}
                   {} # rd_val

                   # build root
                   {}

            # new root on stack
            OP_TOALTSTACK
        ",
            script,
            hex::encode(rd_val.clone()),
            self.amend_register(dec_insn.rd, 1),
        );
        root_pos += 1;
        //       }

        // Set new pc to pc + imm;
        script = self.add_pc(script, dec_insn.imm);
        script = self.verify_commitment(script, root_pos);

        Script {
            script: script,
            witness_gen: Box::new(WitnessJal {
                insn_pc: self.insn_pc,
                dec_insn: dec_insn,
            }),

            tags: tags,
        }
    }

    fn process_jalr(&mut self, dec_insn: IType) -> Self::InstructionResult {
        let mut tags = HashMap::new();
        let mut add_tag = |k: Vec<u8>, v: &str| {
            if k.len() == 0 {
                return;
            }
            tags.insert(hex::encode(k), v.to_string());
        };

        println!("pc is {:b}", self.insn_pc);
        let pc_addr = reg_addr(REG_MAX);
        let pc_path = self.addr_to_merkle(pc_addr);
        let pc_incl = Self::merkle_inclusion(&pc_path);

        let pc_start = to_script_num(self.insn_pc);
        println!(
            "converting pc {} for script->{}",
            hex::encode((self.insn_pc).to_le_bytes()),
            hex::encode(pc_start.clone())
        );

        let mut pc_end = to_script_num(self.insn_pc + 4);
        let imm = to_script_num(dec_insn.imm);

        add_tag(imm.clone(), "imm");
        add_tag(pc_start.clone(), "pc_start");
        add_tag(pc_end.clone(), "pc_end");

        println!(
            "imm {:x} for script->{}",
            dec_insn.imm,
            hex::encode(imm.clone()),
        );

        let rd_addr = reg_addr(dec_insn.rd);
        let rd_path = self.addr_to_merkle(rd_addr);
        let rd_incl = Self::merkle_inclusion(&rd_path);

        let rs1_addr = reg_addr(dec_insn.rs1);
        let rs1_path = self.addr_to_merkle(rs1_addr);
        let rs1_incl = Self::merkle_inclusion(&rs1_path);

        let mut script = push_altstack(&self.str);

        // rs1 on stack, verify against start root on alt stack.
        script = format!(
            "{}
                # rs1 on stack
                OP_DUP OP_TOALTSTACK
                # rs1 inclusion
                {}
                ",
            script,
            self.register_inclusion_script(dec_insn.rs1, 2),
        );

        // prev rd on stack
        script = format!(
            "{}
                # old rd on stack

                # new rd is pc+4
                {}

                # rd inclusion
                {}

                OP_TOALTSTACK
                ",
            script,
            hex::encode(pc_end.clone()),
            self.amend_register(dec_insn.rd, 2),
        );

        script = format!(
            "{}
            {} # pc
            OP_FROMALTSTACK # current root
            OP_FROMALTSTACK # rs1
            OP_SWAP OP_TOALTSTACK
            {} # offset
            OP_ADD

            # pc inclusion
                   {}
        ",
            script,
            hex::encode(pc_start.clone()),
            witness_encode(imm.clone()),
            self.amend_register(REG_MAX, 1),
        );

        script = self.verify_commitment(script, 2);

        Script {
            script: script,
            witness_gen: Box::new(WitnessJalr {
                insn_pc: self.insn_pc,
                dec_insn: dec_insn,
            }),

            tags: tags,
        }
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
