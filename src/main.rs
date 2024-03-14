use bitcoin::script::{read_scriptint, write_scriptint};
use fast_merkle::Tree;
use risc0_binfmt::{MemoryImage, Program};
use risc0_zkvm::host::server::opcode::{MajorType, OpCode};
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, TraceEvent};
use risc0_zkvm_platform::memory::{GUEST_MAX_MEM, GUEST_MIN_MEM, SYSTEM};
use risc0_zkvm_platform::syscall::reg_abi::REG_SP;
use risc0_zkvm_platform::syscall::reg_abi::{REG_A0, REG_MAX};
use risc0_zkvm_platform::{PAGE_SIZE, WORD_SIZE};
use rrs_lib::process_instruction;
use sha2::{Digest, Sha256};

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::{env, fs};

mod processor;

use processor::BitcoinInstructionProcessor;

fn main() {
    println!("Hello, world!");

    let args: Vec<String> = env::args().collect();
    dbg!(&args);

    let file_path = &args[1];
    println!("parsing file {}", file_path);

    let input = &args[2];
    let x = u32::from_str(input).unwrap();
    println!("using x={} as program input", x);

    let mtxs = Arc::new(Mutex::new(Vec::new()));
    let trace = mtxs.clone();

    let mut builder = ExecutorEnv::builder();
    let env = builder
        .trace_callback(|e| {
            trace.lock().unwrap().push(e);
            Ok(())
        })
        .build()
        .unwrap();
    let elf_contents = fs::read(file_path).unwrap();
    let mut exec = ExecutorImpl::from_elf(env, &elf_contents).unwrap();

    // Input value is inserted into A= before execution starts.
    exec.write_register(REG_A0, x);

    // Recreated executor starting memory.
    let program = Program::load_elf(&elf_contents, GUEST_MAX_MEM as u32).unwrap();
    let img = exec.memory().unwrap();
    println!("got starting memory: 0x{:x}", img.pc);

    let mem_len = guest_mem_len();

    let mut first = true;
    let mut addr: u32 = 0;
    let mut scripts = HashMap::new();
    for _addr in program.program_range.step_by(WORD_SIZE) {
        addr = _addr;
        if first {
            println!("start 0x{:x}", addr);
        }
        first = false;

        let mut bytes = [0_u8; WORD_SIZE];
        img.load_region_in_page(addr, &mut bytes);

        let insn = u32::from_le_bytes(bytes);

        let opcode = OpCode::decode(insn, addr).unwrap();
        println!("0x{:x}: {:?}", addr, opcode);
        if opcode.major == MajorType::ECall {
            continue;
        }
        let mut outputter = BitcoinInstructionProcessor {
            str: format!("# pc: {:x}\t{:?}", addr, opcode),
            //str: format!("# pc: {:x}", addr),
            insn_pc: addr,
            start_addr: GUEST_MIN_MEM as u32,
            mem_len: mem_len as u32,
        };

        println!("inserting desc at 0x{:x}: {:?}", addr, opcode);
        let desc = process_instruction(&mut outputter, insn).unwrap();

        fs::create_dir_all("trace").unwrap(); // make sure the 'trace' directory exists

        let pc_str = format!("{:05x}", addr);
        let mut script_file = File::create(format!("trace/pc_{}_script.txt", pc_str)).unwrap();
        write!(script_file, "{}", desc.script).unwrap();

        scripts.insert(addr, desc);
    }

    println!("end 0x{:x}", addr);

    let _session = exec.run().unwrap();

    println!("trace: {:?}", trace.lock().unwrap().clone());

    //let zero_val = to_script_num(0u32.to_le_bytes());
    //let zero_val = 0u32.to_le_bytes();
    let zero_val = [0u8; 32];
    let mut mem_tree = Tree::new_with_default(mem_len, zero_val.into()).unwrap();
    let start = Instant::now();
    let start_root = build_merkle(&mut mem_tree, &img);
    let duration = start.elapsed();
    println!(
        "start root built from img={} in {:?}",
        hex::encode(start_root),
        duration,
    );

    let mut roots: Vec<[u8; 32]> = vec![start_root];

    // We'll keep two active merkle trees in order to prove the state of the computation before and
    // after each instruction. One is altered by the trace events, while the other is build from the bitcoin instruction processor.
    let mut script_tree = mem_tree.clone();

    // (pc, insn)
    let mut current_insn: (u32, u32) = (0, 0);
    //let mut current_opcode: Option<OpCode> = None;

    // Now we go through the trace once again, this time creating the scripts and witnesses for
    // each state transition.
    // TODO: organize in a way such that script and witness creation is seperate (don't know memory when creating scripts).
    // we can keep script creation in here as well, to assert they are the same.
    // iterate program range, decode insn, ignore if not a real instruction otherwise create script.
    let mut ins = 0;
    for (_i, e) in trace.lock().unwrap().iter().enumerate() {
        //println!("iteration[{}]={:?}", i, e);
        match e {
            // A new instruction is starting.
            TraceEvent::InstructionStart { cycle, pc, insn } => {
                // Set the new PC and get a state commitment. This will be the state of computation
                // before this instruction is executed, hence the post-state of the previous instruction.
                set_register(&mut mem_tree, REG_MAX, *pc);
                let root = mem_tree.commit();
                roots.push(root);

                println!("new root[{} cycle={}]={}", ins, *cycle, hex::encode(root));

                let pcc = current_insn.0;
                if pcc != 0 {
                    let desc = scripts.get(&pcc).unwrap();
                    let ins_str = format!("{:04x}", ins);

                    let (witness, mut w_tags) =
                        desc.witness_gen.generate_witness(&mut script_tree, root);

                    w_tags.extend(desc.tags.clone().into_iter());

                    let pc_str = format!("{:05x}", pcc);
                    let mut witness_file =
                        File::create(format!("trace/ins_{}_pc_{}_witness.txt", ins_str, pc_str))
                            .unwrap();
                    write!(witness_file, "{}", witness.join("\n")).unwrap();

                    let tags_file =
                        File::create(format!("trace/ins_{}_pc_{}_tags.json", ins_str, pc_str))
                            .unwrap();

                    let writer = BufWriter::new(tags_file);
                    serde_json::to_writer_pretty(writer, &w_tags).unwrap();

                    let mut hasher = Sha256::new();
                    let start_root = roots[roots.len() - 2];
                    let end_root = roots[roots.len() - 1];
                    hasher.update(start_root);
                    hasher.update(end_root);
                    let hash = hasher.finalize();
                    let hash_array: [u8; 32] = hash.into();
                    println!(
                        "h({}|{}) = {}",
                        hex::encode(start_root),
                        hex::encode(end_root),
                        hex::encode(hash_array)
                    );

                    let mut commitfile = File::create(format!(
                        "trace/ins_{}_pc_{}_commitment.txt",
                        ins_str, pc_str
                    ))
                    .unwrap();

                    write!(commitfile, "{}", hex::encode(hash_array)).unwrap();

                    // NEXT: add script/witness validation that will run each step.
                    // to avoid having to implement this (and OP_CCV) in rust, maybe write a Go program that can be run on the created scripts.

                    // Start and  end root alwyas first in the witness.
                    //let witness = vec![];
                }

                let r1 = hex::encode(script_tree.root());
                let r2 = hex::encode(mem_tree.root());
                if r1 != r2 {
                    panic!("root mismatch: {} vs {}", r1, r2);
                }

                let opcode = OpCode::decode(*insn, *pc).unwrap();
                println!("next opcode {:x}: {:?}", *pc, opcode);
                //current_opcode = Some(opcode);
                ins += 1;

                // Now that we've handled the previous instruction, set things up for processing
                // the next.
                current_insn = (*pc, *insn);

                //prev_root = root.clone();
            }
            TraceEvent::RegisterSet { idx, value } => {
                set_register(&mut mem_tree, *idx, *value);
            }
            TraceEvent::MemorySet { addr, region } => {
                set_addr(&mut mem_tree, (*addr) as usize, region.clone());
            }
        }
    }

    let root = mem_tree.commit();
    println!("final root[{}]={}", ins, hex::encode(root));

    // Return value is found in A0 after execution.
    let y = exec.read_register(REG_A0);
    println!("end y={}", y);
}

fn guest_mem_len() -> usize {
    let mut mem_len: usize = (GUEST_MAX_MEM - GUEST_MIN_MEM) / WORD_SIZE;

    println!("guest memory length {}", mem_len);

    // In addition to committing to the memory we want to commit to the registers. These are
    // already located in the host memory starting at SYSTEM.start.
    for _reg in 0..REG_MAX {
        mem_len += 1;
    }

    // Add room for pc.
    mem_len += 1;

    // Merkle tree implementation requires power of two.
    while !mem_len.is_power_of_two() {
        mem_len += 1;
    }
    println!("final memory length {}", mem_len);

    mem_len
}

fn set_register(fast_tree: &mut Tree, reg: usize, val: u32) {
    println!("register {} (SP={}) set to {:08x}", reg, reg == REG_SP, val);
    let sys_addr = SYSTEM.start();
    let addr = sys_addr + (reg * WORD_SIZE);

    set_addr(fast_tree, addr, val.to_le_bytes().into());
}

fn addr_word(fast_tree: &mut Tree, addr: usize, val: Vec<u8>) -> [u8; 4] {
    let (index, offset) = addr_to_index(addr);
    let n = val.len();
    if !(n == 1 || n == WORD_SIZE / 2 || n == WORD_SIZE) {
        panic!("invalid word length");
    }
    if offset + n > WORD_SIZE {
        panic!("unaligned write")
    }

    if n == WORD_SIZE && offset == 0 {
        return val.try_into().unwrap();
    }

    // Otherwise get the original data.
    let word = fast_tree.get_leaf(index);
    let mut le = from_mem_repr(word);

    for (i, b) in val.iter().enumerate() {
        le[i + offset] = *b
    }

    le
}

fn set_addr(fast_tree: &mut Tree, addr: usize, val: Vec<u8>) {
    let b = addr_word(fast_tree, addr, val);
    //let b = val.to_le_bytes();
    let val = u32::from_le_bytes(b);
    let mem = to_mem_repr(b);
    println!(
        "memory addr={:x}  set to {:08x} (le={}) mem={}",
        addr,
        val,
        hex::encode(b),
        hex::encode(mem),
    );
    set_commit(fast_tree, addr, b);
}

fn load_addr(img: &MemoryImage, addr: usize) -> [u8; 4] {
    let mut b: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    img.load_region_in_page(addr as u32, &mut b[..]);

    b
}

// mem repr: [a0 a1 ... a31]
// where a0 is LSB
fn to_mem_repr(b: [u8; 4]) -> Vec<u8> {
    let bits = 32;
    let w = u32::from_le_bytes(b);

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

fn from_mem_repr(mem: Vec<u8>) -> [u8; 4] {
    if mem.len() != 32 {
        panic!("uneexpected word len");
    }

    let bits = 32;

    let mut val = 0u32;
    for i in (0..bits) {
        let n = 1 << i;
        if mem[i] == 1 {
            val += n
        }
    }

    val.to_le_bytes()
}

fn to_script_num(b: [u8; 4]) -> Vec<u8> {
    let w = u32::from_le_bytes(b);

    let mut script_num: [u8; 8] = [0; 8];
    let n = write_scriptint(&mut script_num, w as i64);

    script_num[..n].to_vec()
}
fn set_commit(fast_tree: &mut Tree, addr: usize, b: [u8; 4]) {
    //println!("setting addr {:x}", addr);
    // let script_num = to_script_num(b.clone());
    let (index, _) = addr_to_index(addr);
    //    println!(
    //        "converting addr {}={} for commit->{}",
    //        addr,
    //        hex::encode(b),
    //        hex::encode(script_num.clone())
    //    );

    let mem = to_mem_repr(b);

    //fast_tree.set_leaf(index, script_num);
    fast_tree.set_leaf(index, mem);
}

fn build_merkle(fast_tree: &mut Tree, img: &MemoryImage) -> [u8; 32] {
    let temp_image = img;
    let pc = img.pc;
    //    println!("temp image pc {}", temp_image.pc);
    //    println!("pages {}", temp_image.pages.len());
    //    println!("max memory 0x{:08x}",GUEST_MAX_MEM);

    let end_mem = GUEST_MAX_MEM;
    for addr in (GUEST_MIN_MEM..end_mem).step_by(WORD_SIZE) {
        let b = load_addr(temp_image, addr);
        set_commit(fast_tree, addr, b);
    }

    let sys_addr = SYSTEM.start();
    for reg in 0..REG_MAX {
        let addr = sys_addr + (reg * WORD_SIZE);
        let b = load_addr(temp_image, addr);

        set_commit(fast_tree, addr, b);
    }

    // Push PC
    let pc_addr = SYSTEM.start() + REG_MAX * WORD_SIZE;
    set_commit(fast_tree, pc_addr, pc.to_le_bytes());
    let root = fast_tree.commit();

    return root;
}

// returns (index, word offset)
fn addr_to_index(addr: usize) -> (usize, usize) {
    (
        (addr - GUEST_MIN_MEM) / WORD_SIZE,
        (addr - GUEST_MIN_MEM) % WORD_SIZE,
    )
}
