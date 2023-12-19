use bitcoin::script::write_scriptint;
use fast_merkle::Tree;
use risc0_zkvm::host::server::opcode::OpCode;
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, MemoryImage, Program, TraceEvent};
use risc0_zkvm_platform::memory::{GUEST_MAX_MEM, GUEST_MIN_MEM, SYSTEM};
use risc0_zkvm_platform::syscall::reg_abi::REG_MAX;
use risc0_zkvm_platform::syscall::reg_abi::REG_SP;
use risc0_zkvm_platform::{PAGE_SIZE, WORD_SIZE};
use rrs_lib::process_instruction;
use sha2::{Digest, Sha256};

use std::fs::File;
use std::io::{BufWriter, Write};
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

    // Recreated executor starting memory.
    let program = Program::load_elf(&elf_contents, GUEST_MAX_MEM as u32).unwrap();
    let img = MemoryImage::new(&program, PAGE_SIZE as u32).unwrap();
    println!("got starting memory: {}", img.pc);

    let mem_len = guest_mem_len();

    let mut first = true;
    let mut addr: u32 = 0;
    //    for _addr in program.program_range.step_by(WORD_SIZE) {
    //        addr = _addr;
    //        if first {
    //            println!("start 0x{:x}", addr);
    //        }
    //        first = false;
    //
    //        let mut bytes = [0_u8; WORD_SIZE];
    //        img.load_region_in_page(addr, &mut bytes);
    //
    //        let insn = u32::from_le_bytes(bytes);
    //
    //        let opcode = OpCode::decode(insn, addr).unwrap();
    //        println!("0x{:x}: {:?}", addr, opcode);
    //        let dummy_num: u32 = 3;
    //        let mut outputter = BitcoinInstructionProcessor {
    //            str: format!("# pc: {:x}\t{:?}", addr, opcode),
    //            //str: format!("# pc: {:x}", addr),
    //            insn_pc: addr,
    //            start_addr: GUEST_MIN_MEM as u32,
    //            mem_len: mem_len as u32,
    //            //pre_tree: None,
    //            //end_root: None,
    //            dummy_num: &dummy_num,
    //        };
    //
    //        let desc = process_instruction(&mut outputter, insn).unwrap();
    //    }

    println!("end 0x{:x}", addr);

    let _session = exec.run().unwrap();

    println!("trace: {:?}", trace.lock().unwrap().clone());

    let zero_val = to_script_num(0u32.to_le_bytes());
    let mut mem_tree = Tree::new_with_default(mem_len, zero_val.clone()).unwrap();
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
                    //let opcode = current_opcode.unwrap();
                    //println!("executing opcode {:?}", opcode);
                    let mut outputter = BitcoinInstructionProcessor {
                        //str: format!("# {:?}", opcode),
                        str: format!("# pc: {:x}", pcc),
                        insn_pc: pcc,
                        start_addr: GUEST_MIN_MEM as u32,
                        mem_len: mem_len as u32,
                        //pre_tree: Some(&mut script_tree),
                        //end_root: Some(root),
                    };
                    let desc = process_instruction(&mut outputter, current_insn.1).unwrap();
                    //let dummy_num: u32 = 3;
                    //    dummy_num: &dummy_num,
                    //println!("{}", desc);

                    let ins_str = format!("{:04x}", ins);

                    let mut script_file =
                        File::create(format!("trace/ins_{}_script.txt", ins_str)).unwrap();
                    write!(script_file, "{}", desc.script).unwrap();

                    let (witness, mut w_tags) =
                        desc.witness_gen.generate_witness(&mut script_tree, root);

                    w_tags.extend(desc.tags.into_iter());

                    let mut witness_file =
                        File::create(format!("trace/ins_{}_witness.txt", ins_str)).unwrap();
                    write!(witness_file, "{}", witness.join("\n")).unwrap();

                    let tags_file =
                        File::create(format!("trace/ins_{}_tags.json", ins_str)).unwrap();

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

                    let mut commitfile =
                        File::create(format!("trace/ins_{}_commitment.txt", ins_str)).unwrap();

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

                //let opcode = OpCode::decode(*insn, *pc).unwrap();
                //println!("next opcode {:?}", opcode);
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
            TraceEvent::MemorySet { addr, value } => {
                set_addr(&mut mem_tree, (*addr) as usize, *value);
            }
        }
    }

    let root = mem_tree.commit();
    println!("final root[{}]={}", ins, hex::encode(root));
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
    println!("register {} (SP={}) set to {:x}", reg, reg == REG_SP, val);
    let sys_addr = SYSTEM.start();
    let addr = sys_addr + (reg * WORD_SIZE);

    set_addr(fast_tree, addr, val);
}

fn set_addr(fast_tree: &mut Tree, addr: usize, val: u32) {
    let b = val.to_le_bytes();
    set_commit(fast_tree, addr, b);
}

fn load_addr(img: &MemoryImage, addr: usize) -> [u8; 4] {
    let mut b: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    img.load_region_in_page(addr as u32, &mut b[..]);

    b
}

fn to_script_num(b: [u8; 4]) -> Vec<u8> {
    let w = u32::from_le_bytes(b);

    let mut script_num: [u8; 8] = [0; 8];
    let n = write_scriptint(&mut script_num, w as i64);

    script_num[..n].to_vec()
}
fn set_commit(fast_tree: &mut Tree, addr: usize, b: [u8; 4]) {
    let script_num = to_script_num(b.clone());
    let index = addr_to_index(addr);
    println!(
        "converting addr {}={} for commit->{}",
        addr,
        hex::encode(b),
        hex::encode(script_num.clone())
    );

    fast_tree.set_leaf(index, script_num);
}

fn build_merkle(fast_tree: &mut Tree, img: &MemoryImage) -> [u8; 32] {
    let temp_image = img;
    let pc = img.pc;
    //    println!("temp image pc {}", temp_image.pc);
    //    println!("pages {}", temp_image.pages.len());
    //    println!("max memory 0x{:08x}",GUEST_MAX_MEM);

    // TODO: use full memory for real applications
    let end_mem = 0x0002_0000;
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

fn addr_to_index(addr: usize) -> usize {
    (addr - GUEST_MIN_MEM) / WORD_SIZE
}

pub fn search<'a>(query: &str, contents: &'a str) -> Vec<&'a str> {
    let mut results = Vec::new();

    for line in contents.lines() {
        if line.contains(query) {
            results.push(line);
        }
    }

    results
}
