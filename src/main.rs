use bitcoin::script::write_scriptint;
use fast_merkle::Tree;
//use risc0_zkvm::host::server::opcode::{MajorType, OpCode};
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, MemoryImage, Program, TraceEvent};
use risc0_zkvm_platform::memory::{GUEST_MAX_MEM, GUEST_MIN_MEM, SYSTEM};
use risc0_zkvm_platform::syscall::reg_abi::REG_MAX;
use risc0_zkvm_platform::syscall::reg_abi::{REG_A5, REG_GP, REG_RA, REG_S0, REG_SP};
use risc0_zkvm_platform::{PAGE_SIZE, WORD_SIZE};
use rrs_lib::{instruction_string_outputter::InstructionStringOutputter, process_instruction};

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

    let mut mtxs = Arc::new((Mutex::new(Vec::new())));
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

    let _session = exec.run().unwrap();

    println!("trace: {:?}", trace.lock().unwrap().clone());

    let mem_len = guest_mem_len();
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

    let mut ins = 0;
    for (i, e) in trace.lock().unwrap().iter().enumerate() {
        //println!("iteration[{}]={:?}", i, e);
        match e {
            TraceEvent::InstructionStart { cycle, pc, insn } => {
                set_register(&mut mem_tree, REG_MAX, *pc);
                let root = mem_tree.commit();
                println!("new root[{}]={}", ins, hex::encode(root));
                ins += 1;

                //let opcode = OpCode::decode(*insn, *pc).unwrap();
                //println!("next opcode {:?}", opcode);
                if *pc == 0x10098 {
                    let mut outputter = BitcoinInstructionProcessor {
                        insn_pc: *pc,
                        start_addr: GUEST_MIN_MEM as u32,
                        mem_len: mem_len as u32,
                    };
                    let desc = process_instruction(&mut outputter, *insn).unwrap();
                    println!("{}", desc);
                }
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
    let mut mem_len: usize = 0; // Number of words (4 bytes) in the guest memory.

    mem_len = (GUEST_MAX_MEM - GUEST_MIN_MEM) / WORD_SIZE;

    println!("guest memory length {}", mem_len);

    // In addition to committing to the memory we want to commit to the registers. These are
    // already located in the host memory starting at SYSTEM.start.
    let sys_addr = SYSTEM.start() as u32;
    for reg in 0..REG_MAX {
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
    let sys_addr = SYSTEM.start();
    let addr = sys_addr + (reg * WORD_SIZE);

    set_addr(fast_tree, addr, val);
}

fn set_addr(fast_tree: &mut Tree, addr: usize, val: u32) {
    let index = addr_to_index(addr);
    let leaf = fast_tree.get_leaf(index);
    //println!("leaf {} before setting={}", index, hex::encode(leaf));

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
    let script_num = to_script_num(b);
    let index = addr_to_index(addr);

    fast_tree.set_leaf(index, script_num);
}

fn build_merkle(fast_tree: &mut Tree, img: &MemoryImage) -> [u8; 32] {
    let temp_image = img;
    let pc = img.pc;
    //    println!("temp image pc {}", temp_image.pc);
    //    println!("pages {}", temp_image.pages.len());
    //    println!("max memory 0x{:08x}",GUEST_MAX_MEM);

    let start1 = Instant::now();

    // TODO: use full memory for real applications
    //let end_mem = GUEST_MAX_MEM;
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
    let pc_index = addr_to_index(pc_addr);
    //println!("Executor: pc addr {}-> index {}", pc_addr, pc_index);
    set_commit(fast_tree, pc_addr, pc.to_le_bytes());

    let duration1 = start1.elapsed();
    //println!("iterating mempry took:  {:?}", duration1);

    let mem_len = guest_mem_len();

    let start3 = Instant::now();
    let root = fast_tree.commit();
    let duration3 = start3.elapsed();
    //println!("committing tree took:  {:?}", duration3);

    return root;

    if pc != 0x10098 && pc != (0x10098 + 4) {
        return root;
    }

    println!("creating witnesses for pc={:x}", pc);
    //let pc_addr = BitcoinInstructionProcessor::reg_addr(REG_MAX);
    let pc_num = to_script_num(pc.to_le_bytes());
    println!("pc: {}", hex::encode(pc_num.clone()));
    let pc_proof = fast_tree.proof(pc_index, pc_num).unwrap();
    print_proof(pc_proof);

    let x2_addr = sys_addr + (REG_SP * WORD_SIZE);
    let x2_mem = load_addr(temp_image, x2_addr);
    let x2_num = to_script_num(x2_mem);

    println!("x2: {}", hex::encode(x2_num.clone()));
    let x2_index = addr_to_index(x2_addr);
    let x2_proof = fast_tree.proof(x2_index, x2_num).unwrap();
    print_proof(x2_proof);

    let x8_addr = sys_addr + (REG_S0 * WORD_SIZE);
    let x8_mem = load_addr(temp_image, x8_addr);
    let x8_num = to_script_num(x8_mem);

    println!("x8: {}", hex::encode(x8_num.clone()));
    let x8_index = addr_to_index(x8_addr);
    let x8_proof = fast_tree.proof(x8_index, x8_num).unwrap();
    print_proof(x8_proof);

    root
}

fn addr_to_index(addr: usize) -> usize {
    (addr - GUEST_MIN_MEM) / WORD_SIZE
}

fn print_proof(proof: Vec<[u8; 32]>) {
    let n = proof.len();
    //        for (i, p) in proof.iter().enumerate() {
    //            println!("level {}: {}",n-i, hex::encode(p));
    //        }

    let mut witness = "".to_string();
    for p in proof.iter().rev() {
        let add = format!(" {}", hex::encode(p));
        witness.push_str(add.as_str());
    }

    println!("witness: {}", witness);
}

fn run(img: &MemoryImage) {
    let mut i = 0;
    loop {
        println!("loop iteration {}", i);
        i += 1;
    }
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
