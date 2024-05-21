#![feature(bigint_helper_methods)]

use bitcoin::script::write_scriptint;
use clap::Parser;
use fast_merkle::Tree;
use risc0_binfmt::{MemoryImage, Program};
use risc0_zkvm::host::server::opcode::{MajorType, OpCode};
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, TraceEvent};
use risc0_zkvm_platform::memory::{GUEST_MAX_MEM, GUEST_MIN_MEM, SYSTEM};
use risc0_zkvm_platform::syscall::reg_abi::REG_MAX;
use risc0_zkvm_platform::{PAGE_SIZE, WORD_SIZE};
use rrs_lib::process_instruction;
use sha2::{Digest, Sha256};

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Error, Read, Write};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::{env, fs, io};

mod processor;

use processor::BitcoinInstructionProcessor;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Program binary
    #[arg(short, long)]
    binary: String,

    /// Input to the program
    #[arg(short, long)]
    input: String,

    /// Expected output of the program
    #[arg(short, long)]
    output: String,

    /// Skip checking whether final output matches expected output.
    #[arg(short, long)]
    skip_check_output: bool,

    /// Write scripts to file.
    #[arg(short, long)]
    write: bool,
}

enum Event {
    MemoryEvent { e: TraceEvent },

    ReadEvent { cnt: usize },
}

struct CountReader {
    data: Vec<u32>,
    cnt: usize,
    trace: Arc<Mutex<Vec<Event>>>,
}

impl Read for CountReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.cnt >= self.data.len() {
            //return Err(io::ErrorKind::UnexpectedEof);
            return Err(Error::from(io::ErrorKind::UnexpectedEof));
        }

        let w = self.data[self.cnt];
        self.cnt += 1;
        println!("rad cnt {}", self.cnt);

        self.trace
            .lock()
            .unwrap()
            .push(Event::ReadEvent { cnt: self.cnt });

        let le = w.to_le_bytes();
        buf[..4].copy_from_slice(&le);

        Ok(4)
    }
}

fn main() {
    let cargs = Args::parse();
    let file_path = cargs.binary;
    println!("parsing file {}", file_path);

    let input_bytes = hex::decode(cargs.input.clone()).unwrap();
    //let w = u32::from_le_bytes(x.clone().try_into().unwrap());
    println!(
        "using x={} as program input",
        hex::encode(input_bytes.clone())
    );

    let exp_output = cargs.output;
    println!("using y={} as expected program output", exp_output);
    let y = hex::decode(exp_output.clone()).unwrap();

    let mtxs = Arc::new(Mutex::new(Vec::new()));
    let trace: Arc<Mutex<Vec<Event>>> = mtxs.clone();

    if input_bytes.len() % 4 != 0 {
        panic!("input must be divisible by 4");
    }
    if y.len() % 4 != 0 {
        panic!("output must be divisible by 4");
    }

    let x = u32::from_le_bytes((input_bytes[..4].try_into().unwrap()));
    let exp_output = u32::from_le_bytes((y[..4].try_into().unwrap()));

    fs::create_dir_all("trace").unwrap(); // make sure the 'trace' directory exists
    fs::create_dir_all("trace/script").unwrap(); // make sure the 'script' directory exists
    fs::create_dir_all("trace/witness").unwrap(); // make sure the 'witness' directory exists
    fs::create_dir_all("trace/tags").unwrap(); // make sure the 'tags' directory exists
    fs::create_dir_all("trace/commitment").unwrap(); // make sure the 'commitments' directory exists

    let mut vec32 = Vec::new();
    for i in (0..input_bytes.len()).step_by(4) {
        let b: [u8; 4] = input_bytes[i..i + 4].try_into().unwrap();
        let w = u32::from_le_bytes(b);
        vec32.push(w);
    }

    let creader = CountReader {
        data: vec32,
        cnt: 0,
        trace: trace.clone(),
    };

    let mut output = Vec::new();
    let env = ExecutorEnv::builder()
        .trace_callback(|e| {
            trace.lock().unwrap().push(Event::MemoryEvent { e });
            Ok(())
        })
        //.write(&w)
        //.unwrap()
        .stdin(creader)
        .stdout(&mut output)
        .build()
        .unwrap();
    let elf_contents = fs::read(file_path).unwrap();
    let mem_len = guest_mem_len();

    let zero_val = [0u8; 32];
    let mut mem_tree = Tree::new_with_default(mem_len, zero_val.into()).unwrap();

    // Recreated executor starting memory.
    let program = Program::load_elf(&elf_contents, GUEST_MAX_MEM as u32).unwrap();

    let mut first = true;
    let mut addr: u32 = 0;
    let mut scripts = HashMap::new();
    let mut roots: Vec<[u8; 32]> = vec![];

    let ib: &[u8] = &input_bytes;

    let start = Instant::now();

    {
        let mut exec = ExecutorImpl::from_elf(env, &elf_contents).unwrap();
        let img = exec.memory().unwrap();

        println!("got starting memory: 0x{:x}", img.pc);

        let start_root = build_merkle(&mut mem_tree, &img);
        let duration = start.elapsed();
        println!(
            "start root built from img={} in {:?}",
            hex::encode(start_root),
            duration,
        );
        roots.push(start_root);

        println!("creating program scripts");
        let program_end = program.program_range.end;
        for _addr in program.program_range.step_by(WORD_SIZE) {
            addr = _addr;
            if first {
                println!("start 0x{:x}", addr);
            }
            first = false;

            if addr % (1024*10) == 0 {
                println!("script {addr}/{program_end}");
            }

            let mut bytes = [0_u8; WORD_SIZE];
            img.load_region_in_page(addr, &mut bytes);

            let insn = u32::from_le_bytes(bytes);

            let opcode = match OpCode::decode(insn, addr) {
                Ok(t) => t,
                Err(e) => continue,
            };

            //println!("0x{:x}: {:?}", addr, opcode);

            // TODO: not yet implemented, we skip them until we see them encountered in a real
            // execution.
            if opcode.mnemonic == "SLTI" {
                continue;
            }
            if opcode.mnemonic == "LB" {
                continue;
            }
            if opcode.mnemonic == "SLT" {
                continue;
            }

            if opcode.mnemonic == "SRA" {
                continue;
            }

            let mut outputter = BitcoinInstructionProcessor {
                str: format!("# pc: {:x}\t{:?}", addr, opcode),
                //str: format!("# pc: {:x}", addr),
                insn_pc: addr,
                start_addr: GUEST_MIN_MEM as u32,
                mem_len: mem_len as u32,
            };

            //println!("inserting desc at 0x{:x}: {:?}", addr, opcode);
            let pc_str = format!("{:05x}", addr);
            let v = if opcode.major == MajorType::ECall {
                // Since we don't know which ecall is being requested before having access to memory, we generate all, and have the prover decide which one to run.
                let desc_in = outputter.ecall_read(x);

                if cargs.write {
                    let mut script_file =
                        File::create(format!("trace/script/pc_{}_ecall_input_script.txt", pc_str))
                            .unwrap();
                    write!(script_file, "{}", desc_in.script).unwrap();
                }

                let desc_out = outputter.ecall_write(exp_output);
                if cargs.write {
                    let mut script_file = File::create(format!(
                        "trace/script/pc_{}_ecall_output_script.txt",
                        pc_str
                    ))
                    .unwrap();
                    write!(script_file, "{}", desc_out.script).unwrap();
                }

                vec![desc_in, desc_out]
            } else {
                let desc = process_instruction(&mut outputter, insn).unwrap();
                if cargs.write {
                    let mut script_file =
                        File::create(format!("trace/script/pc_{}_script.txt", pc_str)).unwrap();
                    write!(script_file, "{}", desc.script).unwrap();
                }

                vec![desc]
            };

            scripts.insert(addr, v);
        }

        //println!("num scipts: {}", script_map.len());

        println!("end 0x{:x}", addr);

        let _session = exec.run().unwrap();

        //let stdout: u32 = from_slice(&mut output).unwrap();

        //println!("trace: {:?}", trace.lock().unwrap().clone());
        let tn = trace.lock().unwrap().len();
        println!("trace length: {} ({:x})", tn, tn);
    }
    println!("output: {:?}", output);
    if !cargs.skip_check_output {
        let output_bytes: [u8; 4] = output.try_into().unwrap();
        let actual_output = u32::from_le_bytes(output_bytes);
        if actual_output != exp_output {
            panic!(
                "actual {} and expected {} output differ",
                actual_output, exp_output
            );
        }
    }

    let mut input_len = input_bytes.len() + 1;
    let mut output_len = y.len() + 1;
    // Merkle tree implementation requires power of two.
    while !input_len.is_power_of_two() {
        input_len += 1;
    }
    while !output_len.is_power_of_two() {
        output_len += 1;
    }

    let mut input_tree = Tree::new_with_default(input_len, zero_val.into()).unwrap();
    let mut output_tree = Tree::new_with_default(output_len, zero_val.into()).unwrap();
    let start_index = processor::to_mem_repr(1);

    for i in (0..input_bytes.len()).step_by(WORD_SIZE) {
        let w: [u8; 4] = input_bytes[i..i + WORD_SIZE].try_into().unwrap();
        let mem = to_mem_repr(w);
        input_tree.set_leaf(1 + i / WORD_SIZE, mem);
    }

    // Start index is 1.
    input_tree.set_leaf(0, start_index.clone());
    input_tree.commit();

    for i in (0..y.len()).step_by(WORD_SIZE) {
        let w: [u8; 4] = y[i..i + WORD_SIZE].try_into().unwrap();
        let b = u32::from_le_bytes(w);
        let mem = to_mem_repr(w);
        let index = 1 + i / WORD_SIZE;
        output_tree.set_leaf(index, mem);
    }

    // Start index is 1.
    output_tree.set_leaf(0, start_index);
    output_tree.commit();

    let mut input_hasher = Sha256::new();
    let input_mem_repr = processor::to_mem_repr(x);
    input_hasher.update(input_mem_repr.clone());
    let input_hash = input_hasher.finalize();

    let mut output_hasher = Sha256::new();
    let output_mem_repr = processor::to_mem_repr(exp_output);
    output_hasher.update(output_mem_repr.clone());
    let output_hash = output_hasher.finalize();

    //let zero_val = to_script_num(0u32.to_le_bytes());
    //let zero_val = 0u32.to_le_bytes();

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
    // TODO: check number of insstart to determine progress instead.
    let mut tot_ins = 0;
    let mut tot_reads = 0;
    for (_i, ev) in trace.lock().unwrap().iter().enumerate() {
        match ev {
            Event::MemoryEvent { e } => match e {
                TraceEvent::InstructionStart { cycle, pc, insn } => {
                    tot_ins += 1;
                }
                _ => {}
            },
            Event::ReadEvent { cnt } => {
                tot_reads += 1;
            }
        }
    }

    println!("tot_ins={} tot_reads={}", tot_ins, tot_reads);

    'outer: for (_i, ev) in trace.lock().unwrap().iter().enumerate() {
        //println!("iteration[{}]={:?}", i, e);

        let e = match ev {
            Event::ReadEvent { cnt } => {
                continue 'outer;
            }
            Event::MemoryEvent { e } => e,
        };

        match e {
            // A new instruction is starting.
            TraceEvent::InstructionStart { cycle, pc, insn } => {
                // Set the new PC and get a state commitment. This will be the state of computation
                // before this instruction is executed, hence the post-state of the previous instruction.
                set_register(&mut mem_tree, REG_MAX, *pc);
                let root = mem_tree.commit();
                roots.push(root);

                //println!("new root[{} cycle={}]={}", ins, *cycle, hex::encode(root));

                let pcc = current_insn.0;
                if pcc != 0 {
                    let v_desc = match scripts.get(&pcc) {
                        Some(d) => d,
                        None => {
                            //println!("next opcode {:x}: {:?}", *pc, opcode);
                            let opcode = OpCode::decode(current_insn.1, pcc).unwrap();
                            panic!("not found: {:?} ins={:x} pc={:x}", opcode, ins, pcc);
                        }
                    };

                    for (i, desc) in v_desc.iter().enumerate() {
                        let mut ins_str = format!("{:04x}", ins);
                        if v_desc.len() > 0 {
                            ins_str += format!("_{i}").as_str();
                        }

                        let (mut witness, mut w_tags) = desc.witness_gen.generate_witness(
                            &mut script_tree,
                            &mut input_tree,
                            &mut output_tree,
                            root,
                        );

                        // TODO: just temp hack to indicate wrong ecall type
                        if w_tags.len() == 0 {
                            continue;
                        }

                        // We always add input and output to the witness.
                        witness.push(hex::encode(input_mem_repr.clone()));
                        witness.push(hex::encode(output_mem_repr.clone()));

                        w_tags.extend(desc.tags.clone().into_iter());
                        w_tags.insert(hex::encode(input_hash), "input_hash".to_string());
                        w_tags.insert(
                            hex::encode(input_mem_repr.clone()),
                            "input_bytes".to_string(),
                        );

                        w_tags.insert(hex::encode(output_hash), "output_hash".to_string());

                        w_tags.insert(
                            hex::encode(output_mem_repr.clone()),
                            "output_bytes".to_string(),
                        );

                        //    if pcc == 0x143bb8 {
                        let pc_str = format!("{:05x}", pcc);
                        if cargs.write {
                            let witness_file_name =
                                format!("trace/witness/ins_{}_pc_{}_witness.txt", ins_str, pc_str);
                            let mut witness_file = File::create(witness_file_name.clone()).unwrap();
                            write!(witness_file, "{}", witness.join("\n")).unwrap();
                        }

                        let mut hasher = Sha256::new();
                        let start_root = roots[roots.len() - 2];
                        let end_root = roots[roots.len() - 1];
                        hasher.update(input_hash);
                        hasher.update(output_hash);
                        hasher.update(start_root);
                        hasher.update(end_root);
                        let hash = hasher.finalize();
                        let hash_array: [u8; 32] = hash.into();
                        //println!(
                        //    "h({}|{}) = {}",
                        //    hex::encode(start_root),
                        //    hex::encode(end_root),
                        //    hex::encode(hash_array)
                        //);

                        w_tags.insert(hex::encode(hash_array), "commitment".to_string());

                        if cargs.write {
                            let tags_file = File::create(format!(
                                "trace/tags/ins_{}_pc_{}_tags.json",
                                ins_str, pc_str
                            ))
                            .unwrap();

                            let writer = BufWriter::new(tags_file);
                            serde_json::to_writer_pretty(writer, &w_tags).unwrap();

                            let mut commitfile = File::create(format!(
                                "trace/commitment/ins_{}_pc_{}_commitment.txt",
                                ins_str, pc_str
                            ))
                            .unwrap();
                            write!(commitfile, "{}", hex::encode(hash_array)).unwrap();
                        }

                        // NEXT: add script/witness validation that will run each step.
                        // to avoid having to implement this (and OP_CCV) in rust, maybe write a Go program that can be run on the created scripts.

                        // Start and  end root alwyas first in the witness.
                        //let witness = vec![];

                        // TODO: must really write also after loop ends
                        // BUT: we should rather create witness only on demand. Start with just re-creating trace and generate witness when one wants to publish state proof.
                    }
                }

                let r1 = hex::encode(script_tree.root());
                let r2 = hex::encode(mem_tree.root());
                if r1 != r2 {
                    panic!("root mismatch: {} vs {}", r1, r2);
                }

                //let opcode = OpCode::decode(*insn, *pc).unwrap();
                //println!("next opcode {:x}: {:?}", *pc, opcode);
                //current_opcode = Some(opcode);
                ins += 1;

                // Now that we've handled the previous instruction, set things up for processing
                // the next.
                current_insn = (*pc, *insn);
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
    //println!("register {} (SP={}) set to {:08x}", reg, reg == REG_SP, val);
    let sys_addr = SYSTEM.start();
    let addr = sys_addr + (reg * WORD_SIZE);

    set_addr(fast_tree, addr, val.to_le_bytes().into());
}

fn addr_word(fast_tree: &mut Tree, addr: usize, val: Vec<u8>) -> [u8; 4] {
    let (index, offset) = addr_to_index(addr);
    let n = val.len();
    if !(n == 1 || n == WORD_SIZE / 2 || n == WORD_SIZE) {
        panic!("invalid word length {}", n);
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
    //println!(
    //    "memory addr={:x}  set to {:08x} (le={}) mem={}",
    //    addr,
    //    val,
    //    hex::encode(b),
    //    hex::encode(mem),
    //);
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
        if addr % (2048 * 4096) == 0 {
            println!(
                "building merkle commitment for addr {}/{}",
                addr, GUEST_MAX_MEM
            );
        }

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
