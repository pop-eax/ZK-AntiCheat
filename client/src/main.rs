mod memory;


use memory::{MemoryDumper, RegionFilter, find_process_by_name,};
use blake3::{hash};
use std::fs;

fn main() {
    let pid = find_process_by_name("game").unwrap();
    println!("Dump memory of process {}", pid);
    let mut dumper = MemoryDumper::new(pid).unwrap();
    let mem = dumper.dump_regions(RegionFilter::Interesting);
    let mut i = 0;
    let mut merkle_tree: Vec<String> = Vec::new();
    let chunk_size = 2048;
    while i < mem.len()-chunk_size {
        let block = &mem[i .. i+chunk_size];
        let h = hash(block).to_string();
        merkle_tree.push(h);
        
        i += chunk_size;
    }
    let _ = fs::write("tree.bin",merkle_tree.join(",")).unwrap();
    // fs::write("dump.bin", mem);
}