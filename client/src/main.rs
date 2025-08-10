mod memory;
use hex;
use memory::{MemoryDumper, RegionFilter, find_process_by_name};
use serde::{Deserialize, Serialize};
use serde_json::Result;
use std::{thread, time::Duration, fs};
use std::io::Write;
use flate2::write::GzEncoder;


#[derive(Serialize, Deserialize)]
struct RequestPayload {
    path: Vec<Vec<String>>,
    root: String,
}

const PATH_LENGTH: usize = 64;

//flatten out all the static leafs and compress them into one leaf. afterwards take the dynamic leafs and do the general computation on them
fn generate_leafs(pid: u32) -> Vec<[u8; 32]> {
    let mut dumper = MemoryDumper::new(pid).unwrap();
    let mem: Vec<u8> = dumper.dump_regions(RegionFilter::Interesting);
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let chunk_size = 2048;

    for chunk in mem.chunks(chunk_size) {
        let blake_hash = blake3::hash(chunk).as_bytes().clone();
        leaves.push(blake_hash);
    }

    while !leaves.len().is_power_of_two() {
        leaves.push([0;32]);
    }
    leaves
}

fn generate_leafs_nes(mem_path: String) -> Vec<[u8; 32]> {
    let mem: Vec<u8> = fs::read(mem_path).unwrap();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let chunk_size = 2048;
    println!("here you go {} {} {} ", mem[0x53].clone(), mem[0x54].clone(), mem[0x55].clone());

    for chunk in mem.chunks(chunk_size) {
        let blake_hash = blake3::hash(chunk).as_bytes().clone();
        leaves.push(blake_hash);
    }

    while !leaves.len().is_power_of_two() {
        leaves.push([0;32]);
    }
    leaves
}


fn profiler(process: &str) {
    let pid = find_process_by_name(process).unwrap();
    let leaves = generate_leafs(pid);
    let mut diffs = vec![true; leaves.len()]; 
    for _ in 0 .. 60 {
        let current = generate_leafs(pid);
        for i in 0 .. leaves.len() {
            if leaves[i] != current[i] {
                diffs[i] = false;
            }
        }
        thread::sleep(Duration::from_millis(1000));
    }

    let static_count = diffs.iter().filter(|&&x| x).count();
    

    println!("{} out of {}", static_count, diffs.len());
    let static_memory: Vec<u8> = leaves.iter().zip(diffs.iter())
        .map(|(&byte, &is_static)| if is_static { byte } else { [0; 32] })
        .flatten()
        .collect();
    let filename = format!("static_memory_{}.bin", pid);
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&static_memory).expect("Failed to compress");
    let compressed = encoder.finish().expect("Failed to finish compression");
    std::fs::write(&filename, &compressed).expect("Failed to save compressed file");
    println!("Static memory dump saved to {} ({} bytes)", filename, static_memory.len());
}


fn profiler_nes() {
    let leaves = generate_leafs_nes("/tmp/nes_memory_dump_0.bin".to_string());
    println!("Length of input is: {}", leaves.len());
    let mut diffs = vec![true; leaves.len()]; 
    for j in 1 .. 10 {
        let current = generate_leafs_nes(format!("/tmp/nes_memory_dump_{}.bin", j));
        for i in 0 .. leaves.len() {
            if leaves[i] != current[i] {
                diffs[i] = false;
            }
        }
        // thread::sleep(Duration::from_millis(1000));
    }

    let static_count = diffs.iter().filter(|&&x| x).count();
    

    println!("{} out of {}", static_count, diffs.len());
    let static_memory: Vec<u8> = leaves.iter().zip(diffs.iter())
        .map(|(&byte, &is_static)| if is_static { byte } else { [0; 32] })
        .flatten()
        .collect();
    let filename = format!("static_memory_nes.bin");
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&static_memory).expect("Failed to compress");
    let compressed = encoder.finish().expect("Failed to finish compression");
    std::fs::write(&filename, &compressed).expect("Failed to save compressed file");
    println!("Static memory dump saved to {} ({} bytes)", filename, static_memory.len());
}


#[tokio::main]

async fn main() -> Result<()> {
    // profiler("game");
    // profiler_nes();
    // return Ok(());
    // let pid = find_process_by_name("game").unwrap();

    
    let client = reqwest::Client::new();
    let mut running = true;
    while running {
        let tree = generate_leafs_nes("/tmp/nes_memory_dump_proof.bin".to_string());
        let serialized_tree = tree
            .iter()
            .map(|leaf: &[u8; 32]| format!("0x{}", hex::encode(leaf)))
            .collect::<Vec<String>>();
        println!("Root: {}", hex::encode(tree[0]));
        println!("Tree length: {}", tree.len());
        let payload = RequestPayload {
            path: serialized_tree.chunks(PATH_LENGTH).map(|chunk| chunk.to_vec()).collect(),
            root: "0x0000".to_string(),
        };
        // let test = serde_json::to_string(&payload);
        // let toml_string = toml::to_string(&payload).unwrap();
        // let _ = std::fs::write("test.toml", toml_string);
        let response = client
            .post("http://127.0.0.1:9000/")
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await;
        if response.is_err() {
            running = false;
        }
        thread::sleep(Duration::from_secs(40));
    }
    Ok(())
}
