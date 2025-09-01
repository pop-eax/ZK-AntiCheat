mod memory;
use flate2::write::GzEncoder;
use hex;
use memory::{MemoryDumper, RegionFilter, find_process_by_name};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::{fs, thread, time::Duration};


const PATH_LENGTH: usize = 64;
const CHUNK_SIZE: usize = 2048;
const MEMORY_DUMP_INTERVAL_SECONDS: u64 = 5;

#[derive(Serialize, Deserialize)]
struct RequestPayload {
    path: Vec<Vec<String>>,
    root: String,
}

#[derive(Serialize, Deserialize)]
struct RevealPayload<'a> {
    hash: String,
    segment: &'a [u8],
    indices: [u8; 3],
    values: [u8; 3]
}

/// Generate Merkle tree leaves from process memory
///
/// # Arguments
/// * `pid` - Process ID to dump memory from
///
/// # Returns
/// * `Vec<[u8; 32]>` - Vector of 32-byte leaf hashes
fn generate_leaves_from_process(pid: u32) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    let mut dumper = MemoryDumper::new(pid)?;
    let mem = dumper.dump_regions(RegionFilter::Interesting);
    generate_leaves_from_memory(&mem)
}

/// Generate Merkle tree leaves from memory dump file
///
/// # Arguments
/// * `mem_path` - Path to memory dump file
///
/// # Returns
/// * `Vec<[u8; 32]>` - Vector of 32-byte leaf hashes
fn generate_leaves_from_file(
    mem_path: &str,
) -> Result<(Vec<[u8; 32]>, [u8; CHUNK_SIZE]), Box<dyn std::error::Error>> {
    let mem = fs::read(mem_path)?;

    if mem.len() < CHUNK_SIZE {
        return Err(format!(
            "File too small: {} bytes, need at least {}",
            mem.len(),
            CHUNK_SIZE
        )
        .into());
    }

    // Print Tetris score values from memory addresses 0x53, 0x54, 0x55

    println!("Tetris Score Values:");
    println!("0x53: {}", mem[0x53]);
    println!("0x54: {}", mem[0x54]);
    println!("0x55: {}", mem[0x55]);

    let reveal_segment: [u8; CHUNK_SIZE] = mem[0..CHUNK_SIZE].try_into()?;

    Ok((generate_leaves_from_memory(&mem).unwrap(), reveal_segment))
}

/// Generate Merkle tree leaves from raw memory data
///
/// # Arguments
/// * `mem` - Raw memory bytes
///
/// # Returns
/// * `Vec<[u8; 32]>` - Vector of 32-byte leaf hashes
fn generate_leaves_from_memory(mem: &[u8]) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    let mut leaves = Vec::new();
    // Process memory in chunks and hash each chunk
    for chunk in mem.chunks(CHUNK_SIZE) {
        let blake_hash = blake3::hash(chunk).as_bytes().clone();
        leaves.push(blake_hash);
    }

    // Pad to power of 2 for complete binary tree
    while !leaves.len().is_power_of_two() {
        leaves.push([0; 32]);
    }

    Ok(leaves)
}

/// Profile memory changes over time to identify static vs dynamic regions
///
/// # Arguments
/// * `process_name` - Name of the process to profile
fn profile_memory_changes(process_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pid = find_process_by_name(process_name)?;
    let initial_leaves = generate_leaves_from_process(pid)?;
    let mut is_static = vec![true; initial_leaves.len()];

    // Monitor memory changes for 60 seconds
    for _ in 0..60 {
        let current_leaves = generate_leaves_from_process(pid)?;

        // Mark regions that have changed as dynamic
        for i in 0..initial_leaves.len() {
            if initial_leaves[i] != current_leaves[i] {
                is_static[i] = false;
            }
        }

        thread::sleep(Duration::from_millis(1000));
    }

    let static_count = is_static.iter().filter(|&&x| x).count();
    println!(
        "Static memory regions: {} out of {}",
        static_count,
        is_static.len()
    );

    // Create compressed static memory dump
    let static_memory: Vec<u8> = initial_leaves
        .iter()
        .zip(is_static.iter())
        .flat_map(|(&byte, &is_static)| {
            if is_static {
                byte.to_vec()
            } else {
                vec![0; 32]
            }
        })
        .collect();

    let filename = format!("static_memory_{}.bin", pid);
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&static_memory)?;
    let compressed = encoder.finish()?;
    fs::write(&filename, &compressed)?;

    println!(
        "Static memory dump saved to {} ({} bytes)",
        filename,
        static_memory.len()
    );
    Ok(())
}

/// Profile NES emulator memory changes from dump files
fn profile_nes_memory() -> Result<(), Box<dyn std::error::Error>> {
    let (initial_leaves, _) = generate_leaves_from_file("/tmp/nes_memory_dump_0.bin")?;
    println!("Initial memory dump length: {}", initial_leaves.len());

    let mut is_static = vec![true; initial_leaves.len()];

    // Compare with subsequent dumps
    for dump_index in 1..10 {
        let dump_path = format!("/tmp/nes_memory_dump_{}.bin", dump_index);
        let (current_leaves, _) = generate_leaves_from_file(&dump_path)?;

        for i in 0..initial_leaves.len() {
            if initial_leaves[i] != current_leaves[i] {
                is_static[i] = false;
            }
        }
    }

    let static_count = is_static.iter().filter(|&&x| x).count();
    println!(
        "Static memory regions: {} out of {}",
        static_count,
        is_static.len()
    );

    // Create compressed static memory dump
    let static_memory: Vec<u8> = initial_leaves
        .iter()
        .zip(is_static.iter())
        .flat_map(|(&byte, &is_static)| {
            if is_static {
                byte.to_vec()
            } else {
                vec![0; 32]
            }
        })
        .collect();

    let filename = "static_memory_nes.bin";
    let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&static_memory)?;
    let compressed = encoder.finish()?;
    fs::write(filename, &compressed)?;

    println!(
        "Static memory dump saved to {} ({} bytes)",
        filename,
        static_memory.len()
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Uncomment to run profiling functions
    // profile_memory_changes("game")?;
    // profile_nes_memory()?;
    // return Ok(());

    let client = reqwest::Client::new();
    let mut running = true;

    while running {
        // Generate leaves from NES memory dump
        let (tree, reveal_segment) = generate_leaves_from_file("/tmp/nes_memory_dump_proof.bin")?;
        let serialized_tree = tree
            .iter()
            .map(|leaf: &[u8; 32]| format!("0x{}", hex::encode(leaf)))
            .collect::<Vec<String>>();

        println!("Root: {}", hex::encode(tree[0]));
        println!("Tree length: {}", tree.len());

        let payload = RequestPayload {
            path: serialized_tree
                .chunks(PATH_LENGTH)
                .map(|chunk| chunk.to_vec())
                .collect(),
            root: "0x0000".to_string(),
        };

        let reveal_payload = RevealPayload {
            hash: hex::encode(blake3::hash(reveal_segment.as_ref()).as_bytes().clone()),
            values: [reveal_segment[0x53], reveal_segment[0x54], reveal_segment[0x55]],
            indices: [0x53, 0x54, 0x55],
            segment: &reveal_segment.as_ref()
        };

        let reveal_response = client
        .post("http://127.0.0.1:9000/reveal")
        .header("Content-Type", "application/json")
        .json(&reveal_payload)
        .send()
        .await;

        // Send proof request to server
        let response = client
            .post("http://127.0.0.1:9000/")
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await;

        if response.is_err() || reveal_response.is_err() {
            println!("Failed to send request, stopping client");
            running = false;
        }

        thread::sleep(Duration::from_secs(MEMORY_DUMP_INTERVAL_SECONDS));
    }

    Ok(())
}
