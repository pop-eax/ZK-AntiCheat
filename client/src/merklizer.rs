use rs_merkle::{Hasher, MerkleTree};


// Create a wrapper struct for blake3
#[derive(Clone)]
pub struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    type Hash = [u8; 32]; // blake3 produces 32-byte hashes
    
    fn hash(data: &[u8]) -> Self::Hash {
        *blake3::hash(data).as_bytes()
    }
}

fn generate_tree(leaves: &Vec<[u8; 32]>) -> String {
    // leaves = leaves.into_iter().take(PATH_LENGTH).collect();
    let merkle_tree = MerkleTree::<Blake3Hasher>::from_leaves(&leaves);
    // Get the root hash
    let root = merkle_tree.root().expect("couldn't get the merkle root");

    hex::encode(root)
}
