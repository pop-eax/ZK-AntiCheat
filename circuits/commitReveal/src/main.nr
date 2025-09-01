use std::hash::blake3;

fn main(hash: pub [u8;32], indices: pub [u32;3], values: pub [u8;3], segment: [u8; 2048]) {
    let given_hash = blake3(segment);
    assert(hash == given_hash, "The hashes don't match");
    for i in 0 .. indices.len() {
        assert(segment[indices[i]] == values[i], "Values don't match");
    }
}
