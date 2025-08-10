use poseidon::poseidon2::Poseidon2::hash;

fn main(root: pub Field, paths: [Field; 32], bad_hashes: pub [Field; 1]) {
    for p in paths {
        for k in bad_hashes {
            assert(p != k, "evil hash detected");
        }
    }

    let mut curr_path = paths;

    let depth = 6;
    let bounds= [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
    
    for j in 1 .. depth+1  {
        let idx = depth - j;
        let bound = bounds[idx];
        let mut skip = false;
        let mut k = 0;
        for i in 0 .. bound-1 {
            if !skip {
                let interm =hash([curr_path[i], curr_path[i+1]], 2);
                // let interm : [u8; 32] = std::hash::blake3(curr_path[i].concat(curr_path[i+1]));
                curr_path[k] = interm;
                k += 1;
            }
            skip = !skip;
        }
    }
    assert(root == curr_path[0], "roots don't match");
}
