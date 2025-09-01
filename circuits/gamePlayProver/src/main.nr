use poseidon::poseidon2::Poseidon2::hash;

global HONK_VK_SIZE: u32 = 128;
global HONK_PROOF_SIZE: u32 = 456;
global HONK_IDENTIFIER: u32 = 1;

fn main(
    verification_key: pub [Field; HONK_VK_SIZE],
    proof1: pub [Field; HONK_PROOF_SIZE],
    public_inputs1: pub [Field; 2],
    proof2: pub [Field; HONK_PROOF_SIZE],
    public_inputs2: pub [Field; 2],
    accumulator: pub Field,
    // new_root: pub Field,
) {
    let mut r: Field = accumulator;
    std::verify_proof_with_type(
        verification_key,
        proof1,
        public_inputs1,
        0x0,
        HONK_IDENTIFIER,
    );
    std::verify_proof_with_type(
        verification_key,
        proof2,
        public_inputs2,
        0x0,
        HONK_IDENTIFIER,
    );
    r = hash([r, public_inputs1[0]], 2);

    // assert(r == new_root);
}
