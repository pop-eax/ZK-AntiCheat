fn main(whitelisted: pub [Field; 32], hash: pub Field, currentState: [Field; 32]) {
    for i in 0 .. whitelisted.len() {
        if whitelisted[i] != 0 {
            assert(whitelisted[i] == currentState[i], "illegal state found");
        }
    }
}
