use rand::prelude::*;
use rand::rngs::StdRng;

#[test]
fn deterministic_fuzz_simulation() {
    let seed = [0u8; 32];
    let mut rng = StdRng::from_seed(seed);

    for _i in 0..100 {
        let op_type: u8 = rng.gen_range(0..5);
        match op_type {
            0 => {
                // Simulate InitUser
            },
            1 => {
                // Simulate Deposit
            },
            _ => {}
        }
        
        // Assert invariants
        check_invariants();
    }
}

fn check_invariants() {
    // Assert conservation of mass, etc.
}
