#[cfg(kani)]
mod verification {
    use super::*;
    use percolator_prog::ix::Instruction;

    #[kani::proof]
    fn verify_instruction_decoding() {
        let input: u8 = kani::any();
        let data = [input];
        let _ = Instruction::decode(&data);
    }
}
