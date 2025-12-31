#[cfg(test)]
mod tests {
    use percolator_prog::ix::Instruction;
    use solana_program::pubkey::Pubkey;

    #[test]
    fn test_instruction_decode() {
        // Placeholder test
        let data = [1]; // InitUser tag
        let ix = Instruction::decode(&data).unwrap();
        match ix {
            Instruction::InitUser => assert!(true),
            _ => assert!(false),
        }
    }
}
