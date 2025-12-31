#![no_std]
#![forbid(unsafe_code)]

//! Percolator: Single-file Solana program with embedded Risk Engine.
//!
//! # Account Order per Instruction
//!
//! 1. `InitMarket`
//!    - [0] signer, writable: Admin
//!    - [1] writable: Slab (uninitialized)
//!    - [2] readonly: Collateral Mint
//!    - [3] readonly: System Program
//!
//! 2. `InitUser`
//!    - [0] signer, writable: User
//!    - [1] writable: Slab
//!    - [2] readonly: System Program
//!
//! 3. `DepositCollateral`
//!    - [0] signer: User Authority
//!    - [1] writable: Slab
//!    - [2] writable: User Token Account
//!    - [3] writable: Vault Token Account
//!    - [4] readonly: Token Program
//!
//! 4. `WithdrawCollateral`
//!    - [0] signer: User Authority
//!    - [1] writable: Slab
//!    - [2] writable: Vault Token Account
//!    - [3] writable: User Token Account
//!    - [4] readonly: Vault Authority PDA
//!    - [5] readonly: Token Program
//!
//! ... (Other instructions follow similar strict patterns)
//!
//! # Slab Layout
//!
//! [Header (64B)] [Config (128B)] [RiskEngineState (???B)] [UserDirectory] [UserStates] [Padding]

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    program_error::ProgramError,
    msg,
};

// 1. mod constants
pub mod constants {
    pub const SLAB_LEN: usize = 10_240; // Example fixed size, must be adjusted based on constants
    pub const MAX_USERS: usize = 100;
    pub const MAX_POSITIONS_PER_USER: usize = 5;
    pub const MAX_ORACLES: usize = 5;
    
    pub const MAGIC: u64 = 0x504552434f4c4154; // "PERCOLAT"
    pub const VERSION: u32 = 1;
}

// 2. mod error
pub mod error {
    use solana_program::program_error::ProgramError;
    use num_derive::FromPrimitive;

    #[derive(Clone, Debug, Eq, PartialEq, FromPrimitive)]
    pub enum PercolatorError {
        InvalidMagic,
        InvalidVersion,
        AlreadyInitialized,
        NotInitialized,
        UserTableFull,
        UserNotFound,
        MathOverflow,
        OracleInvalid,
        InsufficientMargin,
        InvalidAccountOwner,
        InvalidPda,
        ExpectedSigner,
        ExpectedWritable,
    }

    impl From<PercolatorError> for ProgramError {
        fn from(e: PercolatorError) -> Self {
            ProgramError::Custom(e as u32)
        }
    }
}

// 3. mod ix
pub mod ix {
    use solana_program::pubkey::Pubkey;
    use bytemuck::{Pod, Zeroable};

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Pod, Zeroable)]
    pub struct OracleConfig {
        pub collateral_oracle: [u8; 32],
        pub index_oracle: [u8; 32],
        pub max_staleness_slots: u64,
        pub conf_filter_bps: u16,
        pub _padding: [u8; 6],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Pod, Zeroable)]
    pub struct RiskParams {
        pub min_margin_ratio: u64,
        pub maint_margin_ratio: u64,
    }

    #[derive(Debug)]
    pub enum Instruction {
        InitMarket { admin: Pubkey, collateral_mint: Pubkey, oracles: OracleConfig, risk_params: RiskParams },
        InitUser,
        DepositCollateral { amount: u64 },
        WithdrawCollateral { amount: u64 },
        PlaceOrder { side: u8, price: u64, size: u64 },
        CancelAll,
        Match, // Simplified
        SettleFunding,
        Liquidate { target_user: Pubkey },
    }

    impl Instruction {
        pub fn decode(input: &[u8]) -> Result<Self, solana_program::program_error::ProgramError> {
            // Simplified manual decoding for no_std/no-borsh requirement if strictly following "no external deps"
            // For now, assuming first byte is discriminant.
            let (&tag, _rest) = input.split_first().ok_or(solana_program::program_error::ProgramError::InvalidInstructionData)?;
            
            match tag {
                0 => {
                    // InitMarket decoding... (Placeholder)
                    Ok(Instruction::InitMarket { 
                        admin: Pubkey::default(), 
                        collateral_mint: Pubkey::default(), 
                        oracles: OracleConfig { collateral_oracle: [0; 32], index_oracle: [0; 32], max_staleness_slots: 0, conf_filter_bps: 0, _padding: [0;6] },
                        risk_params: RiskParams { min_margin_ratio: 0, maint_margin_ratio: 0 }
                    })
                },
                1 => Ok(Instruction::InitUser),
                2 => {
                     // Deposit...
                     Ok(Instruction::DepositCollateral { amount: 0 })
                },
                // ... Implement others
                _ => Err(solana_program::program_error::ProgramError::InvalidInstructionData),
            }
        }
    }
}

// 4. mod accounts (Pinocchio wrapper/shim)
pub mod accounts {
    use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};
    use crate::error::PercolatorError;

    pub struct AccountValidation<'a> {
        info: &'a AccountInfo<'a>,
    }

    impl<'a> AccountValidation<'a> {
        pub fn new(info: &'a AccountInfo<'a>) -> Self {
            Self { info }
        }

        pub fn is_signer(self) -> Result<Self, ProgramError> {
            if !self.info.is_signer {
                return Err(PercolatorError::ExpectedSigner.into());
            }
            Ok(self)
        }

        pub fn is_writable(self) -> Result<Self, ProgramError> {
            if !self.info.is_writable {
                return Err(PercolatorError::ExpectedWritable.into());
            }
            Ok(self)
        }

        pub fn is_owner(self, owner: &Pubkey) -> Result<Self, ProgramError> {
            if self.info.owner != owner {
                return Err(PercolatorError::InvalidAccountOwner.into());
            }
            Ok(self)
        }
        
        pub fn key(self) -> &'a Pubkey {
            self.info.key
        }

        pub fn info(self) -> &'a AccountInfo<'a> {
            self.info
        }
    }
}

// 5. mod state
pub mod state {
    use bytemuck::{Pod, Zeroable};
    use solana_program::pubkey::Pubkey;
    use crate::constants::*;

    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable)]
    pub struct SlabHeader {
        pub magic: u64,
        pub version: u32,
        pub bump: u8,
        pub _padding: [u8; 3],
        pub admin: [u8; 32],
        pub _reserved: [u8; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable)]
    pub struct MarketConfig {
        pub collateral_mint: [u8; 32],
        pub vault_pubkey: [u8; 32],
        pub collateral_oracle: [u8; 32],
        pub index_oracle: [u8; 32],
        pub max_staleness_slots: u64,
        pub conf_filter_bps: u16,
        pub _padding: [u8; 6], 
    }

    // Placeholder for Risk Engine State
    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable)]
    pub struct RiskEngineState {
        // Global risk state (e.g. open interest, insurance fund, etc.)
        pub total_deposits: u64,
        pub _reserved: [u8; 256],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable)]
    pub struct UserState {
        pub balance: u64,
        // Positions would go here
        pub _reserved: [u8; 120],
    }

    // The single Slab layout
    // In practice, this struct might be too large for stack, so we cast from byte slice.
    #[repr(C)]
    #[derive(Clone, Copy, Pod, Zeroable)]
    pub struct SlabLayout {
        pub header: SlabHeader,
        pub config: MarketConfig,
        pub risk_engine: RiskEngineState,
        // User Directory (Open addressing or simple linear scan for now as per constraints)
        pub user_directory: [[u8; 32]; MAX_USERS], 
        pub user_states: [UserState; MAX_USERS],
    }
}

// 6. mod oracle
pub mod oracle {
    use solana_program::{account_info::AccountInfo, program_error::ProgramError};
    // use pyth_sdk_solana::load_price_feed_from_account_info; 

    pub fn read_price(_account: &AccountInfo) -> Result<u64, ProgramError> {
        // Implement Pyth parsing here
        Ok(100) // Placeholder
    }
}

// 7. mod collateral
pub mod collateral {
    use solana_program::{
        account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey,
    };

    pub fn deposit(_from: &AccountInfo, _to: &AccountInfo, _auth: &AccountInfo, _amount: u64) -> Result<(), ProgramError> {
        // SPL Token transfer
        Ok(())
    }

    pub fn withdraw(_from: &AccountInfo, _to: &AccountInfo, _auth: &AccountInfo, _amount: u64) -> Result<(), ProgramError> {
        // SPL Token transfer with signer
        Ok(())
    }
}

// 8. mod processor
pub mod processor {
    use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, msg, pubkey::Pubkey};
    use crate::ix::Instruction;

    pub fn process_instruction(
        _program_id: &Pubkey,
        _accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let instruction = Instruction::decode(instruction_data)?;

        match instruction {
            Instruction::InitMarket { .. } => {
                msg!("Instruction: InitMarket");
                // Implement logic
            },
            Instruction::InitUser => {
                msg!("Instruction: InitUser");
            },
            Instruction::DepositCollateral { .. } => {
                msg!("Instruction: DepositCollateral");
            },
            _ => {
                msg!("Instruction: Unimplemented");
            }
        }
        Ok(())
    }
}

// 10. mod risk (Glue)
pub mod risk {
    // Adapter to the Percolator engine
    // use percolator; 
    // To be implemented: wrapper functions calling percolator::* 
}

// 9. mod entrypoint
pub mod entrypoint {
    use solana_program::{
        account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, pubkey::Pubkey,
    };
    use crate::processor;

    entrypoint!(process_instruction);

    fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        processor::process_instruction(program_id, accounts, instruction_data)
    }
}
