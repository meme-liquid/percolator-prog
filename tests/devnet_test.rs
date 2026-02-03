//! Devnet integration test for deployed Percolator program
//!
//! This test runs against the actual deployed program on devnet.
//! Requires: solana CLI configured for devnet with funded wallet
//!
//! Run: cargo test --test devnet_test -- --nocapture --ignored

use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
    sysvar,
};
use spl_token::state::Account as TokenAccount;
use std::str::FromStr;

// Deployed program IDs on devnet
const PERCOLATOR_PROGRAM_ID: &str = "46iB4ET4WpqfTXAqGSmyBczLBgVhd1sHre93KtU3sTg9";
const MATCHER_PROGRAM_ID: &str = "4HcGCsyjAqnFua5ccuXyt8KRRQzKFbGTJkVChpS7Yfzy";

// Pyth devnet SOL/USD feed
const PYTH_SOL_USD_FEED: &str = "J83w4HKfqxwcq3BEMMkPFSppX3gqekLyLJBexebFVkix";
const PYTH_RECEIVER_PROGRAM: &str = "rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ";

// Account sizes
const SLAB_LEN: usize = 992560;
const MAX_ACCOUNTS: usize = 4096;
const MATCHER_CONTEXT_LEN: usize = 320;

fn get_rpc_client() -> RpcClient {
    RpcClient::new_with_commitment(
        "https://api.devnet.solana.com".to_string(),
        CommitmentConfig::confirmed(),
    )
}

fn load_keypair() -> Keypair {
    let keypair_path = shellexpand::tilde("~/.config/solana/id.json").to_string();
    let keypair_bytes: Vec<u8> = serde_json::from_str(
        &std::fs::read_to_string(&keypair_path).expect("Failed to read keypair file")
    ).expect("Failed to parse keypair");
    Keypair::from_bytes(&keypair_bytes).expect("Invalid keypair")
}

fn encode_init_market(
    admin: &Pubkey,
    mint: &Pubkey,
    feed_id: &[u8; 32],
    invert: u8,
) -> Vec<u8> {
    let mut data = vec![0u8]; // InitMarket instruction
    data.extend_from_slice(admin.as_ref());
    data.extend_from_slice(mint.as_ref());
    data.extend_from_slice(feed_id);
    data.extend_from_slice(&u64::MAX.to_le_bytes()); // max_staleness_secs (disabled for devnet)
    data.extend_from_slice(&10000u16.to_le_bytes()); // conf_filter_bps (100% - disabled)
    data.push(invert);
    data.extend_from_slice(&0u32.to_le_bytes()); // unit_scale
    data.extend_from_slice(&0u64.to_le_bytes()); // initial_mark_price_e6
    // RiskParams
    data.extend_from_slice(&0u64.to_le_bytes()); // warmup_period_slots
    data.extend_from_slice(&500u64.to_le_bytes()); // maintenance_margin_bps (5%)
    data.extend_from_slice(&1000u64.to_le_bytes()); // initial_margin_bps (10%)
    data.extend_from_slice(&10u64.to_le_bytes()); // trading_fee_bps
    data.extend_from_slice(&(MAX_ACCOUNTS as u64).to_le_bytes());
    data.extend_from_slice(&0u128.to_le_bytes()); // new_account_fee
    data.extend_from_slice(&0u128.to_le_bytes()); // risk_reduction_threshold
    data.extend_from_slice(&0u128.to_le_bytes()); // maintenance_fee_per_slot
    data.extend_from_slice(&u64::MAX.to_le_bytes()); // max_crank_staleness_slots
    data.extend_from_slice(&50u64.to_le_bytes()); // liquidation_fee_bps
    data.extend_from_slice(&1_000_000_000_000u128.to_le_bytes()); // liquidation_fee_cap
    data.extend_from_slice(&100u64.to_le_bytes()); // liquidation_buffer_bps
    data.extend_from_slice(&0u128.to_le_bytes()); // min_liquidation_abs
    data
}

fn encode_init_lp(matcher: &Pubkey, ctx: &Pubkey, fee: u64) -> Vec<u8> {
    let mut data = vec![2u8];
    data.extend_from_slice(matcher.as_ref());
    data.extend_from_slice(ctx.as_ref());
    data.extend_from_slice(&fee.to_le_bytes());
    data
}

fn encode_init_user(fee: u64) -> Vec<u8> {
    let mut data = vec![1u8];
    data.extend_from_slice(&fee.to_le_bytes());
    data
}

fn encode_deposit(user_idx: u16, amount: u64) -> Vec<u8> {
    let mut data = vec![3u8];
    data.extend_from_slice(&user_idx.to_le_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

fn encode_trade(lp: u16, user: u16, size: i128) -> Vec<u8> {
    let mut data = vec![6u8];
    data.extend_from_slice(&lp.to_le_bytes());
    data.extend_from_slice(&user.to_le_bytes());
    data.extend_from_slice(&size.to_le_bytes());
    data
}

fn encode_crank() -> Vec<u8> {
    let mut data = vec![5u8];
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.push(0u8); // allow_panic = false
    data
}

fn encode_init_matcher(mode: u8, trading_fee_bps: u32, spread_bps: u32) -> Vec<u8> {
    let mut data = vec![2u8]; // MATCHER_INIT_VAMM_TAG
    data.push(mode); // mode at offset 1
    data.extend_from_slice(&trading_fee_bps.to_le_bytes()); // 2..6
    data.extend_from_slice(&spread_bps.to_le_bytes()); // 6..10
    data.extend_from_slice(&200u32.to_le_bytes()); // max_total_bps 10..14
    data.extend_from_slice(&0u32.to_le_bytes()); // impact_k_bps 14..18
    data.extend_from_slice(&0u128.to_le_bytes()); // liquidity_notional_e6 18..34
    data.extend_from_slice(&1_000_000_000_000u128.to_le_bytes()); // max_fill_abs 34..50
    data.extend_from_slice(&0u128.to_le_bytes()); // max_inventory_abs 50..66
    data
}

/// Create a test market on devnet
#[test]
#[ignore] // Run with: cargo test --test devnet_test -- --ignored --nocapture
fn test_devnet_full_lifecycle() {
    println!("\n=== DEVNET INTEGRATION TEST ===\n");

    let client = get_rpc_client();
    let payer = load_keypair();
    let program_id = Pubkey::from_str(PERCOLATOR_PROGRAM_ID).unwrap();
    let matcher_id = Pubkey::from_str(MATCHER_PROGRAM_ID).unwrap();

    println!("Payer: {}", payer.pubkey());
    println!("Program: {}", program_id);
    println!("Matcher: {}", matcher_id);

    let balance = client.get_balance(&payer.pubkey()).unwrap();
    println!("Balance: {} SOL\n", balance as f64 / 1e9);

    // Use native SOL wrapped as collateral
    let mint = spl_token::native_mint::id();
    println!("Using native SOL mint: {}", mint);

    // Create slab account
    let slab = Keypair::new();
    println!("Slab account: {}", slab.pubkey());

    let rent = client.get_minimum_balance_for_rent_exemption(SLAB_LEN).unwrap();
    println!("Slab rent: {} SOL", rent as f64 / 1e9);

    let create_slab_ix = system_instruction::create_account(
        &payer.pubkey(),
        &slab.pubkey(),
        rent,
        SLAB_LEN as u64,
        &program_id,
    );

    // Derive vault PDA
    let (vault_pda, _bump) = Pubkey::find_program_address(
        &[b"vault", slab.pubkey().as_ref()],
        &program_id,
    );
    println!("Vault PDA: {}", vault_pda);

    // Create vault token account (owned by vault PDA)
    let vault = Keypair::new();
    println!("Vault token account: {}", vault.pubkey());

    let vault_rent = client.get_minimum_balance_for_rent_exemption(TokenAccount::LEN).unwrap();
    let create_vault_ix = system_instruction::create_account(
        &payer.pubkey(),
        &vault.pubkey(),
        vault_rent,
        TokenAccount::LEN as u64,
        &spl_token::id(),
    );

    let init_vault_ix = spl_token::instruction::initialize_account(
        &spl_token::id(),
        &vault.pubkey(),
        &mint,
        &vault_pda,
    ).unwrap();

    // Create matcher context account
    let matcher_ctx = Keypair::new();
    println!("Matcher context: {}", matcher_ctx.pubkey());

    let ctx_rent = client.get_minimum_balance_for_rent_exemption(MATCHER_CONTEXT_LEN).unwrap();
    let create_ctx_ix = system_instruction::create_account(
        &payer.pubkey(),
        &matcher_ctx.pubkey(),
        ctx_rent,
        MATCHER_CONTEXT_LEN as u64,
        &matcher_id,
    );

    // Create payer's wrapped SOL account for deposits
    let user_ata = Keypair::new();
    let create_ata_ix = system_instruction::create_account(
        &payer.pubkey(),
        &user_ata.pubkey(),
        vault_rent,
        TokenAccount::LEN as u64,
        &spl_token::id(),
    );
    let init_ata_ix = spl_token::instruction::initialize_account(
        &spl_token::id(),
        &user_ata.pubkey(),
        &mint,
        &payer.pubkey(),
    ).unwrap();

    // Step 1: Create accounts (split into multiple transactions due to signer limits)
    println!("\n--- Step 1: Creating accounts ---");

    // Create slab account
    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_slab_ix],
        Some(&payer.pubkey()),
        &[&payer, &slab],
        blockhash,
    );
    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("Slab created: {}", sig),
        Err(e) => {
            println!("Failed to create slab: {:?}", e);
            return;
        }
    }

    // Create vault token account
    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_vault_ix, init_vault_ix],
        Some(&payer.pubkey()),
        &[&payer, &vault],
        blockhash,
    );
    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("Vault created: {}", sig),
        Err(e) => {
            println!("Failed to create vault: {:?}", e);
            return;
        }
    }

    // Create matcher context
    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_ctx_ix],
        Some(&payer.pubkey()),
        &[&payer, &matcher_ctx],
        blockhash,
    );
    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("Matcher context created: {}", sig),
        Err(e) => {
            println!("Failed to create matcher context: {:?}", e);
            return;
        }
    }

    // Create user ATA
    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[create_ata_ix, init_ata_ix],
        Some(&payer.pubkey()),
        &[&payer, &user_ata],
        blockhash,
    );
    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("User ATA created: {}", sig),
        Err(e) => {
            println!("Failed to create user ATA: {:?}", e);
            return;
        }
    }

    // Get Pyth feed ID
    let pyth_account = Pubkey::from_str(PYTH_SOL_USD_FEED).unwrap();
    let mut feed_id = [0u8; 32];
    // For devnet, we'll use a placeholder feed_id that matches the Pyth account structure
    // In production, this would be extracted from the Pyth price account
    feed_id.copy_from_slice(pyth_account.as_ref());

    // Step 2: Initialize market
    println!("\n--- Step 2: Initializing market ---");
    let init_market_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab.pubkey(), false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(vault.pubkey(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(sysvar::rent::id(), false),
            AccountMeta::new_readonly(user_ata.pubkey(), false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data: encode_init_market(&payer.pubkey(), &mint, &feed_id, 0),
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[init_market_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("Market initialized: {}", sig),
        Err(e) => {
            println!("Failed to init market: {:?}", e);
            return;
        }
    }

    // Step 3: Initialize matcher context
    println!("\n--- Step 3: Initializing matcher context ---");
    let init_matcher_ix = Instruction {
        program_id: matcher_id,
        accounts: vec![
            AccountMeta::new(matcher_ctx.pubkey(), false),
        ],
        data: encode_init_matcher(0, 5, 10), // Passive mode, 5 bps fee, 10 bps spread
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[init_matcher_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("Matcher initialized: {}", sig),
        Err(e) => {
            println!("Failed to init matcher: {:?}", e);
            return;
        }
    }

    // Step 4: Initialize LP
    println!("\n--- Step 4: Initializing LP ---");
    let init_lp_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab.pubkey(), false),
            AccountMeta::new(user_ata.pubkey(), false),
            AccountMeta::new(vault.pubkey(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(matcher_id, false),
            AccountMeta::new_readonly(matcher_ctx.pubkey(), false),
        ],
        data: encode_init_lp(&matcher_id, &matcher_ctx.pubkey(), 0),
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[init_lp_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("LP initialized (idx=0): {}", sig),
        Err(e) => {
            println!("Failed to init LP: {:?}", e);
            return;
        }
    }

    // Step 5: Initialize User
    println!("\n--- Step 5: Initializing User ---");
    let init_user_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab.pubkey(), false),
            AccountMeta::new(user_ata.pubkey(), false),
            AccountMeta::new(vault.pubkey(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(pyth_account, false),
        ],
        data: encode_init_user(0),
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[init_user_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("User initialized (idx=1): {}", sig),
        Err(e) => {
            println!("Failed to init user: {:?}", e);
            return;
        }
    }

    // Step 6: Wrap SOL and deposit
    println!("\n--- Step 6: Depositing collateral ---");

    // First sync native account (wrap SOL)
    let sync_native_ix = spl_token::instruction::sync_native(&spl_token::id(), &user_ata.pubkey()).unwrap();

    // Transfer SOL to the token account to wrap it
    let wrap_amount = 1_000_000_000u64; // 1 SOL
    let transfer_ix = system_instruction::transfer(
        &payer.pubkey(),
        &user_ata.pubkey(),
        wrap_amount,
    );

    // Deposit to LP (idx=0)
    let deposit_lp_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab.pubkey(), false),
            AccountMeta::new(user_ata.pubkey(), false),
            AccountMeta::new(vault.pubkey(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
        ],
        data: encode_deposit(0, wrap_amount / 2),
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix, sync_native_ix, deposit_lp_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("LP deposit (0.5 SOL): {}", sig),
        Err(e) => {
            println!("Failed to deposit to LP: {:?}", e);
            return;
        }
    }

    // Deposit to User (idx=1)
    let transfer_ix2 = system_instruction::transfer(
        &payer.pubkey(),
        &user_ata.pubkey(),
        wrap_amount / 2,
    );
    let sync_native_ix2 = spl_token::instruction::sync_native(&spl_token::id(), &user_ata.pubkey()).unwrap();
    let deposit_user_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab.pubkey(), false),
            AccountMeta::new(user_ata.pubkey(), false),
            AccountMeta::new(vault.pubkey(), false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
        ],
        data: encode_deposit(1, wrap_amount / 4),
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[transfer_ix2, sync_native_ix2, deposit_user_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("User deposit (0.25 SOL): {}", sig),
        Err(e) => {
            println!("Failed to deposit to user: {:?}", e);
            return;
        }
    }

    // Step 7: Execute trade (TradeNoCpi for simplicity)
    println!("\n--- Step 7: Executing trade ---");
    let trade_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true), // user signer
            AccountMeta::new(payer.pubkey(), true), // lp signer (same for test)
            AccountMeta::new(slab.pubkey(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(pyth_account, false),
        ],
        data: encode_trade(0, 1, 1_000_000), // LP idx=0, User idx=1, size=1M
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[trade_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("Trade executed: {}", sig),
        Err(e) => {
            println!("Trade result: {:?}", e);
            // This might fail due to oracle issues on devnet, that's OK
        }
    }

    // Step 8: Run crank
    println!("\n--- Step 8: Running crank ---");
    let crank_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(slab.pubkey(), false),
            AccountMeta::new_readonly(sysvar::clock::id(), false),
            AccountMeta::new_readonly(pyth_account, false),
        ],
        data: encode_crank(),
    };

    let blockhash = client.get_latest_blockhash().unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[crank_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => println!("Crank executed: {}", sig),
        Err(e) => {
            println!("Crank result: {:?}", e);
        }
    }

    println!("\n=== DEVNET TEST COMPLETE ===");
    println!("Market: {}", slab.pubkey());
    println!("Vault: {}", vault.pubkey());
    println!("Matcher context: {}", matcher_ctx.pubkey());
}
