//! Chapter 2 harness: run the paired carrier send against a COPY of a wallet, without
//! broadcasting. Exercises pairing, proving, signing, extraction, storage and the lineage
//! record; prints the raw transaction hex. Nothing leaves this machine.
//!
//!   cargo build --example wake_pair_send
//!   env HOME=<scratch home with .AppVault/data/wallet.db (a COPY)> \
//!       target/debug/examples/wake_pair_send <seed words file> <asset_id> <recipient UA>
use std::env;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::MainNetwork;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let [_, words_path, asset_id, recipient] = args.as_slice() else {
        anyhow::bail!("usage: wake_pair_send <seed words file> <asset_id> <recipient UA>");
    };
    let home = env::var("HOME")?;
    if home.contains("captain") || home.contains("user2") || !home.contains("scratch") {
        anyhow::bail!("refusing: HOME must be a scratch directory holding a wallet COPY (got {home})");
    }
    // Accept "1. word" per line as well as a plain phrase.
    let words: Vec<String> = std::fs::read_to_string(words_path)?
        .split_whitespace()
        .filter(|t| !t.trim_end_matches('.').chars().all(|c| c.is_ascii_digit()))
        .map(str::to_lowercase)
        .collect();
    let phrase = words.join(" ");
    let mnemonic = bip0039::Mnemonic::<bip0039::English>::from_phrase(&phrase)
        .map_err(|e| anyhow::anyhow!("seed words: {:?}", e))?;
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, &mnemonic.to_seed(""), zip32::AccountId::ZERO)
        .map_err(|e| anyhow::anyhow!("usk: {:?}", e))?;

    let db_path = zecboat_core::paths::as_string::wallet_db_path()?;
    println!("wallet: {db_path}");
    let mut wallet_db = zcash_client_sqlite::WalletDb::for_path(
        &db_path,
        MainNetwork,
        zcash_client_sqlite::util::SystemClock,
        rand::rngs::OsRng,
    )?;
    let t = std::time::Instant::now();
    let hex = zecboat_core::native_builder::send_zmap_asset(&mut wallet_db, &usk, asset_id, recipient)?;
    println!("built, proved, signed and stored in {:.1?}; {} bytes; NOT broadcast", t.elapsed(), hex.len() / 2);
    let out = format!("{home}/paired_tx.hex");
    std::fs::write(&out, &hex)?;
    println!("raw tx hex written to {out}");
    Ok(())
}
