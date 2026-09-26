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
    // Expiry from the node's tip, not the (possibly stale) copy's view: WAKE_ZEBRAD, default local.
    let expiry = {
        let url = env::var("WAKE_ZEBRAD").unwrap_or_else(|_| "http://127.0.0.1:8232".into());
        let out = std::process::Command::new("curl")
            .args(["-s", "--max-time", "10", "-u", "x:x", "-H", "content-type: application/json",
                   "--data", r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#, &url])
            .output()?;
        let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
        let tip = v["result"].as_u64().ok_or_else(|| anyhow::anyhow!("no tip from zebrad"))? as u32;
        println!("node tip {tip}; expiry {}", tip + 40);
        Some(zcash_protocol::consensus::BlockHeight::from_u32(tip + 40))
    };
    // Wake (chapter 8): the genesis outpoint from ZECBOAT_WAKE_MANIFEST if set; the unit may
    // travel unproven only with WAKE_ALLOW_UNPROVEN=1. The lading goes to ZECBOAT_DROPBOX.
    let wake = zecboat_core::wake::SendOptions {
        genesis: zecboat_core::wake::genesis_from_local_manifest(asset_id),
        acknowledge_unproven: env::var("WAKE_ALLOW_UNPROVEN").map(|v| v == "1").unwrap_or(false),
    };
    let t = std::time::Instant::now();
    let hex = zecboat_core::native_builder::send_zmap_asset(&mut wallet_db, &usk, asset_id, recipient, expiry, &wake)?;
    println!("built, proved, signed and stored in {:.1?}; {} bytes; NOT broadcast", t.elapsed(), hex.len() / 2);
    let out = format!("{home}/paired_tx.hex");
    std::fs::write(&out, &hex)?;
    println!("raw tx hex written to {out}");
    Ok(())
}
