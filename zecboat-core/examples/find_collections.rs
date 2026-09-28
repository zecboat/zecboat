//! A3b, phase 1: the wallet's own registry scan, run headless against a node, in a scratch HOME.
//!
//! ```sh
//! mkdir -p /tmp/scratch_registry
//! HOME=/tmp/scratch_registry ZECBOAT_PROVIDER=https://zec.rocks:443 \
//!   cargo run --release --example find_collections [-- --audit]
//! ```
//!
//! With `--audit`, each valid registration is then audited by the wallet's own implementation
//! (phase 2); compare with the mint's `audit` / `registry-scan --audit`.
//!
//! Prints every registration in the Zecboat Registry as the wallet sees it. Compare with the mint's
//! `registry-scan` over the same node: the two are independent implementations (BOUNDARY.md rule 3)
//! and must agree.
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let home = env::var("HOME")?;
    if !home.contains("scratch") {
        anyhow::bail!("refusing: HOME must be a scratch directory (got {home})");
    }
    if let Ok(p) = env::var("ZECBOAT_PROVIDER") {
        *zecboat_core::rpc::PROVIDER_URL.lock().unwrap() = p;
    }
    println!("registry db: {}", zecboat_core::paths::registry_db_path()?.display());
    println!("node:        {}", zecboat_core::rpc::grpc_endpoint());
    let t = std::time::Instant::now();
    let v = zecboat_core::collections::scan_registry().await?;
    println!("scanned to {} in {:.1?}; {} registration(s)", v.scanned_to, t.elapsed(), v.registrations.len());
    for r in &v.registrations {
        println!(
            "\n{} [{}]\n  ik            {}\n  registered    {} at {}\n  mint / close  {} / {} (close tx {})\n  manifest      {}\n  signature     {}\n  viewing key   {} ({} chars)",
            r.name,
            if r.valid { "VALID" } else { "INVALID" },
            r.ik,
            r.registration_txid,
            r.registration_height,
            r.mint_height,
            r.close_height,
            r.close_txid,
            r.manifest_sha256,
            if r.signature_ok { "OK" } else { "FAIL" },
            if r.ufvk_hash_ok { "matches its hash" } else { "DOES NOT match" },
            r.ufvk.as_ref().map(|u| u.len()).unwrap_or(0),
        );
        if let Some(why) = &r.reason {
            println!("  reason        {why}");
        }
    }
    if env::args().any(|a| a == "--holdings") {
        let h = zecboat_core::collections::holdings_by_ik()?;
        println!("\nholdings in this HOME's wallet.db: {} collection key(s)", h.len());
        for (ik, x) in &h {
            println!("  {}…  {} unit(s), {} forged id(s)", &ik[..16], x.count, x.bad_ids);
        }
    }
    // Phase 4: `--badge <asset_id>` shows the issuance badge and Wake's genesis for one unit.
    let args: Vec<String> = env::args().collect();
    let badge_for = args.iter().position(|a| a == "--badge").and_then(|i| args.get(i + 1)).cloned();
    if env::args().any(|a| a == "--audit") {
        for r in v.registrations.iter().filter(|r| r.valid) {
            println!("\nAUDIT {} (birthday {})", r.name, r.mint_height.saturating_sub(zecboat_core::collection_audit::BIRTHDAY_MARGIN));
            let t = std::time::Instant::now();
            let a = zecboat_core::collection_audit::audit_registered(&r.ik, &r.registration_txid).await?;
            for c in &a.checks {
                println!("  [{}] {:>2}. {}{}", if c.pass { "PASS" } else { "FAIL" }, c.n, c.label,
                    c.detail.as_ref().map(|d| format!(" ({d})")).unwrap_or_default());
            }
            for u in &a.units {
                println!("    #{:03} {}  id {}…  genesis {}… #{}  cmx {}…", u.unit, u.name, &u.asset_id[..16], &u.genesis_txid[..12], u.genesis_action, &u.genesis_cmx[..16]);
            }
            println!("  {} in {:.1?}: {} unit(s), closed at {:?}, audited to {}",
                if a.passed { "AUDIT PASSED" } else { "AUDIT FAILED" }, t.elapsed(), a.units.len(), a.close_height, a.audited_to);
        }
    }
    if let Some(id) = badge_for {
        println!("\nBADGE for {id}");
        println!("  {:?}", zecboat_core::issuance::verify_issuance(id.clone()).await?);
        println!("  wake genesis: {:?}", zecboat_core::wake::genesis_outpoint(&id).await);
    }
    Ok(())
}
