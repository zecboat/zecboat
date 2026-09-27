//! A1b harness: run the wallet's own `verify_issuance` for a list of asset ids, in a scratch
//! HOME (a wallet COPY, so the holder-memo check has something to read, or none at all).
//!   env HOME=<scratch> ZECBOAT_PINNED_V1='label|ik|file:///…/issuance_manifest.json' \
//!       target/release/examples/v1_badge <asset_id>...
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let home = std::env::var("HOME")?;
    if home.contains("captain") || home.contains("user2") || !home.contains("scratch") {
        anyhow::bail!("refusing: HOME must be a scratch directory (got {home})");
    }
    for id in std::env::args().skip(1) {
        let state = zecboat_core::verify_issuance(id.clone()).await?;
        println!("{}…\n{}\n", &id[..16], serde_json::to_string_pretty(&state)?);
    }
    Ok(())
}
