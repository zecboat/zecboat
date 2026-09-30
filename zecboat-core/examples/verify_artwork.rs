//! Fetch and verify one asset's artwork exactly as the wallet does, in a scratch HOME.
//!
//! ```sh
//! mkdir -p /tmp/scratch_art && cp <a COPY of>/wallet.db /tmp/scratch_art/.AppVault/data/
//! HOME=/tmp/scratch_art [ZECBOAT_REGISTRY=http://127.0.0.1:8099] \
//!   cargo run --release --example verify_artwork -- <asset_id>
//! ```
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let home = env::var("HOME")?;
    if !home.contains("scratch") {
        anyhow::bail!("refusing: HOME must be a scratch directory (got {home})");
    }
    let asset_id = env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: verify_artwork <asset_id>"))?;
    let v = zecboat_core::rpc::verify_asset_image(asset_id).await?;
    println!("verified:      {}", v["verified"]);
    println!("source_url:    {}", v["source_url"].as_str().unwrap_or(""));
    println!("expected_hash: {}", v["expected_hash"].as_str().unwrap_or(""));
    println!("actual_hash:   {}", v["actual_hash"].as_str().unwrap_or(""));
    println!("bytes:         {}  type: {}", v["bytes"], v["actual_type"].as_str().unwrap_or(""));
    println!("image shown:   {}", if v["image"].is_null() { "no" } else { "yes" });
    Ok(())
}
