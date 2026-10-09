//! verify_badge — run the Design Verified checks against a real asset id.
//!
//! The badge is only worth having if it answers correctly on live data, so this exercises the
//! whole path: the manifest built into the wallet (or the audit's chain copy), verified under
//! its pinned key, the asset found in it, then the genesis output checked on chain.
//!
//!   ZECBOAT_PROVIDER=<grpc url> cargo run --example verify_badge -- <asset_id>
//!
//! A deliberately wrong asset id should come back Unknown (or NotListed when its memo names a
//! known key), never Verified -- a check that has never rejected anything has not been tested.

#[tokio::main]
async fn main() {
    let id = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: verify_badge <asset_id-64-hex>");
        std::process::exit(2);
    });
    match zecboat_core::issuance::verify_issuance(id).await {
        Ok(state) => println!("{}", serde_json::to_string_pretty(&state).unwrap()),
        Err(e) => println!("unexpected error: {e}"),
    }
}
