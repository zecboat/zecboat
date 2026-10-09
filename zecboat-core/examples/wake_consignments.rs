//! Chapter 8 harness for the receiving side, against a COPY of a wallet in a scratch HOME.
//!
//!   cargo build --release --features test-overrides --example wake_consignments
//!   (without the feature ZECBOAT_WAKE_MANIFEST is ignored)
//!   env HOME=<scratch home holding .AppVault/data/wallet.db (a COPY)> \
//!       ZECBOAT_WAKE_MANIFEST=/path/manifest_v05.json \
//!       ZECBOAT_ZEBRAD_RPC=http://127.0.0.1:8232 \
//!       target/release/examples/wake_consignments <list|fetch|verify <asset_id>|state>
//!
//! `list` prints stored ladings; `fetch` collects the ladings carriers' memos commit to; `verify` runs the four-state badge for one asset; `state` prints what
//! `get_zsas` would report. Nothing here builds or broadcasts a transaction.
use std::env;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let home = env::var("HOME")?;
    if home.contains("captain") || home.contains("user2") || !home.contains("scratch") {
        anyhow::bail!("refusing: HOME must be a scratch directory holding a wallet COPY (got {home})");
    }
    let db_path = zecboat_core::paths::as_string::wallet_db_path()?;
    match args.get(1).map(String::as_str) {
        Some("estimate") => {
            // What the confirmation screen would quote for sending this item now.
            let asset_id = args.get(2).ok_or_else(|| anyhow::anyhow!("estimate <asset_id>"))?;
            let conn = rusqlite::Connection::open(&db_path)?;
            println!("{}", serde_json::to_string(&zecboat_core::wake_memo::send_estimate(&conn, asset_id, None)?)?);
        }
        Some("list") => {
            let conn = rusqlite::Connection::open(&db_path)?;
            for c in zecboat_core::zmap::list_consignments(&conn)? {
                let hops = zmap_wake::lading::Lading::parse(&c.json).map(|l| l.hops.len()).unwrap_or(0);
                println!(
                    "#{} asset {}… note {:?} hops {} sha256 {}… verified_at {:?} ({})",
                    c.id, &c.asset_id[..12], c.received_note_id, hops, &c.sha256[..16], c.verified_at_height, c.created_at
                );
            }
        }
        Some("fetch") => {
            let r = zecboat_core::wake::fetch_missing_consignments(&db_path)?;
            println!("{r:?}");
        }
        Some("verify") => {
            let asset_id = args.get(2).ok_or_else(|| anyhow::anyhow!("verify needs an asset id"))?;
            let genesis = zecboat_core::wake::genesis_ref_from_local_manifest(asset_id);
            let state = zecboat_core::wake::verify_holding(&db_path, asset_id, genesis.as_ref())?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Some("state") => {
            let conn = rusqlite::Connection::open(&db_path)?;
            let holdings = zecboat_core::zmap::holdings_from_rows(zecboat_core::zmap::read_carrier_rows(&conn)?);
            for h in holdings {
                let lading = zecboat_core::zmap::latest_consignment(&conn, &h.asset_id)?;
                for c in &h.carriers {
                    println!(
                        "{} {}… out {} memo consignment_hash {:?} stored lading {}",
                        h.name,
                        &c.txid[..12],
                        c.output_index,
                        c.consignment_hash.as_deref().map(|s| &s[..16]),
                        lading.as_ref().map(|l| format!("{}…", &l.sha256[..16])).unwrap_or_else(|| "none".into())
                    );
                }
            }
        }
        _ => anyhow::bail!("usage: wake_consignments <list|fetch|verify <asset_id>|state>"),
    }
    Ok(())
}
