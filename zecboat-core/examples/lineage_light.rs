//! 0.7.1 check, headless: what the wallet's own lineage and issuance code says with NO node on
//! the machine, and whether a lineage file round-trips.
//!
//!   HOME=<a scratch COPY of a wallet home> ZECBOAT_PROVIDER=https://zec.rocks:443 \
//!     cargo run --release --example lineage_light -- [<this wallet's unified address>]
//!
//! Run it on a copy only: with an address it deletes one stored lading from that copy and
//! takes it back in as a file, the way a recipient would.

use anyhow::{anyhow, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let ua = std::env::args().nth(1);
    let db = zecboat_core::paths::as_string::wallet_db_path()?;
    if !db.contains("/scratchpad/") && std::env::var("LINEAGE_LIGHT_ANY_HOME").is_err() {
        return Err(anyhow!("refusing {db}: point HOME at a scratch copy"));
    }
    let ids: Vec<String> = {
        let conn = rusqlite::Connection::open(&db)?;
        let mut st = conn.prepare("SELECT DISTINCT asset_id FROM ext_zecboat_zmap_consignments WHERE received_note_id IS NOT NULL ORDER BY id")?;
        let v = st.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        v
    };
    println!("provider {}   zebrad rpc {}", zecboat_core::get_provider_url().await?, std::env::var("ZECBOAT_ZEBRAD_RPC").unwrap_or_else(|_| "http://127.0.0.1:8232 (default)".into()));
    for id in &ids {
        let t = std::time::Instant::now();
        let badge = serde_json::to_value(zecboat_core::verify_issuance(id.clone()).await?)?;
        let wake = serde_json::to_value(zecboat_core::verify_lineage(id.clone()).await?)?;
        println!("{}…  issuance: {}  lineage: {}  ({:.1}s)", &id[..12], badge["state"], wake["state"], t.elapsed().as_secs_f64());
        if let Some(c) = badge["checks"].as_array().and_then(|c| c.iter().find(|l| l.as_str().map(|s| s.starts_with("5'")).unwrap_or(false))) {
            println!("      {}", c.as_str().unwrap_or(""));
        }
        for k in ["asked", "detail"] {
            if let Some(v) = wake.get(k).and_then(|v| v.as_str()) {
                println!("      lineage {k}: {v}");
            }
        }
        if let Some(d) = badge.get("detail").and_then(|v| v.as_str()) {
            println!("      issuance detail: {d}");
        }
    }

    let Some(ua) = ua else { return Ok(()) };
    println!("-- lineage file round trip");
    let (row, hash, json): (i64, Vec<u8>, Vec<u8>) = {
        let conn = rusqlite::Connection::open(&db)?;
        conn.query_row(
            "SELECT id, sha256, json FROM ext_zecboat_zmap_consignments WHERE received_note_id IS NOT NULL ORDER BY id LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?
    };
    let sealed = zecboat_core::wake::seal_for(&ua, &json)?;
    println!("sealed file: {} bytes for a {}-byte lading", sealed.len(), json.len());
    rusqlite::Connection::open(&db)?.execute("DELETE FROM ext_zecboat_zmap_consignments WHERE id = ?1", [row])?;

    // A file sealed to someone else, and a file that is not the committed lading, must be refused.
    let mut other = json.clone();
    let n = other.len();
    other[n / 2] ^= 1;
    for (label, bytes) in [("a different lading sealed to this wallet", zecboat_core::wake::seal_for(&ua, &other)?), ("not a lineage file", b"{\"hello\":1}".to_vec())] {
        match zecboat_core::lineage_import(bytes).await {
            Ok(_) => println!("  {label}: ACCEPTED (BAD)"),
            Err(e) => println!("  {label}: refused ({})", e.to_string().chars().take(90).collect::<String>()),
        }
    }
    let got = zecboat_core::lineage_import(sealed.clone()).await?;
    println!("  the real file: accepted for \"{}\", {} proof(s), hash {}…", got.name, got.hops, &got.consignment_hash[..16]);
    assert_eq!(got.consignment_hash, hex::encode(&hash));
    match zecboat_core::lineage_import(sealed).await {
        Ok(_) => println!("  the same file again: ACCEPTED (BAD)"),
        Err(e) => println!("  the same file again: refused ({})", e.to_string().chars().take(70).collect::<String>()),
    }
    let wake = serde_json::to_value(zecboat_core::verify_lineage(got.asset_id).await?)?;
    println!("  lineage after import: {}", wake["state"]);

    // The same hand-over through a drop-box, when one is named: put the sealed record there as
    // a sending wallet would, then let the ordinary fetch pass collect it.
    let base = zecboat_core::dropbox_base();
    println!("-- drop-box round trip via {base}");
    rusqlite::Connection::open(&db)?.execute("DELETE FROM ext_zecboat_zmap_consignments WHERE id = (SELECT MAX(id) FROM ext_zecboat_zmap_consignments)", [])?;
    let hash_hex = hex::encode(&hash);
    let sealed = zecboat_core::wake::seal_for(&ua, &json)?;
    let (h2, s2) = (hash_hex.clone(), sealed.clone());
    tokio::task::spawn_blocking(move || zecboat_core::wake::dropbox_put(&h2, &s2)).await??;
    let h3 = hash_hex.clone();
    let back = tokio::task::spawn_blocking(move || zecboat_core::wake::dropbox_get(&h3)).await??;
    println!("  put {} bytes; the drop-box returns {} bytes, identical: {}", sealed.len(), back.as_ref().map(|b| b.len()).unwrap_or(0), back.as_deref() == Some(&sealed[..]));
    let r = zecboat_core::fetch_consignments().await?;
    println!("  fetch pass: fetched {}, already held {}, not in drop-box {}, failed {:?}", r.fetched, r.already_held, r.not_in_dropbox, r.failed);
    Ok(())
}
