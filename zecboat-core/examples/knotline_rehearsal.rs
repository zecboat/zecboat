//! Knotline, sender's side, without keys: on a COPY of a wallet, prove the next hop for one
//! asset exactly as a send would, build the log outputs, and check that what they carry rebuilds
//! the very lading whose hash would go into the carrier's memo. Nothing is spent or built into a
//! transaction; a spending key is never needed for this part.
//!
//!   env HOME=<scratch home with a wallet COPY> ZECBOAT_LADING_IN_MEMOS=knotline \
//!       cargo run --release --example knotline_rehearsal -- <asset_id>
use anyhow::{anyhow, Result};
use zmap_wake::knotline as log;

fn main() -> Result<()> {
    let asset_id = std::env::args().nth(1).ok_or_else(|| anyhow!("usage: knotline_rehearsal <asset_id>"))?;
    let home = std::env::var("HOME")?;
    if !home.contains("scratch") {
        return Err(anyhow!("refusing: HOME must be a scratch directory holding a wallet COPY (got {home})"));
    }
    let db_path = zecboat_core::paths::as_string::wallet_db_path()?;
    let conn = rusqlite::Connection::open(&db_path)?;
    let wallet_db = zcash_client_sqlite::WalletDb::for_path(&db_path, zcash_protocol::consensus::MainNetwork, zcash_client_sqlite::util::SystemClock, zmap_wake::rng::OsRng)?;
    let holdings = zecboat_core::zmap::holdings_from_rows(zecboat_core::zmap::read_carrier_rows(&conn)?);
    let plan = zecboat_core::zmap::plan_asset_send(&holdings, &asset_id)?;
    let chain = zecboat_core::wake::chain();
    println!("chain source: {}", chain.described());
    let t = std::time::Instant::now();
    let lading = zecboat_core::wake::prepare_send_lading(
        &wallet_db,
        &conn,
        &asset_id,
        plan.carrier.txid().as_ref(),
        u32::try_from(plan.carrier.output_index())?,
        zecboat_core::wake::genesis_ref_from_local_manifest(&asset_id).as_ref(),
        &chain,
    )?
    .ok_or_else(|| anyhow!("no lading can be made for this asset"))?;
    println!("next hop proved in {:.1?}: lading of {} proofs, {} bytes, sha256 {}…", t.elapsed(), lading.hops, lading.bytes.len(), &lading.hash_hex[..16]);

    let (extras, what) = zecboat_core::wake_memo::extra_outputs(&conn, plan.carrier.txid().as_ref(), None, &lading.bytes, lading.hops)?;
    println!("{what}");
    let to_recipient: Vec<&[u8]> = extras.iter().filter(|(to, _)| matches!(to, zecboat_core::wake_memo::ExtraTo::Recipient)).map(|(_, m)| &m[..]).collect();
    let to_record: Vec<(&String, &[u8])> = extras
        .iter()
        .filter_map(|(to, m)| match to {
            zecboat_core::wake_memo::ExtraTo::Address(a) => Some((a, &m[..])),
            _ => None,
        })
        .collect();
    println!("outputs: {} to the recipient, {} to the record address; a transfer of {} outputs, fee {:.5} ZEC", to_recipient.len(), to_record.len(), extras.len() + 2, (extras.len() + 2) as f64 * 5000.0 / 1e8);

    // What the recipient would do, on the plain memos: key, record, rebuild, compare.
    let key = log::key_from_memos(to_recipient.iter().copied()).ok_or_else(|| anyhow!("no key memo among the recipient's outputs"))?;
    let (_, addr) = log::knot_keys(&key);
    let want_ua = zcash_keys::address::UnifiedAddress::from_receivers(Some(addr), None, None, None, None).map(|ua| zecboat_core::addr::encode_u1(&ua)).unwrap();
    println!("record address is the one derived from the key: {}", to_record.iter().all(|(a, _)| **a == want_ua));
    let packed = log::from_memos(to_record.iter().map(|(_, m)| *m), log::KNOT_TAG).ok_or_else(|| anyhow!("record chunks do not reassemble"))?;
    let record = log::unpack_knot(&packed)?;
    println!("record: {} hop(s), names a predecessor: {}, names the genesis: {}", record.hops.len(), record.prev.is_some(), record.genesis.is_some());
    let mut open = |_: &[u8; 32], _: &[u8; 32], _: Option<u32>| Ok(Some(packed.clone()));
    match log::walk_back(key, [0u8; 32], &mut open) {
        Ok((rebuilt, _)) if record.prev.is_none() => {
            let bytes = rebuilt.to_bytes();
            println!("rebuilt lading is byte-identical to the one being sent: {}; hash matches: {}", bytes == lading.bytes, hex::encode(zmap_wake::lading::lading_hash(&bytes)) == lading.hash_hex);
        }
        Ok(_) => println!("(this record links to an earlier one; the full rebuild needs the chain)"),
        Err(e) => println!("(walk back from this record alone: {e}; expected when it links to an earlier one)"),
    }
    Ok(())
}
