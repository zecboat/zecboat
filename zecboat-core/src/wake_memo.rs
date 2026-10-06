//! PROTOTYPE (2026-10-05): a lineage record carried inside the transfer itself.
//!
//! Instead of leaving the lading in a drop-box or a file, the sender splits it over the memos
//! of extra zero-value outputs to the recipient, in the same transaction as the carrier. The
//! recipient's wallet finds them in a transaction it reads anyway. No server, no third party.
//!
//! Sending is OFF unless `ZECBOAT_LADING_IN_MEMOS` is set: `1` sends the whole lading to the
//! recipient (at most [`MAX_HOPS`] proofs: the whole chain is resent on every transfer, about ten
//! outputs per hop); `knotline` ties only the new hop onto the item's Knotline
//! (`zmap_wake::knotline`, twelve outputs per transfer whatever the history).
//! Receiving either form is always on; it costs nothing when no such memos are present.
//!
//! Nothing here adds a byte to the carrier's own memo, which is nearly full (2026-10-02: HBD10
//! reached 533 bytes with its hash, over the 512 limit).
//!
//! Wire form, per memo (ZIP 302 lead byte 0xF5, "arbitrary data"):
//!   0xF5 | "WKL1" | first 8 bytes of the lading hash | chunk index u16 | chunk count u16 | data
//! The data is the lading packed as: version 1 | genesis txid 32 | action index u32 | hops u16 |
//! per hop: circuit 0/1 | instance 3x32 | anchor height u32 | proof length u16 | proof.
//! Packing is lossless: unpacked and re-serialised, a lading is byte-identical, so the
//! `consignment_hash` in the carrier's memo is unchanged.

use anyhow::{anyhow, Result};
use base64::Engine;
use zmap_wake::lading::{lading_hash, Lading, ProofEntry};

/// Ladings longer than this are not carried in the transfer.
pub const MAX_HOPS: usize = 3;
const TAG: &[u8; 4] = b"WKL1";
const HEAD: usize = 1 + 4 + 8 + 2 + 2;
const CHUNK: usize = 512 - HEAD;
const KIND_V1: &str = "wake-v1";

/// How this wallet sends a lading inside the transfer (`ZECBOAT_LADING_IN_MEMOS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendMode {
    /// Unset: not in the transfer at all (drop-box or file, as in 0.7.1).
    Off,
    /// `1`: the whole lading, to the recipient, up to [`MAX_HOPS`] proofs.
    FullRecord,
    /// `knotline` (or `log`, its first name): only the new hop, as one knot on the item's
    /// Knotline (`zmap_wake::knotline`).
    Knotline,
}

pub fn send_mode() -> SendMode {
    match std::env::var("ZECBOAT_LADING_IN_MEMOS").as_deref() {
        Ok("1") => SendMode::FullRecord,
        Ok("knotline") | Ok("log") => SendMode::Knotline,
        _ => SendMode::Off,
    }
}

/// Where an extra zero-value output of a transfer goes.
#[derive(Clone, Debug)]
pub enum ExtraTo {
    /// The recipient of the carrier.
    Recipient,
    /// A unified address, encoded.
    Address(String),
}

/// The extra outputs that carry `lading` in this transfer, and a line saying what they are.
/// Empty when the mode is off or the lading cannot travel this way.
pub fn extra_outputs(conn: &rusqlite::Connection, carrier_txid_internal: &[u8; 32], lading_bytes: &[u8], hops: usize) -> Result<(Vec<(ExtraTo, [u8; 512])>, String)> {
    match send_mode() {
        SendMode::Off => Ok((Vec::new(), String::new())),
        SendMode::FullRecord => {
            let memos = memos_for(lading_bytes, hops)?.unwrap_or_default();
            let n = memos.len();
            Ok((memos.into_iter().map(|m| (ExtraTo::Recipient, m)).collect(), format!("the whole lading, {n} memo output(s) to the recipient")))
        }
        SendMode::Knotline => knotline_outputs(conn, carrier_txid_internal, lading_bytes),
    }
}

/// An item whose history is not in the log yet publishes it once; longer histories than this
/// are left to the other routes.
pub const MAX_JOIN_HOPS: usize = 6;

fn memos_in_transaction(conn: &rusqlite::Connection, txid_internal: &[u8; 32]) -> Result<Vec<Vec<u8>>> {
    let mut stmt = conn.prepare(
        "SELECT n.memo FROM ironwood_received_notes n
           JOIN transactions t ON t.id_tx = n.transaction_id
          WHERE t.txid = ?1 AND n.memo IS NOT NULL",
    )?;
    let memos = stmt.query_map([txid_internal.as_slice()], |r| r.get::<_, Vec<u8>>(0))?.collect::<rusqlite::Result<_>>()?;
    Ok(memos)
}

/// Knotline, sending: one key memo to the recipient and one record under a fresh key. The
/// record holds only the newest hop when the carrier arrived with a key memo of its own (its
/// history is already in the log); otherwise the item joins the log and the record holds the
/// history so far.
fn knotline_outputs(conn: &rusqlite::Connection, carrier_txid_internal: &[u8; 32], lading_bytes: &[u8]) -> Result<(Vec<(ExtraTo, [u8; 512])>, String)> {
    use zmap_wake::knotline as log;
    let l = Lading::parse(lading_bytes).map_err(|e| anyhow!("{e}"))?;
    let n = l.hops.len();
    let memos = memos_in_transaction(conn, carrier_txid_internal)?;
    let prev_key = log::key_from_memos(memos.iter().map(|m| m.as_slice()));
    let (record, what) = match prev_key {
        Some(k) if n >= 2 => (
            log::Knot { prev: Some((k, *carrier_txid_internal)), genesis: None, hops: l.hops[n - 1..].to_vec() },
            format!("Knotline: one knot, hop {n} only, tied to the knot before it"),
        ),
        _ if n <= MAX_JOIN_HOPS => (
            log::Knot { prev: None, genesis: Some((l.genesis.txid.clone(), l.genesis.action_index)), hops: l.hops.clone() },
            format!("Knotline: this item starts its line, publishing its {n} hop(s) once"),
        ),
        _ => return Ok((Vec::new(), String::new())),
    };
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    let (_, addr) = log::knot_keys(&key);
    let ua = zcash_keys::address::UnifiedAddress::from_receivers(Some(addr), None, None)
        .ok_or_else(|| anyhow!("could not form the knot's address"))?
        .encode(&zcash_protocol::consensus::MainNetwork);
    let mut out = vec![(ExtraTo::Recipient, log::key_memo(&key))];
    for m in log::chunks(log::KNOT_TAG, &log::pack_knot(&record)?)? {
        out.push((ExtraTo::Address(ua.clone()), m));
    }
    let count = out.len();
    Ok((out, format!("{what}; {count} memo output(s)")))
}

/// What sending `asset_id` now would add to the transfer and cost, for the confirmation screen.
/// It mirrors [`extra_outputs`] without proving anything: the new hop is taken at its fixed
/// size, which is what decides the number of memo outputs.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SendEstimate {
    /// `none` (no lineage travels in the transfer), `knot` (one knot), `start` (the item starts
    /// its Knotline with its history so far) or `whole` (the whole lading to the recipient).
    pub lineage: &'static str,
    /// Proofs the lading will have after this send; 0 when it has none.
    pub proofs: usize,
    pub extra_outputs: usize,
    pub outputs: usize,
    pub fee_zat: u64,
}

pub fn send_estimate(conn: &rusqlite::Connection, asset_id: &str) -> Result<SendEstimate> {
    // One packed hop: circuit byte, three instance fields, anchor height, proof length, proof.
    const HOP: usize = 1 + 96 + 4 + 2 + 4960;
    const CHUNK: usize = 512 - 9;
    let plain = SendEstimate { lineage: "none", proofs: 0, extra_outputs: 0, outputs: 2, fee_zat: 10_000 };
    let with = |lineage: &'static str, proofs: usize, extras: usize| SendEstimate {
        lineage,
        proofs,
        extra_outputs: extras,
        outputs: extras + 2,
        fee_zat: 5_000 * (extras as u64 + 2),
    };
    let held = match crate::zmap::latest_consignment(conn, asset_id)? {
        Some(c) => Lading::parse(&c.json).map(|l| l.hops.len()).unwrap_or(0),
        None => 0,
    };
    // With no lading held, a proof can still be made if this note is the issuance output; that
    // is not known here without the manifest, so it is estimated as a line of one proof.
    let after = held + 1;
    Ok(match send_mode() {
        SendMode::Off => plain,
        SendMode::FullRecord if after <= MAX_HOPS => {
            let packed = 1 + 32 + 4 + 2 + after * HOP;
            with("whole", after, packed.div_ceil(512 - HEAD))
        }
        SendMode::FullRecord => plain,
        SendMode::Knotline => {
            let holdings = crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(conn)?);
            let plan = crate::zmap::plan_asset_send(&holdings, asset_id)?;
            let memos = memos_in_transaction(conn, plan.carrier.txid().as_ref())?;
            let linked = zmap_wake::knotline::key_from_memos(memos.iter().map(|m| m.as_slice())).is_some() && after >= 2;
            if linked {
                with("knot", after, (2 + 64 + 2 + HOP).div_ceil(CHUNK) + 1)
            } else if after <= MAX_JOIN_HOPS {
                with("start", after, (2 + 36 + 2 + after * HOP).div_ceil(CHUNK) + 1)
            } else {
                plain
            }
        }
    })
}

/// Knotline, receiving: if the carrier's transaction hands this wallet a key, walk the log
/// back and return the rebuilt lading and the number of records walked. The result hashes to
/// `expected_hash_hex` or it is an error. `None` when there is no key memo.
pub fn lading_from_knotline(conn: &rusqlite::Connection, carrier_txid_internal: &[u8; 32], expected_hash_hex: &str) -> Result<Option<(Vec<u8>, usize)>> {
    use zmap_wake::knotline as log;
    let memos = memos_in_transaction(conn, carrier_txid_internal)?;
    let Some(key) = log::key_from_memos(memos.iter().map(|m| m.as_slice())) else {
        return Ok(None);
    };
    // A transaction this wallet already holds is read from its own database; an older one is
    // asked of the chain source (own node if it answers, the provider otherwise).
    let mut chain: Option<crate::wake::Chain> = None;
    let mut open = |k: &[u8; 32], txid: &[u8; 32]| -> Result<Option<Vec<u8>>> {
        let held: Option<(Vec<u8>, Option<u32>)> = conn
            .query_row("SELECT raw, mined_height FROM transactions WHERE txid = ?1 AND raw IS NOT NULL", [txid.as_slice()], |r| Ok((r.get(0)?, r.get(1)?)))
            .ok();
        let (raw, height) = match held {
            Some((raw, Some(h))) => (raw, h),
            _ => {
                let c = chain.get_or_insert_with(crate::wake::chain);
                match c.raw_transaction(txid)? {
                    Some((h, raw)) => (raw, h),
                    None => return Ok(None),
                }
            }
        };
        log::read_knot_in_tx(&raw, height, &zcash_protocol::consensus::Network::MainNetwork, k)
    };
    let (lading, walked) = log::walk_back(key, *carrier_txid_internal, &mut open)?;
    let bytes = lading.to_bytes();
    if hex::encode(lading_hash(&bytes)) != expected_hash_hex.to_ascii_lowercase() {
        return Err(anyhow!("the lading rebuilt from the Knotline does not hash to the memo's consignment_hash"));
    }
    Lading::parse(&bytes).map_err(|e| anyhow!("{e}"))?;
    Ok(Some((bytes, walked)))
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| anyhow!("not 32 bytes of hex"))
}

/// Pack a lading. Refuses anything the packed form cannot reproduce exactly.
pub fn pack(lading_bytes: &[u8]) -> Result<Vec<u8>> {
    let l = Lading::parse(lading_bytes).map_err(|e| anyhow!("{e}"))?;
    let mut out = vec![1u8];
    out.extend_from_slice(&hex32(&l.genesis.txid)?);
    out.extend_from_slice(&l.genesis.action_index.to_le_bytes());
    out.extend_from_slice(&u16::try_from(l.hops.len())?.to_le_bytes());
    for h in &l.hops {
        if h.kind != KIND_V1 {
            return Err(anyhow!("proof kind {} cannot be packed", h.kind));
        }
        out.push(match h.circuit.as_str() {
            "genesis" => 0,
            "hop" => 1,
            other => return Err(anyhow!("circuit {other} cannot be packed")),
        });
        for i in &h.instance {
            out.extend_from_slice(&hex32(i)?);
        }
        out.extend_from_slice(&h.anchor_height.to_le_bytes());
        let proof = base64::engine::general_purpose::STANDARD.decode(&h.proof)?;
        out.extend_from_slice(&u16::try_from(proof.len())?.to_le_bytes());
        out.extend_from_slice(&proof);
    }
    if unpack(&out)? != lading_bytes {
        return Err(anyhow!("this lading does not survive packing byte for byte"));
    }
    Ok(out)
}

/// Unpack to the lading's canonical bytes.
pub fn unpack(b: &[u8]) -> Result<Vec<u8>> {
    let mut i = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let s = b.get(i..i + n).ok_or_else(|| anyhow!("packed lading is truncated"))?;
        i += n;
        Ok(s)
    };
    if take(1)?[0] != 1 {
        return Err(anyhow!("unknown packed lading version"));
    }
    let txid = hex::encode(take(32)?);
    let action_index = u32::from_le_bytes(take(4)?.try_into()?);
    let hops = u16::from_le_bytes(take(2)?.try_into()?) as usize;
    let mut l = Lading::new(&txid, action_index);
    for _ in 0..hops {
        let circuit = match take(1)?[0] {
            0 => "genesis",
            1 => "hop",
            _ => return Err(anyhow!("unknown circuit in packed lading")),
        }
        .to_string();
        let instance = [hex::encode(take(32)?), hex::encode(take(32)?), hex::encode(take(32)?)];
        let anchor_height = u32::from_le_bytes(take(4)?.try_into()?);
        let len = u16::from_le_bytes(take(2)?.try_into()?) as usize;
        let proof = base64::engine::general_purpose::STANDARD.encode(take(len)?);
        l.hops.push(ProofEntry { kind: KIND_V1.to_string(), circuit, instance, anchor_height, proof });
    }
    Ok(l.to_bytes())
}

/// The memos that carry `lading_bytes`, or `None` when it is too long to carry.
pub fn memos_for(lading_bytes: &[u8], hops: usize) -> Result<Option<Vec<[u8; 512]>>> {
    if hops == 0 || hops > MAX_HOPS {
        return Ok(None);
    }
    let packed = pack(lading_bytes)?;
    let hash = lading_hash(lading_bytes);
    let total = u16::try_from(packed.chunks(CHUNK).count())?;
    Ok(Some(
        packed
            .chunks(CHUNK)
            .enumerate()
            .map(|(i, c)| {
                let mut m = [0u8; 512];
                m[0] = 0xF5;
                m[1..5].copy_from_slice(TAG);
                m[5..13].copy_from_slice(&hash[..8]);
                m[13..15].copy_from_slice(&(i as u16).to_le_bytes());
                m[15..17].copy_from_slice(&total.to_le_bytes());
                m[HEAD..HEAD + c.len()].copy_from_slice(c);
                m
            })
            .collect(),
    ))
}

/// Reassemble the lading whose hash is `expected_hash_hex` from a transaction's memos. `None`
/// when the memos carry no complete record for that hash. The result hashes to the expected
/// value or it is not returned.
pub fn from_memos<'a>(memos: impl IntoIterator<Item = &'a [u8]>, expected_hash_hex: &str) -> Option<Vec<u8>> {
    let want = hex::decode(expected_hash_hex).ok()?;
    let mut parts: Vec<(u16, u16, Vec<u8>)> = Vec::new();
    for m in memos {
        if m.len() < HEAD || m[0] != 0xF5 || &m[1..5] != TAG || m[5..13] != want[..8.min(want.len())] {
            continue;
        }
        // A stored memo may have lost its trailing zero bytes; a chunk is CHUNK bytes or fewer.
        let mut data = m[HEAD..].to_vec();
        data.resize(CHUNK, 0);
        parts.push((u16::from_le_bytes([m[13], m[14]]), u16::from_le_bytes([m[15], m[16]]), data));
    }
    parts.sort_by_key(|p| p.0);
    parts.dedup_by_key(|p| p.0);
    let total = parts.first()?.1 as usize;
    if total == 0 || parts.len() != total || parts.iter().enumerate().any(|(i, p)| p.0 as usize != i || p.1 as usize != total) {
        return None;
    }
    let packed: Vec<u8> = parts.into_iter().flat_map(|p| p.2).collect();
    let bytes = unpack(&packed).ok()?;
    (lading_hash(&bytes).as_slice() == want.as_slice()).then_some(bytes)
}

/// The record for carrier `(txid, consignment hash)` if its own transaction carries it.
pub fn record_in_transaction(conn: &rusqlite::Connection, txid_internal: &[u8; 32], expected_hash_hex: &str) -> Result<Option<Vec<u8>>> {
    let memos = memos_in_transaction(conn, txid_internal)?;
    Ok(from_memos(memos.iter().map(|m| m.as_slice()), expected_hash_hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(hops: usize) -> Vec<u8> {
        let mut l = Lading::new(&"ab".repeat(32), 7);
        for j in 0..hops {
            l.hops.push(ProofEntry {
                kind: KIND_V1.to_string(),
                circuit: if j == 0 { "genesis" } else { "hop" }.to_string(),
                instance: [format!("{:064x}", j + 1), format!("{:064x}", j + 2), format!("{:064x}", j + 3)],
                anchor_height: 3_500_000 + j as u32,
                proof: base64::engine::general_purpose::STANDARD.encode(vec![j as u8 + 1; 4960]),
            });
        }
        l.to_bytes()
    }

    #[test]
    fn packing_is_lossless_and_chunks_reassemble() {
        for hops in 1..=MAX_HOPS {
            let bytes = sample(hops);
            assert_eq!(unpack(&pack(&bytes).unwrap()).unwrap(), bytes);
            let memos = memos_for(&bytes, hops).unwrap().unwrap();
            assert_eq!(memos.len(), [0, 11, 21, 31][hops]);
            let hash = hex::encode(lading_hash(&bytes));
            // In any order, with unrelated memos mixed in, and with trailing zeros trimmed.
            let mut shuffled: Vec<Vec<u8>> = memos.iter().rev().map(|m| m.to_vec()).collect();
            shuffled.push(vec![0xF6]);
            shuffled.push(br#"{"asset_id":"x"}"#.to_vec());
            while shuffled[0].last() == Some(&0) {
                shuffled[0].pop();
            }
            assert_eq!(from_memos(shuffled.iter().map(|m| m.as_slice()), &hash).unwrap(), bytes);
        }
    }

    #[test]
    fn an_incomplete_or_foreign_record_is_not_returned() {
        let bytes = sample(2);
        let memos = memos_for(&bytes, 2).unwrap().unwrap();
        let hash = hex::encode(lading_hash(&bytes));
        let missing_one: Vec<&[u8]> = memos.iter().skip(1).map(|m| &m[..]).collect();
        assert!(from_memos(missing_one, &hash).is_none());
        let other_hash = hex::encode(lading_hash(&sample(1)));
        assert!(from_memos(memos.iter().map(|m| &m[..]), &other_hash).is_none());
        let mut tampered = memos.clone();
        tampered[3][100] ^= 1;
        assert!(from_memos(tampered.iter().map(|m| &m[..]), &hash).is_none(), "the hash check catches a changed chunk");
    }

    #[test]
    fn long_ladings_are_not_carried() {
        assert!(memos_for(&sample(MAX_HOPS + 1), MAX_HOPS + 1).unwrap().is_none());
    }
}
