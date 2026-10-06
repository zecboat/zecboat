//! PROTOTYPE (2026-10-05): a lineage record carried inside the transfer itself.
//!
//! Instead of leaving the lading in a drop-box or a file, the sender splits it over the memos
//! of extra zero-value outputs to the recipient, in the same transaction as the carrier. The
//! recipient's wallet finds them in a transaction it reads anyway. No server, no third party.
//!
//! Sending is OFF unless `ZECBOAT_LADING_IN_MEMOS=1`, and only for ladings of at most
//! [`MAX_HOPS`] proofs: the whole chain is resent on every transfer, about ten outputs per hop.
//! Receiving is always on; it costs nothing when no such memos are present.
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

/// Whether this wallet sends ladings inside the transfer.
pub fn sending_enabled() -> bool {
    std::env::var("ZECBOAT_LADING_IN_MEMOS").map(|v| v == "1").unwrap_or(false)
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
    let mut stmt = conn.prepare(
        "SELECT n.memo FROM ironwood_received_notes n
           JOIN transactions t ON t.id_tx = n.transaction_id
          WHERE t.txid = ?1 AND n.memo IS NOT NULL",
    )?;
    let memos: Vec<Vec<u8>> = stmt
        .query_map([txid_internal.as_slice()], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<_>>()?;
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
