//! Feasibility check (2026-10-05): carry a lineage record inside the transfer itself, as memos
//! of extra shielded outputs to the recipient, instead of handing it to a drop-box.
//!
//!   cargo run --release --features lightwalletd --example memo_carry -- <wallet-copy.db> <server-url>
//!
//! For ladings of 1 and 2 real hops (the second hop proved here, as a send would) and for longer
//! ones padded out with repeated hops (size only), it:
//!   1. packs the lading into a compact binary form and shows that form is lossless: unpacked
//!      and re-serialised it is byte-identical to the original, so the hash in the memo holds;
//!   2. splits it over 512-byte memos (ZIP 302 "arbitrary data", first byte 0xF5) and builds a
//!      real Ironwood bundle of that many zero-value outputs to a recipient, with its proof;
//!   3. checks the bundle's proof, measures its size and proving time, and prices it by ZIP 317;
//!   4. plays the recipient: trial-decrypts every action with the recipient's viewing key,
//!      reassembles the record, and (real hops only) verifies it against the server.
//! Nothing is signed for broadcast and nothing leaves this process except the server queries.

use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ff::PrimeField;
use orchard::builder::{Builder, BundleType};
use orchard::bundle::{Authorized, Bundle, BundleVersion};
use orchard::circuit::{ProvingKey, VerifyingKey};
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey};
use orchard::note::Rho;
use orchard::note_encryption::IronwoodDomain;
use orchard::value::NoteValue;
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::Path;
use zcash_note_encryption::try_note_decryption;
use zcash_protocol::consensus::Network;
use zmap_wake::lading::{lading_hash, Lading, ProofEntry};
use zmap_wake::oracle::{decode_hex_32, reversed, MIN_DEPTH};
use zmap_wake::oracle_lightwalletd::LightwalletdOracle;
use zmap_wake::wallet_notes::{received_notes_in_tx, witness_at};
use zmap_wake::wallet_path::{open_wallet_copy, open_wallet_copy_sql};
use zmap_wake::{prove_hop, verify_chain};

const TAG: &[u8; 4] = b"WKL1";
/// 512 minus the 0xF5 lead byte, the tag, 8 bytes of the lading hash, chunk index and count.
const CHUNK: usize = 512 - 1 - 4 - 8 - 2 - 2;

fn pack(l: &Lading) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&decode_hex_32(&l.genesis.txid)?);
    out.extend_from_slice(&l.genesis.action_index.to_le_bytes());
    out.extend_from_slice(&(l.hops.len() as u16).to_le_bytes());
    for h in &l.hops {
        out.push(match h.circuit.as_str() { "genesis" => 0, "hop" => 1, o => return Err(anyhow!("circuit {o}")) });
        for i in &h.instance {
            out.extend_from_slice(&decode_hex_32(i)?);
        }
        out.extend_from_slice(&h.anchor_height.to_le_bytes());
        let proof = base64::engine::general_purpose::STANDARD.decode(&h.proof)?;
        out.extend_from_slice(&(proof.len() as u16).to_le_bytes());
        out.extend_from_slice(&proof);
    }
    Ok(out)
}

fn unpack(b: &[u8], template: &Lading) -> Result<Lading> {
    let hex = |x: &[u8]| x.iter().map(|v| format!("{v:02x}")).collect::<String>();
    let mut i = 0;
    let mut take = |n: usize| -> Result<&[u8]> {
        let s = b.get(i..i + n).ok_or_else(|| anyhow!("truncated"))?;
        i += n;
        Ok(s)
    };
    let mut l = template.clone();
    l.genesis.txid = hex(take(32)?);
    l.genesis.action_index = u32::from_le_bytes(take(4)?.try_into()?);
    let n = u16::from_le_bytes(take(2)?.try_into()?) as usize;
    l.hops.clear();
    for _ in 0..n {
        let circuit = if take(1)?[0] == 0 { "genesis" } else { "hop" }.to_string();
        let instance = [hex(take(32)?), hex(take(32)?), hex(take(32)?)];
        let anchor_height = u32::from_le_bytes(take(4)?.try_into()?);
        let len = u16::from_le_bytes(take(2)?.try_into()?) as usize;
        let proof = base64::engine::general_purpose::STANDARD.encode(take(len)?);
        l.hops.push(ProofEntry { kind: template.hops[0].kind.clone(), circuit, instance, anchor_height, proof });
    }
    Ok(l)
}

fn to_memos(packed: &[u8], hash: &[u8; 32]) -> Vec<[u8; 512]> {
    let total = packed.chunks(CHUNK).count() as u16;
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
            m[17..17 + c.len()].copy_from_slice(c);
            m
        })
        .collect()
}

struct Built {
    bundle: Bundle<Authorized, i64>,
    prove_secs: f64,
}

fn build(memos: &[[u8; 512]], recipient: orchard::Address, anchor: orchard::tree::Anchor, pk: &ProvingKey) -> Result<Built> {
    let version = BundleVersion::ironwood_v3();
    let mut b = Builder::new(BundleType::DEFAULT, version, version.default_flags(), anchor).map_err(|e| anyhow!("{e:?}"))?;
    // The transfer itself: the new carrier and the change. Their memos are the asset's, not ours.
    for _ in 0..2 {
        b.add_output(None, recipient, NoteValue::from_raw(0), [0u8; 512]).map_err(|e| anyhow!("{e:?}"))?;
    }
    for m in memos {
        b.add_output(None, recipient, NoteValue::from_raw(0), *m).map_err(|e| anyhow!("{e:?}"))?;
    }
    let (unproven, _) = b.build::<i64>(OsRng).map_err(|e| anyhow!("{e:?}"))?.ok_or_else(|| anyhow!("empty bundle"))?;
    let t = Instant::now();
    let proven = unproven.create_proof(pk, OsRng).map_err(|e| anyhow!("{e:?}"))?;
    let prove_secs = t.elapsed().as_secs_f64();
    let bundle = proven.prepare(OsRng, [0u8; 32]).finalize().map_err(|e| anyhow!("{e:?}"))?;
    Ok(Built { bundle, prove_secs })
}

fn receive(bundle: &Bundle<Authorized, i64>, fvk: &FullViewingKey) -> Result<Vec<u8>> {
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let mut parts: Vec<(u16, u16, Vec<u8>)> = Vec::new();
    for a in bundle.actions() {
        let Some((_, _, memo)) = try_note_decryption(&IronwoodDomain::for_action(a), &ivk, a) else { continue };
        if memo[0] != 0xF5 || &memo[1..5] != TAG {
            continue;
        }
        let idx = u16::from_le_bytes([memo[13], memo[14]]);
        let total = u16::from_le_bytes([memo[15], memo[16]]);
        parts.push((idx, total, memo[17..].to_vec()));
    }
    parts.sort_by_key(|p| p.0);
    let total = parts.first().map(|p| p.1).ok_or_else(|| anyhow!("no record memos decrypted"))? as usize;
    if parts.len() != total || parts.iter().enumerate().any(|(i, p)| p.0 as usize != i) {
        return Err(anyhow!("{} of {total} record memos", parts.len()));
    }
    Ok(parts.into_iter().flat_map(|p| p.2).collect())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err(anyhow!("usage: memo_carry <wallet-copy.db> <server-url>"));
    }
    let conn = open_wallet_copy_sql(&args[1])?;
    let wallet = open_wallet_copy(&args[1], Network::MainNetwork)?;
    let oracle = LightwalletdOracle::new(args[2].clone(), Network::MainNetwork)?;
    let tip = oracle.tip_height()?;
    let anchor = oracle.ironwood_tree_state(tip - 10)?.root;
    println!("server {}  tip {tip}", args[2]);

    let (json, sha, rho, note_row, txid_internal): (Vec<u8>, Vec<u8>, Vec<u8>, i64, Vec<u8>) = conn.query_row(
        "SELECT c.json, c.sha256, n.rho, n.id, t.txid FROM ext_zecboat_zmap_consignments c \
         JOIN ironwood_received_notes n ON n.id = c.received_note_id \
         JOIN transactions t ON t.id_tx = n.transaction_id ORDER BY c.id LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    let one = Lading::parse(&json).map_err(|e| anyhow!("{e:?}"))?;
    let rho1: Rho = Option::from(Rho::from_bytes(&<[u8; 32]>::try_from(rho.as_slice())?)).context("rho")?;
    assert_eq!(lading_hash(&json).as_slice(), sha.as_slice());

    // A second, real hop: proved from the server's tree state, as a send would.
    zmap_wake::keys::warm();
    let txid: [u8; 32] = txid_internal.as_slice().try_into()?;
    let note = received_notes_in_tx(Path::new(&args[1]), Network::MainNetwork, &reversed(txid))?
        .into_iter()
        .find(|n| n.row_id == note_row)
        .ok_or_else(|| anyhow!("note not found"))?;
    let ts = oracle.ironwood_tree_state(note.mined_height)?;
    let proof = prove_hop(&witness_at(&wallet, &note, &ts)?).map_err(|e| anyhow!("{e:?}"))?;
    let mut two = one.clone();
    two.hops.push(ProofEntry::from_proof(&proof, note.mined_height));
    let rho2: Rho = Option::from(Rho::from_bytes(&proof.instance[2].to_repr())).context("rho2")?;

    // The recipient: a throwaway key made here. Only its viewing key is used to receive.
    let mut seed = [0u8; 32];
    let sk = loop {
        OsRng.fill_bytes(&mut seed);
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed)) {
            break sk;
        }
    };
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    let version = BundleVersion::ironwood_v3();
    let t = Instant::now();
    let pk = ProvingKey::build(version.circuit_version());
    let vk = VerifyingKey::build(version.circuit_version());
    println!("proving and verifying keys built in {:.1}s (once per wallet start)\n", t.elapsed().as_secs_f64());

    let base = build(&[], recipient, anchor, &pk)?;
    let size = |b: &Bundle<Authorized, i64>| {
        let n = b.actions().len();
        // cv, nf, rk, cmx, epk, enc, out per action; one signature per action; flags, value
        // balance, anchor, binding signature; the proof with its length prefix.
        n * (32 * 5 + 580 + 80) + n * 64 + 1 + 8 + 32 + 64 + b.authorization().proof().as_ref().len() + 3 + 3
    };
    let base_size = size(&base.bundle);
    println!("a transfer with no record:  2 actions, {} bytes, fee {:.5} ZEC, proved in {:.1}s\n", base_size, 2.0 * 5000.0 / 1e8, base.prove_secs);
    println!("{:>5} {:>9} {:>6} {:>8} {:>10} {:>11} {:>9} {:>9}  {}", "hops", "record B", "memos", "actions", "tx bytes", "fee ZEC", "prove s", "receive s", "result");

    let cases: Vec<(usize, Lading, Option<Rho>)> = {
        let mut v = vec![(1, one.clone(), Some(rho1)), (2, two.clone(), Some(rho2))];
        for n in [3usize, 5] {
            let mut l = two.clone();
            while l.hops.len() < n {
                l.hops.push(two.hops[1].clone());
            }
            v.push((n, l, None));
        }
        v
    };
    for (hops, lading, rho) in cases {
        let original = lading.to_bytes();
        let hash = lading_hash(&original);
        let packed = pack(&lading)?;
        if unpack(&packed, &lading)?.to_bytes() != original {
            return Err(anyhow!("compact form is not lossless at {hops} hop(s)"));
        }
        let memos = to_memos(&packed, &hash);
        let built = build(&memos, recipient, anchor, &pk)?;
        built.bundle.verify_proof(&vk).map_err(|e| anyhow!("bundle proof does not verify: {e:?}"))?;
        let n = built.bundle.actions().len();

        let t = Instant::now();
        let got = receive(&built.bundle, &fvk)?;
        let rebuilt = unpack(&got[..packed.len()], &lading)?.to_bytes();
        let mut result = if lading_hash(&rebuilt) == hash { "reassembled, hash matches".to_string() } else { "HASH MISMATCH".to_string() };
        if let Some(rho) = rho {
            result += match verify_chain(&rebuilt, Some(hash), &rho, &oracle, MIN_DEPTH) {
                Ok(_) => "; lineage verifies",
                Err(_) => "; LINEAGE FAILED",
            };
        } else {
            result += " (padded: size only)";
        }
        let receive_secs = t.elapsed().as_secs_f64();
        println!(
            "{:>5} {:>9} {:>6} {:>8} {:>10} {:>11.5} {:>9.1} {:>9.2}  {}",
            hops, packed.len(), memos.len(), n, size(&built.bundle), n as f64 * 5000.0 / 1e8, built.prove_secs, receive_secs, result
        );
    }
    // A stranger's key decrypts none of it.
    let other = FullViewingKey::from(&Option::<SpendingKey>::from(SpendingKey::from_bytes([7u8; 32])).context("sk")?);
    let again = build(&to_memos(&pack(&one)?, &lading_hash(&one.to_bytes())), recipient, anchor, &pk)?;
    println!("\nanother wallet's key on the same transfer: {}", match receive(&again.bundle, &other) { Ok(_) => "READ IT (BAD)".to_string(), Err(e) => format!("nothing ({e})") });
    Ok(())
}
