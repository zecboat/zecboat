//! Feasibility check (2026-10-06) of the Knotline (first written up as the "encrypted lineage
//! log", variant B; see `~/knotline.md`). Written before the name and before the library module
//! `zmap_wake::knotline`, so it carries its own copy of the format: each transfer publishes ONLY its own hop, in memos of
//! outputs to an address derived from a fresh key; the key goes to the new owner in one memo;
//! each record carries the key and the transaction of the record before it.
//!
//!   cargo run --release --features lightwalletd --example knotline_feasibility -- <wallet-copy.db> <server-url>
//!
//! Uses a wallet COPY holding a real lading and its note. A further real hop is proved here from
//! the server's tree state, so the chain has real proofs end to end. For each hop it builds a
//! real Ironwood bundle with its proof (the transfer's two outputs, the record, the key memo),
//! then plays the last owner: reads the key with their viewing key, walks back record by record,
//! rebuilds the lading, checks its hash and verifies it against the server. It also shows who
//! cannot read what. Transactions are kept in memory under a made-up id; nothing is signed for
//! broadcast.

use std::collections::HashMap;
use std::path::Path;
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
use zcash_note_encryption::try_note_decryption;
use zcash_protocol::consensus::Network;
use zmap_wake::lading::{lading_hash, Lading, ProofEntry};
use zmap_wake::oracle::{decode_hex_32, reversed, MIN_DEPTH};
use zmap_wake::oracle_lightwalletd::LightwalletdOracle;
use zmap_wake::wallet_notes::{received_notes_in_tx, witness_at};
use zmap_wake::wallet_path::{open_wallet_copy, open_wallet_copy_sql};
use zmap_wake::{prove_hop, verify_chain};

const REC: &[u8; 4] = b"WKR1";
const KEY: &[u8; 4] = b"WKK1";
const HEAD: usize = 1 + 4 + 2 + 2;
const CHUNK: usize = 512 - HEAD;
type Tx = Bundle<Authorized, i64>;

fn hexs(x: &[u8]) -> String {
    x.iter().map(|v| format!("{v:02x}")).collect()
}

/// The one-time address a record for key `k` is written to, and the key that reads it.
fn record_keys(k: &[u8; 32]) -> (FullViewingKey, orchard::Address) {
    let mut counter = 0u8;
    loop {
        let h = blake2b_simd::Params::new().hash_length(32).personal(b"ZbWakeRecordV1__").to_state().update(k).update(&[counter]).finalize();
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(h.as_bytes().try_into().unwrap())) {
            let fvk = FullViewingKey::from(&sk);
            let addr = fvk.address_at(0u32, Scope::External);
            return (fvk, addr);
        }
        counter += 1;
    }
}

fn pack_hop(h: &ProofEntry) -> Result<Vec<u8>> {
    let mut out = vec![if h.circuit == "genesis" { 0u8 } else { 1 }];
    for i in &h.instance {
        out.extend_from_slice(&decode_hex_32(i)?);
    }
    out.extend_from_slice(&h.anchor_height.to_le_bytes());
    let proof = base64::engine::general_purpose::STANDARD.decode(&h.proof)?;
    out.extend_from_slice(&(proof.len() as u16).to_le_bytes());
    out.extend_from_slice(&proof);
    Ok(out)
}

/// A record: the previous record's key and transaction (absent for the first), the genesis
/// outpoint (first record only), and one or more hops.
fn pack_record(prev: Option<(&[u8; 32], &[u8; 32])>, genesis: Option<(&str, u32)>, hops: &[ProofEntry]) -> Result<Vec<u8>> {
    let mut out = vec![1u8, prev.is_some() as u8 | (genesis.is_some() as u8) << 1];
    if let Some((k, t)) = prev {
        out.extend_from_slice(k);
        out.extend_from_slice(t);
    }
    if let Some((txid, idx)) = genesis {
        out.extend_from_slice(&decode_hex_32(txid)?);
        out.extend_from_slice(&idx.to_le_bytes());
    }
    out.extend_from_slice(&(hops.len() as u16).to_le_bytes());
    for h in hops {
        out.extend_from_slice(&pack_hop(h)?);
    }
    Ok(out)
}

struct Record {
    prev: Option<([u8; 32], [u8; 32])>,
    genesis: Option<(String, u32)>,
    hops: Vec<ProofEntry>,
}

fn unpack_record(b: &[u8], kind: &str) -> Result<Record> {
    let mut i = 0usize;
    let mut take = |n: usize| -> Result<&[u8]> {
        let s = b.get(i..i + n).ok_or_else(|| anyhow!("record truncated"))?;
        i += n;
        Ok(s)
    };
    if take(1)?[0] != 1 {
        return Err(anyhow!("unknown record version"));
    }
    let flags = take(1)?[0];
    let prev = if flags & 1 != 0 { Some((take(32)?.try_into()?, take(32)?.try_into()?)) } else { None };
    let genesis = if flags & 2 != 0 { Some((hexs(take(32)?), u32::from_le_bytes(take(4)?.try_into()?))) } else { None };
    let n = u16::from_le_bytes(take(2)?.try_into()?) as usize;
    let mut hops = Vec::new();
    for _ in 0..n {
        let circuit = if take(1)?[0] == 0 { "genesis" } else { "hop" }.to_string();
        let instance = [hexs(take(32)?), hexs(take(32)?), hexs(take(32)?)];
        let anchor_height = u32::from_le_bytes(take(4)?.try_into()?);
        let len = u16::from_le_bytes(take(2)?.try_into()?) as usize;
        let proof = base64::engine::general_purpose::STANDARD.encode(take(len)?);
        hops.push(ProofEntry { kind: kind.to_string(), circuit, instance, anchor_height, proof });
    }
    Ok(Record { prev, genesis, hops })
}

fn chunks(tag: &[u8; 4], data: &[u8]) -> Vec<[u8; 512]> {
    let total = data.chunks(CHUNK).count() as u16;
    data.chunks(CHUNK)
        .enumerate()
        .map(|(i, c)| {
            let mut m = [0u8; 512];
            m[0] = 0xF5;
            m[1..5].copy_from_slice(tag);
            m[5..7].copy_from_slice(&(i as u16).to_le_bytes());
            m[7..9].copy_from_slice(&total.to_le_bytes());
            m[HEAD..HEAD + c.len()].copy_from_slice(c);
            m
        })
        .collect()
}

/// Everything `fvk` can read under `tag` in this transaction, reassembled; `None` if nothing.
fn read(tx: &Tx, fvk: &FullViewingKey, tag: &[u8; 4]) -> Option<Vec<u8>> {
    let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let mut parts: Vec<(u16, u16, Vec<u8>)> = Vec::new();
    for a in tx.actions() {
        let Some((_, _, memo)) = try_note_decryption(&IronwoodDomain::for_action(a), &ivk, a) else { continue };
        if memo[0] == 0xF5 && &memo[1..5] == tag {
            parts.push((u16::from_le_bytes([memo[5], memo[6]]), u16::from_le_bytes([memo[7], memo[8]]), memo[HEAD..].to_vec()));
        }
    }
    parts.sort_by_key(|p| p.0);
    let total = parts.first()?.1 as usize;
    (parts.len() == total).then(|| parts.into_iter().flat_map(|p| p.2).collect())
}

struct Built {
    tx: Tx,
    id: [u8; 32],
    prove_secs: f64,
}

fn build(recipient: orchard::Address, record: &[u8], key: &[u8; 32], anchor: orchard::tree::Anchor, pk: &ProvingKey) -> Result<Built> {
    let version = BundleVersion::ironwood_v3();
    let mut b = Builder::new(BundleType::DEFAULT, version, version.default_flags(), anchor).map_err(|e| anyhow!("{e:?}"))?;
    let out = |b: &mut Builder, to: orchard::Address, memo: [u8; 512]| b.add_output(None, to, NoteValue::from_raw(0), memo).map_err(|e| anyhow!("{e:?}"));
    // The transfer itself: the new carrier and the change.
    out(&mut b, recipient, [0u8; 512])?;
    out(&mut b, recipient, [0u8; 512])?;
    // The key, to the new owner. The record, to the address only that key can read.
    for m in chunks(KEY, key) {
        out(&mut b, recipient, m)?;
    }
    let (_, record_addr) = record_keys(key);
    for m in chunks(REC, record) {
        out(&mut b, record_addr, m)?;
    }
    let (unproven, _) = b.build::<i64>(OsRng).map_err(|e| anyhow!("{e:?}"))?.ok_or_else(|| anyhow!("empty bundle"))?;
    let t = Instant::now();
    let proven = unproven.create_proof(pk, OsRng).map_err(|e| anyhow!("{e:?}"))?;
    let prove_secs = t.elapsed().as_secs_f64();
    let tx = proven.prepare(OsRng, [0u8; 32]).finalize().map_err(|e| anyhow!("{e:?}"))?;
    let mut st = blake2b_simd::Params::new().hash_length(32).to_state();
    for a in tx.actions() {
        st.update(&a.cmx().to_bytes());
    }
    Ok(Built { id: st.finalize().as_bytes().try_into().unwrap(), tx, prove_secs })
}

fn size(b: &Tx) -> usize {
    let n = b.actions().len();
    n * (32 * 5 + 580 + 80) + n * 64 + 1 + 8 + 32 + 64 + b.authorization().proof().as_ref().len() + 6
}

fn new_owner() -> (FullViewingKey, orchard::Address) {
    let mut seed = [0u8; 32];
    loop {
        OsRng.fill_bytes(&mut seed);
        if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(seed)) {
            let fvk = FullViewingKey::from(&sk);
            let a = fvk.address_at(0u32, Scope::External);
            return (fvk, a);
        }
    }
}

/// What the owner holding `owner_fvk` can rebuild, starting from transaction `last`.
fn walk_back(chain: &HashMap<[u8; 32], Tx>, last: &[u8; 32], owner_fvk: &FullViewingKey, kind: &str) -> Result<(Lading, usize)> {
    let key_bytes = read(&chain[last], owner_fvk, KEY).ok_or_else(|| anyhow!("no key memo readable with this viewing key"))?;
    let mut key: [u8; 32] = key_bytes[..32].try_into()?;
    let mut at = *last;
    let mut fetched = 0;
    let mut hops_rev: Vec<Vec<ProofEntry>> = Vec::new();
    let genesis;
    loop {
        fetched += 1;
        let tx = chain.get(&at).ok_or_else(|| anyhow!("transaction {} not found", hexs(&at[..6])))?;
        let (fvk, _) = record_keys(&key);
        let bytes = read(tx, &fvk, REC).ok_or_else(|| anyhow!("record not readable with the key in hand"))?;
        let r = unpack_record(&bytes, kind)?;
        hops_rev.push(r.hops);
        match r.prev {
            Some((k, t)) => {
                key = k;
                at = t;
            }
            None => {
                genesis = r.genesis.ok_or_else(|| anyhow!("first record names no genesis"))?;
                break;
            }
        }
    }
    let mut l = Lading::new(&genesis.0, genesis.1);
    for hs in hops_rev.into_iter().rev() {
        l.hops.extend(hs);
    }
    Ok((l, fetched))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        return Err(anyhow!("usage: knotline_feasibility <wallet-copy.db> <server-url>"));
    }
    let conn = open_wallet_copy_sql(&args[1])?;
    let wallet = open_wallet_copy(&args[1], Network::MainNetwork)?;
    let oracle = LightwalletdOracle::new(args[2].clone(), Network::MainNetwork)?;
    let tip = oracle.tip_height()?;
    let anchor = oracle.ironwood_tree_state(tip - 10)?.root;

    // The longest real lading in the copy, and the note it ends at.
    let (json, note_row, txid_internal): (Vec<u8>, i64, Vec<u8>) = conn.query_row(
        "SELECT c.json, n.id, t.txid FROM ext_zecboat_zmap_consignments c \
         JOIN ironwood_received_notes n ON n.id = c.received_note_id \
         JOIN transactions t ON t.id_tx = n.transaction_id ORDER BY length(c.json) DESC LIMIT 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let mut real = Lading::parse(&json).map_err(|e| anyhow!("{e:?}"))?;
    let held = real.hops.len();
    zmap_wake::keys::warm();
    let txid: [u8; 32] = txid_internal.as_slice().try_into()?;
    let note = received_notes_in_tx(Path::new(&args[1]), Network::MainNetwork, &reversed(txid))?
        .into_iter()
        .find(|n| n.row_id == note_row)
        .ok_or_else(|| anyhow!("note not found"))?;
    let ts = oracle.ironwood_tree_state(note.mined_height)?;
    let proof = prove_hop(&witness_at(&wallet, &note, &ts)?).map_err(|e| anyhow!("{e:?}"))?;
    real.hops.push(ProofEntry::from_proof(&proof, note.mined_height));
    let rho_next: Rho = Option::from(Rho::from_bytes(&proof.instance[2].to_repr())).context("rho")?;
    let n = real.hops.len();
    let kind = real.hops[0].kind.clone();
    let want = real.to_bytes();
    let want_hash = lading_hash(&want);
    println!("server {}  tip {tip}\nreal lading: {held} proof(s) held in the copy + 1 proved here = {n} hops, {} bytes as today's record\n", args[2], want.len());

    let version = BundleVersion::ironwood_v3();
    let pk = ProvingKey::build(version.circuit_version());
    let vk = VerifyingKey::build(version.circuit_version());

    // Owners 1..=n+1. Transfer j (1-based) goes from owner j to owner j+1 and publishes hop j.
    let owners: Vec<(FullViewingKey, orchard::Address)> = (0..=n).map(|_| new_owner()).collect();
    let mut chain: HashMap<[u8; 32], Tx> = HashMap::new();
    let mut keys: Vec<[u8; 32]> = Vec::new();
    let mut ids: Vec<[u8; 32]> = Vec::new();
    println!("{:>9} {:>8} {:>6} {:>8} {:>9} {:>9} {:>8}", "transfer", "record B", "memos", "actions", "tx bytes", "fee ZEC", "prove s");
    for j in 0..n {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        let prev = (j > 0).then(|| (&keys[j - 1], &ids[j - 1]));
        let genesis = (j == 0).then(|| (real.genesis.txid.as_str(), real.genesis.action_index));
        let record = pack_record(prev, genesis, &real.hops[j..j + 1])?;
        let built = build(owners[j + 1].1, &record, &k, anchor, &pk)?;
        built.tx.verify_proof(&vk).map_err(|e| anyhow!("bundle proof does not verify: {e:?}"))?;
        let a = built.tx.actions().len();
        println!("{:>9} {:>8} {:>6} {:>8} {:>9} {:>9.5} {:>8.1}", format!("hop {}", j + 1), record.len(), chunks(REC, &record).len() + 1, a, size(&built.tx), a as f64 * 5000.0 / 1e8, built.prove_secs);
        chain.insert(built.id, built.tx);
        keys.push(k);
        ids.push(built.id);
    }

    // The last owner reads back.
    let t = Instant::now();
    let (rebuilt, fetched) = walk_back(&chain, &ids[n - 1], &owners[n].0, &kind)?;
    let bytes = rebuilt.to_bytes();
    let walk = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let verdict = match verify_chain(&bytes, Some(want_hash), &rho_next, &oracle, MIN_DEPTH) {
        Ok(v) => format!("lineage verifies, {} proofs, trust {:?}", v.hops, v.trust),
        // "Not wrong; not yet safe" (WAKE-v1 section 8): the hop proved a moment ago is anchored
        // at the block its note was mined in. If that is the only objection, say so and show
        // that everything else holds.
        Err(zmap_wake::WakeFailure::AnchorTooShallow { hop, depth }) => match verify_chain(&bytes, Some(want_hash), &rho_next, &oracle, depth) {
            Ok(v) => format!(
                "every check passes for all {} proofs (trust {:?}); the newest anchor (hop {}) is {depth} blocks deep and the wallet waits for {MIN_DEPTH} before calling it verified",
                v.hops, v.trust, hop + 1
            ),
            Err(e) => format!("LINEAGE FAILED even ignoring depth: {e:?}"),
        },
        Err(e) => format!("LINEAGE FAILED: {e:?}"),
    };
    println!("\nlast owner: read the key, walked back {fetched} transactions in {walk:.2}s; rebuilt record is byte-identical to today's: {}; hash matches: {}", bytes == want, lading_hash(&bytes) == want_hash);
    println!("            {verdict} ({:.1}s)", t.elapsed().as_secs_f64());

    // Who cannot read what.
    println!("\nwho cannot read:");
    let stranger = new_owner().0;
    println!("  a stranger, on the last transfer: {}", match walk_back(&chain, &ids[n - 1], &stranger, &kind) { Ok(_) => "READ IT (BAD)".to_string(), Err(e) => format!("nothing ({e})") });
    if n >= 2 {
        // Owner n-1 sent transfer n-1, so holds keys 1..n-1 and their own viewing key, not key n.
        let past = &owners[n - 1].0;
        println!("  the previous owner's viewing key, on the last transfer: {}", match walk_back(&chain, &ids[n - 1], past, &kind) { Ok(_) => "READ IT (BAD)".to_string(), Err(e) => format!("nothing ({e})") });
        let (fvk_old, _) = record_keys(&keys[n - 2]);
        println!("  the previous record's key, on the last transfer's record: {}", match read(&chain[&ids[n - 1]], &fvk_old, REC) { Some(_) => "READ IT (BAD)", None => "nothing" });
        println!("  the previous record's key, on its own record (must work): {}", match read(&chain[&ids[n - 2]], &fvk_old, REC) { Some(b) => format!("{} bytes", b.len()), None => "NOTHING (BAD)".to_string() });
    }
    let (fvk_last, _) = record_keys(&keys[n - 1]);
    let mut tampered = keys[n - 1];
    tampered[0] ^= 1;
    println!("  the last key with one bit changed: {}", match read(&chain[&ids[n - 1]], &record_keys(&tampered).0, REC) { Some(_) => "READ IT (BAD)", None => "nothing" });
    let _ = fvk_last;

    // An existing item joins the scheme: its history so far is published once.
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    let boot = pack_record(None, Some((real.genesis.txid.as_str(), real.genesis.action_index)), &real.hops[..])?;
    let built = build(owners[n].1, &boot, &k, anchor, &pk)?;
    let a = built.tx.actions().len();
    println!("\nan item with {n} hops of history joining the scheme, once: record {} bytes, {} memos, {a} actions, {} tx bytes, fee {:.5} ZEC, proved in {:.1}s", boot.len(), chunks(REC, &boot).len() + 1, size(&built.tx), a as f64 * 5000.0 / 1e8, built.prove_secs);
    Ok(())
}
