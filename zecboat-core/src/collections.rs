//! A3b (v0.7.0): Find collections — the Zecboat Registry read by the wallet itself.
//!
//! The registry's viewing key, address and birthday have been pinned in `issuance_v1.rs` since
//! A1b; nothing read them. This module does:
//!
//! 1. keeps a **separate** view-only wallet, `registry.db` ([`crate::paths::registry_db_path`]),
//!    with one account imported from the pinned `REGISTRY_UFVK`. The user's `wallet.db` is never
//!    opened here;
//! 2. syncs it with the wallet's own engine ([`crate::rpc::sync_pass`]), whose tip step fetches
//!    each received transaction in full, so the registrations' memos are stored;
//! 3. parses every registration from those memos and checks it, as the published format says.
//!
//! # Written from the spec, not from the mint
//!
//! `~/zecboat_mint_wake/BOUNDARY.md` rule 3: the ZMAP formats are implemented twice, from the
//! written spec, so each side is a second opinion on the other. This file follows
//! `~/collections/audit/METHODOLOGY.md` §3 and was not written from the mint's `registry.rs`.
//! Agreement with the mint's `registry-scan` is checked by test, not assumed.
//!
//! ```text
//! header "zmap:registry:v1"(16) ‖ ik(32) ‖ sha256(UFVK)(32) ‖ close_txid(32, display order)
//!        ‖ mint_height(4) ‖ close_height(4) ‖ sha256(manifest)(32) ‖ sig(64) ‖ name (UTF-8)
//!        sig = BIP-340 under ik over every header byte except sig
//! chunk  "zmap:chunk:v1"(13) ‖ kind(1) ‖ index(2) ‖ total(2) ‖ ≤494 bytes;  kind 2 = the UFVK
//! ```
//! Integers big-endian; trailing zero padding of a memo is ignored.
//!
//! What a listed registration means: the holder of `ik` registered this viewing key. Nothing
//! about the collection's honesty; that is the audit's job (phase 2).

use anyhow::{anyhow, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::issuance_v1::{verify_bip340, REGISTRY_BIRTHDAY, REGISTRY_UFVK};

pub const HEADER_PREFIX: &[u8; 16] = b"zmap:registry:v1";
pub const CHUNK_PREFIX: &[u8; 13] = b"zmap:chunk:v1";
pub const KIND_UFVK: u8 = 2;
/// Fixed part of a header, before the name.
const HEADER_FIXED: usize = 16 + 32 + 32 + 32 + 4 + 4 + 32 + 64;
const SIG_AT: usize = 16 + 32 + 32 + 32 + 4 + 4 + 32;
const CHUNK_HEADER: usize = 13 + 1 + 2 + 2;
const CHUNK_BODY_MAX: usize = 494;
/// The first chunk's index. `METHODOLOGY.md` §3 does not say; settled from the real registry's
/// on-chain bytes (see `chunk_index_base_matches_the_chain`).
pub const CHUNK_INDEX_BASE: u16 = 0;

/// A registration header, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub ik: [u8; 32],
    pub ufvk_sha256: [u8; 32],
    /// Display order (as a block explorer shows it).
    pub close_txid: [u8; 32],
    pub mint_height: u32,
    pub close_height: u32,
    pub manifest_sha256: [u8; 32],
    pub sig: [u8; 64],
    pub name: String,
    /// The bytes the signature covers: the header without its 64 signature bytes.
    signed: Vec<u8>,
}

/// Strip a memo's trailing zero padding.
pub fn trim(memo: &[u8]) -> &[u8] {
    let end = memo.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    &memo[..end]
}

fn arr<const N: usize>(b: &[u8]) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(b);
    a
}

/// Parse a registration header, or `None` if the memo is not one. Never panics on any input.
pub fn parse_header(memo: &[u8]) -> Option<Header> {
    let m = trim(memo);
    if m.len() <= HEADER_FIXED || &m[..16] != HEADER_PREFIX {
        return None;
    }
    let name = std::str::from_utf8(&m[HEADER_FIXED..]).ok()?.to_string();
    let mut signed = m[..SIG_AT].to_vec();
    signed.extend_from_slice(&m[HEADER_FIXED..]);
    Some(Header {
        ik: arr(&m[16..48]),
        ufvk_sha256: arr(&m[48..80]),
        close_txid: arr(&m[80..112]),
        mint_height: u32::from_be_bytes(arr(&m[112..116])),
        close_height: u32::from_be_bytes(arr(&m[116..120])),
        manifest_sha256: arr(&m[120..152]),
        sig: arr(&m[SIG_AT..HEADER_FIXED]),
        name,
        signed,
    })
}

impl Header {
    /// BIP-340 under the header's own `ik`, over every header byte except the signature.
    pub fn signature_ok(&self) -> bool {
        verify_bip340(&self.ik, &self.signed, &self.sig)
    }
}

/// One chunk: `(kind, index, total, body)`.
pub fn parse_chunk(memo: &[u8]) -> Option<(u8, u16, u16, Vec<u8>)> {
    let m = trim(memo);
    if m.len() <= CHUNK_HEADER || m.len() > CHUNK_HEADER + CHUNK_BODY_MAX || &m[..13] != CHUNK_PREFIX {
        return None;
    }
    let kind = m[13];
    let index = u16::from_be_bytes([m[14], m[15]]);
    let total = u16::from_be_bytes([m[16], m[17]]);
    Some((kind, index, total, m[CHUNK_HEADER..].to_vec()))
}

/// Reassemble the chunks of `kind` from one transaction's memos. Orchard shuffles actions, so
/// order comes from the index. A gap, a duplicate, an inconsistent total or no chunks at all is
/// an error, never a partial result.
pub fn reassemble(kind: u8, memos: &[Vec<u8>]) -> std::result::Result<Vec<u8>, String> {
    let chunks: Vec<(u16, u16, Vec<u8>)> = memos
        .iter()
        .filter_map(|m| parse_chunk(m))
        .filter(|c| c.0 == kind)
        .map(|(_, i, t, b)| (i, t, b))
        .collect();
    if chunks.is_empty() {
        return Err("no chunks".into());
    }
    let total = chunks[0].1;
    if total == 0 || chunks.iter().any(|c| c.1 != total) {
        return Err("chunks disagree on their total".into());
    }
    let mut by_index: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
    for (i, _, b) in chunks {
        if by_index.insert(i, b).is_some() {
            return Err(format!("duplicate chunk {i}"));
        }
    }
    let expected: Vec<u16> = (0..total).map(|k| k + CHUNK_INDEX_BASE).collect();
    let got: Vec<u16> = by_index.keys().copied().collect();
    if got != expected {
        return Err(format!("chunks {got:?}, expected {} numbered from {CHUNK_INDEX_BASE}", total));
    }
    Ok(by_index.into_values().flatten().collect())
}

/// One registration, as the wallet shows it.
#[derive(Debug, Clone, Serialize)]
pub struct Registration {
    pub name: String,
    pub ik: String,
    pub registration_txid: String,
    pub registration_height: u32,
    pub close_txid: String,
    pub mint_height: u32,
    pub close_height: u32,
    pub manifest_sha256: String,
    /// The collection's issuance viewing key, reassembled from the chunks, when complete.
    pub ufvk: Option<String>,
    pub signature_ok: bool,
    pub ufvk_hash_ok: bool,
    /// Both checks passed.
    pub valid: bool,
    /// Why it is invalid, when it is.
    pub reason: Option<String>,
}

/// Every registration in one transaction's memos. A transaction normally carries one.
pub fn registrations_in_tx(txid_display: &str, height: u32, memos: &[Vec<u8>]) -> Vec<Registration> {
    let ufvk = reassemble(KIND_UFVK, memos);
    memos
        .iter()
        .filter_map(|m| parse_header(m))
        .map(|h| {
            let signature_ok = h.signature_ok();
            let (ufvk_str, ufvk_hash_ok, ufvk_err) = match &ufvk {
                Ok(bytes) => match String::from_utf8(bytes.clone()) {
                    Ok(s) => {
                        let ok = <[u8; 32]>::from(Sha256::digest(s.as_bytes())) == h.ufvk_sha256;
                        (Some(s), ok, None)
                    }
                    Err(_) => (None, false, Some("viewing key is not text".to_string())),
                },
                Err(e) => (None, false, Some(format!("viewing key incomplete: {e}"))),
            };
            let reason = if !signature_ok {
                Some("signature does not verify under its ik".to_string())
            } else if let Some(e) = ufvk_err {
                Some(e)
            } else if !ufvk_hash_ok {
                Some("viewing key does not match the hash the header commits to".to_string())
            } else {
                None
            };
            Registration {
                name: h.name.clone(),
                ik: hex::encode(h.ik),
                registration_txid: txid_display.to_string(),
                registration_height: height,
                close_txid: hex::encode(h.close_txid),
                mint_height: h.mint_height,
                close_height: h.close_height,
                manifest_sha256: hex::encode(h.manifest_sha256),
                ufvk: ufvk_str,
                signature_ok,
                ufvk_hash_ok,
                valid: reason.is_none(),
                reason,
            }
        })
        .collect()
}

// ── the registry database ────────────────────────────────────────────────────────────────────

fn registry_db() -> Result<String> {
    Ok(crate::paths::registry_db_path()?.to_string_lossy().into_owned())
}

/// Read every registration held in `registry.db`. No network.
pub fn read_registrations(db_path: &str) -> Result<Vec<Registration>> {
    if !std::path::Path::new(db_path).exists() {
        return Ok(vec![]);
    }
    let conn = rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let has_view: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='v_received_outputs'",
        [],
        |r| r.get(0),
    )?;
    if has_view == 0 {
        return Ok(vec![]);
    }
    let mut stmt = conn.prepare(
        "SELECT t.txid, t.mined_height, v.memo
           FROM v_received_outputs v
           JOIN transactions t ON t.id_tx = v.transaction_id
          WHERE v.memo IS NOT NULL AND t.mined_height IS NOT NULL
          ORDER BY t.mined_height, t.id_tx",
    )?;
    let rows: Vec<(Vec<u8>, u32, Vec<u8>)> =
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
    let mut by_tx: BTreeMap<(u32, Vec<u8>), Vec<Vec<u8>>> = BTreeMap::new();
    for (txid, h, memo) in rows {
        by_tx.entry((h, txid)).or_default().push(memo);
    }
    let mut out = Vec::new();
    for ((h, mut txid), memos) in by_tx {
        txid.reverse();
        out.extend(registrations_in_tx(&hex::encode(txid), h, &memos));
    }
    Ok(out)
}

/// Create `registry.db` and its one view-only account from the pinned key, if not done yet.
async fn ensure_registry_account(db_path: &str) -> Result<()> {
    use zcash_client_backend::data_api::{chain::ChainState, AccountBirthday, AccountPurpose, WalletRead, WalletWrite};
    use zcash_client_sqlite::{util::SystemClock, WalletDb};
    use zcash_keys::keys::UnifiedFullViewingKey;
    use zcash_protocol::consensus::MainNetwork;

    if let Some(dir) = std::path::Path::new(db_path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let has_account = {
        let mut db = WalletDb::for_path(db_path, MainNetwork, SystemClock, rand::rngs::OsRng)
            .map_err(|e| anyhow!("could not open the registry database: {e:?}"))?;
        zcash_client_sqlite::wallet::init::init_wallet_db(&mut db, None)
            .map_err(|e| anyhow!("could not initialise the registry database: {e:?}"))?;
        !db.get_account_ids().map_err(|e| anyhow!("{e:?}"))?.is_empty()
    };
    if has_account {
        return Ok(());
    }
    let ufvk = UnifiedFullViewingKey::decode(&MainNetwork, REGISTRY_UFVK)
        .map_err(|e| anyhow!("the pinned registry key does not decode: {e}"))?;

    let endpoint = crate::rpc::grpc_endpoint();
    let mut client = zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("could not reach the node at {endpoint}: {e}"))?;
    let ts = client
        .get_tree_state(tonic::Request::new(zcash_client_backend::proto::service::BlockId {
            height: u64::from(REGISTRY_BIRTHDAY - 1),
            hash: vec![],
        }))
        .await
        .map_err(|e| anyhow!("cannot read the tree state at {}: {e}", REGISTRY_BIRTHDAY - 1))?
        .into_inner();
    let cs: ChainState = ts.to_chain_state().map_err(|e| anyhow!("malformed tree state: {e:?}"))?;

    let mut db = WalletDb::for_path(db_path, MainNetwork, SystemClock, rand::rngs::OsRng)
        .map_err(|e| anyhow!("could not open the registry database: {e:?}"))?;
    db.import_account_ufvk("Zecboat Registry", &ufvk, &AccountBirthday::from_parts(cs, None), AccountPurpose::ViewOnly, None)
        .map_err(|e| anyhow!("could not import the registry key: {e:?}"))?;
    println!("[collections] registry view-only account created, birthday {REGISTRY_BIRTHDAY}");
    Ok(())
}

/// One scan at a time: the UI's Refresh can be pressed twice.
static SCANNING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// What the Collections view shows.
#[derive(Debug, Clone, Serialize)]
pub struct RegistryView {
    /// Height the registry was read to; 0 if never scanned.
    pub scanned_to: u32,
    /// The node that answered.
    pub node: String,
    pub registrations: Vec<Registration>,
}

fn scanned_height(db_path: &str) -> u32 {
    rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .and_then(|c| c.query_row("SELECT COALESCE(MAX(height),0) FROM blocks", [], |r| r.get::<_, u32>(0)))
        .unwrap_or(0)
}

/// The registry as last scanned. No network.
pub fn registry_view() -> Result<RegistryView> {
    let db = registry_db()?;
    Ok(RegistryView { scanned_to: scanned_height(&db), node: crate::rpc::grpc_endpoint(), registrations: read_registrations(&db)? })
}

/// Bring `registry.db` level with the chain, then list the registrations.
pub async fn scan_registry() -> Result<RegistryView> {
    let _one = SCANNING.try_lock().map_err(|_| anyhow!("a registry scan is already running"))?;
    let db = registry_db()?;
    ensure_registry_account(&db).await?;

    let mut retreat = 0usize;
    let mut settled = 0u32;
    for _ in 0..10_000 {
        match crate::rpc::sync_pass(&db).await? {
            crate::rpc::SyncStep::Advanced(_) => {}
            crate::rpc::SyncStep::AtTip(_) => {
                // At the tip, sync_pass services the backend's requests, which is where the
                // registrations' full transactions (and so their memos) are fetched. A second
                // pass at the tip settles anything the first one queued.
                settled += 1;
                if settled >= 2 {
                    break;
                }
            }
            crate::rpc::SyncStep::Continuity(at) => {
                let steps = crate::rpc::SYNC_RETREAT_STEPS;
                let target = u32::from(at).saturating_sub(steps[retreat.min(steps.len() - 1)]).max(REGISTRY_BIRTHDAY);
                println!("[collections] divergence at {}; rewinding the registry to {target}", u32::from(at));
                crate::rpc::truncate_wallet_to(&db, target)?;
                retreat += 1;
            }
        }
    }
    registry_view()
}

// ── phase 3: what this wallet holds ──────────────────────────────────────────────────────────

/// Units of one collection held in this wallet.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Held {
    /// Unspent carriers whose memo names this collection's `ik` and whose id recomputes.
    pub count: usize,
    pub asset_ids: Vec<String>,
    /// Carriers naming this `ik` whose id does NOT recompute from ik + desc (a forged memo).
    pub bad_ids: usize,
}

/// Group carrier memos by the collection key they name. Pure; used by [`holdings_by_ik`].
/// A name reduced for comparison: lower case, letters and digits only, with the common
/// Cyrillic and Greek look-alikes folded onto their Latin twins. Two registrations whose
/// skeletons match but whose keys differ are shown as look-alikes (review 2026-10-09,
/// session 4, Issue A). A short table, not UTS #39: it catches the cheap cases.
pub fn name_skeleton(name: &str) -> String {
    // Unicode lower case first (capital Cyrillic and Greek fold to the lower-case rows below;
    // Latin I folds to i and then to l), and fullwidth forms onto ASCII (review 2026-10-09,
    // regression over 12-13, Issue F).
    let lowered: String = name
        .to_lowercase()
        .chars()
        .map(|c| match c as u32 {
            0xFF01..=0xFF5E => char::from_u32(c as u32 - 0xFF01 + 0x21).unwrap_or(c),
            _ => c,
        })
        .collect();
    lowered
        .chars()
        .filter_map(|c| {
            let c = match c {
                'а' | 'α' => 'a', 'е' | 'ε' => 'e', 'о' | 'ο' => 'o', 'р' | 'ρ' => 'p', 'с' | 'ϲ' => 'c', 'х' | 'χ' => 'x',
                'у' | 'υ' => 'y', 'ј' => 'j', 'ѕ' => 's', 'ԁ' => 'd', 'ν' => 'v', 'к' | 'κ' => 'k', 'т' | 'τ' => 't',
                'н' => 'h', 'в' => 'b', 'м' => 'm', '0' => 'o',
                // i, l, 1 and their look-alikes are one letter for this purpose ("BarceIona").
                'i' | 'і' | 'ι' | 'ⅼ' | 'ӏ' | '1' | 'l' => 'l',
                other => other,
            };
            let c = c.to_ascii_lowercase();
            c.is_ascii_alphanumeric().then_some(c)
        })
        .collect()
}

pub fn group_held(memos: &[Vec<u8>]) -> std::collections::HashMap<String, Held> {
    // One strict reading of a memo, the item list's (`parse_memo`): duplicate keys and
    // upper-case ids are refused there, and used to be accepted here (review 2026-10-09,
    // session 4, Issue E). `parse_memo` already refuses a v1 memo whose id does not derive, so
    // `bad_ids` counts memos that name this key and fail that reading.
    let mut out: std::collections::HashMap<String, Held> = std::collections::HashMap::new();
    for m in memos {
        let text = trim(m);
        if text.first() != Some(&b'{') {
            continue;
        }
        match crate::zmap::parse_memo(text) {
            Some(r) => {
                let (Some(ik), Some(_)) = (r.ik.as_deref(), r.desc.as_deref()) else { continue };
                let e = out.entry(ik.to_ascii_lowercase()).or_default();
                e.count += 1;
                e.asset_ids.push(r.asset_id.to_ascii_lowercase());
            }
            None => {
                let Ok(j) = serde_json::from_slice::<serde_json::Value>(text) else { continue };
                if let (Some(ik), Some(_), Some(_)) = (j["ik"].as_str(), j["asset_id"].as_str(), j["desc"].as_str()) {
                    out.entry(ik.to_ascii_lowercase()).or_default().bad_ids += 1;
                }
            }
        }
    }
    out
}

/// What the user's own wallet holds, per collection key. Reads `wallet.db` read-only; nothing is
/// written there. Only unspent 10,000-zat carriers count.
pub fn holdings_by_ik() -> Result<std::collections::HashMap<String, Held>> {
    let path = crate::paths::wallet_db_path()?;
    if !path.exists() {
        return Ok(Default::default());
    }
    let conn = rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let rows = crate::zmap::read_carrier_rows(&conn)?;
    let memos: Vec<Vec<u8>> = rows.into_iter().filter_map(|r| r.memo).collect();
    Ok(group_held(&memos))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a header exactly as METHODOLOGY.md §3 describes, signed with `secret`.
    fn header(secret: &[u8; 32], ufvk: &str, name: &str) -> Vec<u8> {
        use k256::schnorr::signature::Signer;
        let sk = k256::schnorr::SigningKey::from_bytes(secret).unwrap();
        let ik: [u8; 32] = sk.verifying_key().to_bytes().into();
        let mut fixed = Vec::new();
        fixed.extend_from_slice(HEADER_PREFIX);
        fixed.extend_from_slice(&ik);
        fixed.extend_from_slice(&Sha256::digest(ufvk.as_bytes()));
        fixed.extend_from_slice(&[0xab; 32]);
        fixed.extend_from_slice(&3_498_971u32.to_be_bytes());
        fixed.extend_from_slice(&3_498_974u32.to_be_bytes());
        fixed.extend_from_slice(&[0xcd; 32]);
        let mut signed = fixed.clone();
        signed.extend_from_slice(name.as_bytes());
        let sig: k256::schnorr::Signature = sk.sign(&signed);
        let mut m = fixed;
        m.extend_from_slice(&sig.to_bytes());
        m.extend_from_slice(name.as_bytes());
        m.resize(512, 0);
        m
    }

    fn chunks(kind: u8, data: &[u8]) -> Vec<Vec<u8>> {
        let parts: Vec<&[u8]> = data.chunks(CHUNK_BODY_MAX).collect();
        parts
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mut m = CHUNK_PREFIX.to_vec();
                m.push(kind);
                m.extend_from_slice(&(i as u16 + CHUNK_INDEX_BASE).to_be_bytes());
                m.extend_from_slice(&(parts.len() as u16).to_be_bytes());
                m.extend_from_slice(p);
                m.resize(512, 0);
                m
            })
            .collect()
    }

    const SECRET: [u8; 32] = [7u8; 32];
    const UFVK: &str = "uview1-not-a-real-key-but-long-enough-to-need-two-chunks-when-repeated";

    fn tx(name: &str, ufvk: &str) -> Vec<Vec<u8>> {
        let long = ufvk.repeat(10);
        let mut memos = vec![header(&SECRET, &long, name)];
        let mut c = chunks(KIND_UFVK, long.as_bytes());
        c.reverse(); // actions are shuffled
        memos.extend(c);
        memos
    }

    #[test]
    fn a_well_formed_registration_is_valid() {
        let r = registrations_in_tx(&"11".repeat(32), 3_498_977, &tx("Lagos Post Card", UFVK));
        assert_eq!(r.len(), 1);
        let r = &r[0];
        assert!(r.signature_ok && r.ufvk_hash_ok && r.valid, "{r:?}");
        assert_eq!(r.name, "Lagos Post Card");
        assert_eq!((r.mint_height, r.close_height), (3_498_971, 3_498_974));
        assert_eq!(r.ufvk.as_deref(), Some(UFVK.repeat(10).as_str()));
    }

    #[test]
    fn an_altered_header_fails_its_signature() {
        let mut memos = tx("Lagos Post Card", UFVK);
        memos[0][112] ^= 1; // the mint height
        let r = &registrations_in_tx("00", 1, &memos)[0];
        assert!(!r.signature_ok && !r.valid);
        let mut memos = tx("Lagos Post Card", UFVK);
        memos[0][HEADER_FIXED] = b'X'; // the name
        assert!(!registrations_in_tx("00", 1, &memos)[0].valid, "renamed");
    }

    #[test]
    fn a_swapped_viewing_key_fails_its_hash() {
        let mut memos = vec![tx("A", UFVK)[0].clone()];
        memos.extend(chunks(KIND_UFVK, "uview1-someone-else".as_bytes()));
        let r = &registrations_in_tx("00", 1, &memos)[0];
        assert!(r.signature_ok && !r.ufvk_hash_ok && !r.valid);
    }

    #[test]
    fn missing_duplicate_and_inconsistent_chunks_are_refused() {
        let full = tx("A", UFVK);
        let mut missing = full.clone();
        missing.remove(1);
        assert!(registrations_in_tx("00", 1, &missing)[0].reason.as_deref().unwrap().contains("incomplete"));
        let mut dup = full.clone();
        dup.push(full[1].clone());
        assert!(!registrations_in_tx("00", 1, &dup)[0].valid);
        let mut bad_total = full.clone();
        bad_total[1][17] ^= 1;
        assert!(!registrations_in_tx("00", 1, &bad_total)[0].valid);
    }

    /// Anyone can send to the registry. A registration claiming someone else's ik must fail.
    #[test]
    fn held_memos_are_read_by_the_one_strict_parser() {
        // Duplicate keys and upper-case ids are refused by the item list's parser; Collections
        // used to read them with a lenient one and count them (review 2026-10-09, session 4,
        // Issue E).
        let ik = [7u8; 32];
        let desc = "zmap-desc-v1|Coll|1|Coll #001|CL|".to_string() + &"a".repeat(64);
        let id = crate::issuance_v1::derive_asset_id(&ik, &desc);
        let good = format!(r#"{{"asset_id":"{id}","ik":"{}","desc":"{desc}"}}"#, hex::encode(ik));
        let upper = good.replace(&id, &id.to_ascii_uppercase());
        let dup = format!(r#"{{"asset_id":"{id}","ik":"{}","desc":"other","desc":"{desc}"}}"#, hex::encode(ik));
        let forged = good.replace(&id[..8], "deadbeef");
        let held = group_held(&[good.into_bytes(), upper.into_bytes(), dup.into_bytes(), forged.into_bytes()]);
        let h = &held[&hex::encode(ik)];
        // One genuine memo counts; every memo naming this key that the strict reader refuses
        // (a forged id, an upper-case id, duplicate keys) is flagged, none is counted as held.
        assert_eq!((h.count, h.bad_ids), (1, 3));
        assert_eq!(name_skeleton("Lagоs Post Card"), name_skeleton("Lagos Post Card"), "Cyrillic о folds onto o");
        for look_alike in ["Lagos Роst Card", "LАGOS POST CARD", "Lagos Ρost Card", "Ｌａｇｏｓ Post Card", "BarceIona Post Card"] {
            let target = if look_alike.starts_with("Barce") { "Barcelona Post Card" } else { "Lagos Post Card" };
            assert_eq!(name_skeleton(look_alike), name_skeleton(target), "{look_alike}");
        }
        assert_ne!(name_skeleton("Lagos Post Card"), name_skeleton("Lagos Post Card 2"));
    }

    #[test]
    fn a_registration_under_someone_elses_ik_fails() {
        let mut memos = tx("Lagos Post Card", UFVK);
        let other = k256::schnorr::SigningKey::from_bytes(&[9u8; 32]).unwrap();
        memos[0][16..48].copy_from_slice(&<[u8; 32]>::from(other.verifying_key().to_bytes()));
        assert!(!registrations_in_tx("00", 1, &memos)[0].signature_ok);
    }

    /// Malformed memos: never a panic, never a registration.
    #[test]
    fn garbage_never_panics() {
        let mut inputs: Vec<Vec<u8>> = vec![vec![], vec![0; 512], HEADER_PREFIX.to_vec(), CHUNK_PREFIX.to_vec()];
        for n in [17usize, 100, 215, 216, 217, 400, 512] {
            let mut m = HEADER_PREFIX.to_vec();
            m.resize(n, 0xff);
            inputs.push(m);
        }
        let mut m = CHUNK_PREFIX.to_vec();
        m.extend_from_slice(&[2, 0xff, 0xff, 0, 0]);
        inputs.push(m);
        for i in &inputs {
            let _ = parse_header(i);
            let _ = parse_chunk(i);
        }
        assert!(registrations_in_tx("00", 1, &inputs).iter().all(|r| !r.valid));
    }

    fn carrier(ik_secret: &[u8; 32], unit: u32, forge: bool) -> Vec<u8> {
        let sk = k256::schnorr::SigningKey::from_bytes(ik_secret).unwrap();
        let ik: [u8; 32] = sk.verifying_key().to_bytes().into();
        let desc = format!("zmap-desc-v1|Lagos Post Card|{unit}|Lagos Post Card #{unit:03}|LPC|{}", "ab".repeat(32));
        let id = if forge { "00".repeat(32) } else { crate::issuance_v1::derive_asset_id(&ik, &desc) };
        serde_json::to_vec(&serde_json::json!({"asset_id": id, "ik": hex::encode(ik), "desc": desc, "name": "x", "symbol": "LPC", "decimals": 0})).unwrap()
    }

    #[test]
    fn holdings_group_by_key_and_refuse_forged_ids() {
        let mut memos = vec![carrier(&SECRET, 1, false), carrier(&SECRET, 7, false), carrier(&SECRET, 9, true)];
        memos.push(carrier(&[9u8; 32], 1, false)); // another collection
        memos.push(b"plain text memo".to_vec());
        memos.push(b"{not json".to_vec());
        let g = group_held(&memos);
        assert_eq!(g.len(), 2);
        let sk = k256::schnorr::SigningKey::from_bytes(&SECRET).unwrap();
        let ik = hex::encode(<[u8; 32]>::from(sk.verifying_key().to_bytes()));
        let h = &g[&ik];
        assert_eq!((h.count, h.bad_ids), (2, 1), "two real units, one forged id not counted");
    }

    #[test]
    fn trim_only_strips_trailing_zeros() {
        assert_eq!(trim(&[1, 0, 2, 0, 0]), &[1, 0, 2]);
        assert_eq!(trim(&[0, 0]), &[] as &[u8]);
    }
}
