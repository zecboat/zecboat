//! ZMAP — the Zcash Memo Asset Protocol (ZRC-721) — Layer-2 shielded-asset detection.
//!
//! # What a ZMAP asset actually is
//!
//! There is **no protocol-level asset support** on Zcash today. `orchard 0.15.3` carries the
//! Ironwood pool but has zero `AssetBase` references, and every attempt in this project's history to
//! emit a real issuance bundle was silently dropped by the builder — `final_batch_tx.hex` is a v5
//! transaction with no issuance bundle at all.
//!
//! So a ZMAP asset is exactly two things:
//!
//! 1. a **carrier note** of exactly [`CARRIER_ZAT`] zatoshi — the dust floor that stops the note
//!    being swept as change, and
//! 2. a **memo** naming the asset.
//!
//! Nothing else. Identity lives in the memo and nowhere else, which is why this module refuses to
//! call anything an asset unless *both* conditions hold. The previous implementation checked only
//! the memo, so an ordinary payment whose memo happened to contain the text `asset_id` was reported
//! as an asset.
//!
//! # Two memo dialects
//!
//! **JSON** — the forward format. Carries identity *and* metadata location on chain, so no
//! collection registry is needed:
//!
//! ```text
//! {"asset_id":"<64 hex>","name":"…","symbol":"…","decimals":0,"metadata_uri":"https://…"}
//! ```
//!
//! **Legacy prose** — the 2026 Cyber-Nomad and ZecOil collections:
//!
//! ```text
//! ZecBoat Cyber-Nomad #001. Image Hash: <64 hex>. Backing: 10,000 Zats.
//! ```
//!
//! # Which identifier
//!
//! Three incompatible schemes exist in the wild for the same legacy asset, and they were never
//! reconciled: the Glass indexer derived `sha256(full memo text)`, the published registry uses
//! `sha256("ZecBoat_CyberNomads_<NNN>")`, and the memo itself carries the image hash. The public
//! Glass README's own worked example 404s because of this.
//!
//! **This module canonicalises on the image hash** for legacy memos: it is the only one of the three
//! actually present in the memo, and it is content-addressed, so a holder can verify the artwork
//! without trusting anyone. Registry lookups for known collections are derived separately in
//! [`KnownCollection`] — a per-collection constant, not a per-asset table.
//!
//! # Quantity, not uniqueness
//!
//! Semi-fungible editions are a planned product: many carriers, one identical memo. Holdings are
//! therefore **grouped by `asset_id` and counted**. Assuming one note per asset works only for 1-of-1
//! collections and silently under-reports everything else.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use zcash_client_backend::wallet::{LockOwner, OutputRef};
use zcash_protocol::{PoolType, ShieldedPool, TxId};

/// The ZMAP carrier value. Exact — not a minimum.
///
/// 10,000 zatoshi (0.0001 ZEC) is the standard's dust floor: below it a wallet may sweep the note as
/// change and destroy the asset with it.
pub const CARRIER_ZAT: u64 = 10_000;

/// `v_received_outputs.pool` codes, confirmed against the live wallet schema.
pub const POOL_TRANSPARENT: i64 = 0;
pub const POOL_SAPLING: i64 = 2;
pub const POOL_ORCHARD: i64 = 3;
pub const POOL_IRONWOOD: i64 = 4;

pub fn pool_name(pool: i64) -> &'static str {
    match pool {
        POOL_TRANSPARENT => "transparent",
        POOL_SAPLING => "sapling",
        POOL_ORCHARD => "orchard",
        POOL_IRONWOOD => "ironwood",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dialect {
    /// `{"asset_id":…}` — identity and metadata location both on chain.
    Json,
    /// `<Name>. Image Hash: <hex>. Backing: …` — identity on chain, metadata by convention.
    LegacyProse,
}

/// One asset record parsed from a single memo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZmapRecord {
    /// Canonical identity. JSON dialect: the memo's `asset_id`. Legacy: the image hash.
    pub asset_id: String,
    pub name: String,
    pub symbol: Option<String>,
    pub decimals: u8,
    /// Where the metadata JSON lives, if the memo says or the collection is known.
    pub metadata_uri: Option<String>,
    /// SHA-256 of the artwork, when the memo commits to one. Enables zero-trust verification.
    pub image_hash: Option<String>,
    pub dialect: Dialect,
}

/// A carrier note backing a holding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrierRef {
    pub pool: i64,
    pub pool_name: String,
    pub note_id: i64,
    /// Hex, for display and JSON.
    pub txid: String,
    /// Raw txid, kept for [`OutputRef`] construction. Not serialised — a 32-element JSON array is
    /// no use to the UI, which already has the hex.
    #[serde(skip)]
    pub txid_bytes: [u8; 32],
    pub output_index: i64,
    /// The carrier's memo, exactly as stored.
    ///
    /// A transfer spends this note and writes the **same bytes** to the new carrier. Re-deriving
    /// the memo from parsed fields would risk changing it — and the memo *is* the asset, so a
    /// different memo is a different asset. Not serialised; the UI has the parsed form.
    #[serde(skip)]
    pub memo: Vec<u8>,
}

/// An aggregated holding: one asset, however many carriers back it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZmapHolding {
    pub asset_id: String,
    pub name: String,
    pub symbol: Option<String>,
    pub decimals: u8,
    pub metadata_uri: Option<String>,
    pub image_hash: Option<String>,
    pub dialect: Dialect,
    /// Number of unspent carrier notes. **Not assumed to be 1.**
    pub quantity: u64,
    pub carriers: Vec<CarrierRef>,
}

/// Per-collection constants for legacy prose memos, which do not carry a metadata URI.
///
/// This is deliberately a *collection* table, not an asset table — four entries, not four hundred.
/// New collections should use the JSON dialect and never appear here.
struct KnownCollection {
    /// Memo prefix that identifies the collection.
    prefix: &'static str,
    /// Template for the registry id, `{}` replaced by the zero-padded index.
    id_template: &'static str,
}

const KNOWN_COLLECTIONS: &[KnownCollection] = &[KnownCollection {
    prefix: "ZecBoat Cyber-Nomad #",
    // Verified live 2026-08-13: sha256("ZecBoat_CyberNomads_042") resolves to a real 674-byte
    // metadata JSON whose image_hash matches the memo.
    id_template: "ZecBoat_CyberNomads_{}",
}];

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Derive the published metadata URI for a legacy asset, if its collection is recognised.
///
/// Returns `None` for unknown collections rather than guessing. An unrecognised asset still
/// displays from its memo and still hash-verifies its artwork — it simply shows no enrichment.
fn legacy_metadata_uri(memo_text: &str) -> Option<String> {
    let c = KNOWN_COLLECTIONS.iter().find(|c| memo_text.starts_with(c.prefix))?;
    let rest = &memo_text[c.prefix.len()..];
    let idx: String = rest.chars().take_while(|ch| ch.is_ascii_digit()).collect();
    if idx.is_empty() {
        return None;
    }
    let registry_id = sha256_hex(c.id_template.replace("{}", &idx).as_bytes());
    Some(format!("https://zecboat.com/collection/{}.json", registry_id))
}

/// Recover the printable text of a Zcash memo.
///
/// Handles the three shapes seen in practice:
/// - `0xF6` lead byte — ZIP-302 "no memo". Returns `None`.
/// - full 512-byte padded memos — trailing NULs stripped.
/// - short unpadded memos — this wallet's `v_received_outputs.memo` stores a bare single `0xF6`
///   rather than a padded block, so length cannot be assumed.
pub fn memo_text(memo: &[u8]) -> Option<String> {
    if memo.is_empty() || memo[0] == 0xF6 {
        return None;
    }
    // Some producers prepend 0xF5 (reserved) or leave the byte off entirely; take the bytes as they
    // are and stop at the first NUL, which is where padding begins.
    let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
    let text = std::str::from_utf8(&memo[..end]).ok()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// Shape of the JSON memo dialect.
#[derive(Deserialize)]
struct JsonMemo {
    asset_id: String,
    name: Option<String>,
    symbol: Option<String>,
    decimals: Option<u8>,
    metadata_uri: Option<String>,
    image_hash: Option<String>,
}

/// Parse one memo into a ZMAP record, or `None` if it is not a ZMAP memo.
///
/// This does **not** check the carrier value — [`holdings_from_rows`] does, because the value rule is
/// a property of the note, not the memo.
pub fn parse_memo(memo: &[u8]) -> Option<ZmapRecord> {
    let text = memo_text(memo)?;

    // Dialect 1: JSON.
    if text.starts_with('{') {
        if let Ok(j) = serde_json::from_str::<JsonMemo>(&text) {
            if j.asset_id.len() == 64 && j.asset_id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(ZmapRecord {
                    name: j.name.clone().unwrap_or_else(|| j.asset_id[..8].to_string()),
                    // When asset_id is the content hash (the scheme this project mints with) it
                    // doubles as the image hash, so artwork stays verifiable without a second field.
                    image_hash: j.image_hash.clone().or_else(|| Some(j.asset_id.clone())),
                    metadata_uri: j.metadata_uri.clone(),
                    symbol: j.symbol.clone(),
                    decimals: j.decimals.unwrap_or(0),
                    asset_id: j.asset_id,
                    dialect: Dialect::Json,
                });
            }
        }
        return None;
    }

    // Dialect 2: legacy prose — `<name>. Image Hash: <64 hex>. …`
    let (name_part, after) = text.split_once(". Image Hash: ")?;
    let hash: String = after.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if hash.len() != 64 {
        return None;
    }
    let name = name_part.trim();
    if name.is_empty() {
        return None;
    }
    Some(ZmapRecord {
        asset_id: hash.clone(),
        name: name.to_string(),
        symbol: None,
        decimals: 0,
        metadata_uri: legacy_metadata_uri(text.as_str()),
        image_hash: Some(hash),
        dialect: Dialect::LegacyProse,
    })
}

/// One unspent output as read from `v_received_outputs`.
pub struct OutputRow {
    pub pool: i64,
    pub note_id: i64,
    pub txid: [u8; 32],
    pub output_index: i64,
    pub value: i64,
    pub memo: Option<Vec<u8>>,
}

/// Group carrier notes into holdings.
///
/// **Enforces the carrier-value rule**: a note is only a carrier if its value is exactly
/// [`CARRIER_ZAT`]. Rows failing that are skipped no matter what their memo says.
pub fn holdings_from_rows(rows: impl IntoIterator<Item = OutputRow>) -> Vec<ZmapHolding> {
    use std::collections::BTreeMap;
    let mut by_asset: BTreeMap<String, ZmapHolding> = BTreeMap::new();

    for row in rows {
        if row.value < 0 || row.value as u64 != CARRIER_ZAT {
            continue;
        }
        let Some(memo) = row.memo.as_deref() else { continue };
        let Some(rec) = parse_memo(memo) else { continue };

        let carrier = CarrierRef {
            pool: row.pool,
            pool_name: pool_name(row.pool).to_string(),
            note_id: row.note_id,
            txid: hex::encode(row.txid),
            txid_bytes: row.txid,
            output_index: row.output_index,
            memo: memo.to_vec(),
        };

        by_asset
            .entry(rec.asset_id.clone())
            .and_modify(|h| {
                h.quantity += 1;
                h.carriers.push(carrier.clone());
            })
            .or_insert_with(|| ZmapHolding {
                asset_id: rec.asset_id,
                name: rec.name,
                symbol: rec.symbol,
                decimals: rec.decimals,
                metadata_uri: rec.metadata_uri,
                image_hash: rec.image_hash,
                dialect: rec.dialect,
                quantity: 1,
                carriers: vec![carrier],
            });
    }

    by_asset.into_values().collect()
}

/// What a ZMAP asset transfer must do, resolved before any transaction is built.
///
/// A transfer is **not** the operation every tool in this project's history performed. Those spent
/// an ordinary ZEC change note and wrote a fresh memo, which *re-declares* the asset: the identity
/// then exists in two places on chain with no input edge between them, and supply is whatever the
/// issuer last claimed. A transfer spends the carrier itself, so the old note is provably consumed.
#[derive(Debug, Clone)]
pub struct AssetSendPlan {
    pub asset_id: String,
    /// The one carrier to spend.
    pub carrier: OutputRef,
    /// Its pool. An Orchard carrier still spends fine — the pool is closed to new *outputs*, not to
    /// spends — but the replacement carrier must be Ironwood.
    pub source_pool: PoolType,
    /// The memo to write on the new carrier, byte-identical to the one being spent.
    pub memo: Vec<u8>,
    /// Always [`CARRIER_ZAT`]: value is preserved, only custody moves.
    pub amount: u64,
    /// Scopes the lock override to this asset alone, leaving every other carrier protected.
    pub lock_owner: LockOwner,
}

/// Resolve a transfer of one unit of `asset_id`.
///
/// Fails rather than guessing when the wallet cannot satisfy the request exactly.
pub fn plan_asset_send(holdings: &[ZmapHolding], asset_id: &str) -> Result<AssetSendPlan> {
    let h = holdings
        .iter()
        .find(|h| h.asset_id == asset_id)
        .ok_or_else(|| anyhow::anyhow!("this wallet holds no asset {}", asset_id))?;

    // Take one carrier, deterministically, so a retry after a crash resolves to the same note
    // rather than silently moving to another unit of the same asset.
    let carrier = h
        .carriers
        .iter()
        .min_by_key(|c| (c.txid.clone(), c.output_index))
        .ok_or_else(|| anyhow::anyhow!("asset {} has no unspent carrier note", asset_id))?;

    let source_pool = pool_type(carrier.pool).ok_or_else(|| {
        anyhow::anyhow!(
            "asset {} sits in an unrecognised pool ({}); refusing to spend it",
            asset_id,
            carrier.pool
        )
    })?;

    // The memo is the asset. If it did not survive detection intact there is nothing safe to re-issue.
    if parse_memo(&carrier.memo).map(|r| r.asset_id) != Some(asset_id.to_string()) {
        return Err(anyhow::anyhow!(
            "the carrier's memo does not re-parse to {} — refusing to transfer an asset whose \
             identity cannot be reproduced exactly",
            asset_id
        ));
    }

    let idx = u32::try_from(carrier.output_index)
        // TryFromIntError carries no information beyond "did not fit", which the
        // message already says.
        .map_err(|_| anyhow::anyhow!("carrier output index out of range"))?;

    Ok(AssetSendPlan {
        asset_id: asset_id.to_string(),
        carrier: OutputRef::new(TxId::from_bytes(carrier.txid_bytes), source_pool, idx),
        source_pool,
        memo: carrier.memo.clone(),
        amount: CARRIER_ZAT,
        lock_owner: carrier_lock_owner(asset_id),
    })
}

/// Verify artwork against the hash the memo commits to.
///
/// Returns `Ok(true)` only on an exact match. **Never** treat a fetch failure as verification.
pub fn verify_image(image_bytes: &[u8], expected_hash: &str) -> Result<bool> {
    Ok(sha256_hex(image_bytes).eq_ignore_ascii_case(expected_hash))
}

/// Lock owner protecting the carriers of one specific asset.
///
/// # Why the owner is per-asset, not per-wallet
///
/// A single wallet-wide owner is enough to *protect* carriers — [`LockedInputPolicy::Exclude`], the
/// default, hides every locked note from selection. It is **not** enough to *spend* one on purpose.
///
/// Sending asset X means overriding the lock, and the override is owner-scoped:
/// `PreferLocked({owner})`. With one shared owner that override admits **every** carrier in the
/// wallet, so value-driven selection could reach for asset Y's note to make up a fee and burn it —
/// change returns as a single ordinary note, and Y is gone.
///
/// Deriving the owner from the asset id narrows the override to exactly the asset being sent.
/// Everything else stays locked, including other assets, throughout the send.
///
/// Derived rather than random so it is stable across restarts: the backend permits same-owner
/// re-locking and just refreshes the expiry, which makes [`crate::native_builder`]'s
/// lock-before-every-build idempotent.
///
/// [`LockedInputPolicy::Exclude`]: zcash_client_backend::data_api::wallet::input_selection::LockedInputPolicy::Exclude
pub fn carrier_lock_owner(asset_id: &str) -> LockOwner {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    // Domain-separated so the token cannot collide with any other use of an asset id.
    h.update(b"zecboat:zmap-carrier-lock:v1:");
    h.update(asset_id.as_bytes());
    LockOwner::new(h.finalize().into())
}

/// Every carrier note of these holdings, paired with the owner its lock is held under.
///
/// Grouped by owner because [`lock_outputs`] takes one owner per call.
///
/// [`lock_outputs`]: zcash_client_backend::data_api::WalletWrite::lock_outputs
pub fn carrier_locks(holdings: &[ZmapHolding]) -> Vec<(LockOwner, Vec<OutputRef>)> {
    holdings
        .iter()
        .filter_map(|h| {
            let refs = holding_output_refs(h);
            if refs.is_empty() {
                None
            } else {
                Some((carrier_lock_owner(&h.asset_id), refs))
            }
        })
        .collect()
}

/// Lockable references for the carriers of a single holding.
pub fn holding_output_refs(h: &ZmapHolding) -> Vec<OutputRef> {
    h.carriers
        .iter()
        .filter_map(|c| {
            let pool = pool_type(c.pool)?;
            let idx = u32::try_from(c.output_index).ok()?;
            Some(OutputRef::new(TxId::from_bytes(c.txid_bytes), pool, idx))
        })
        .collect()
}

/// Map a `v_received_outputs.pool` code to a [`PoolType`].
pub fn pool_type(pool: i64) -> Option<PoolType> {
    match pool {
        POOL_TRANSPARENT => Some(PoolType::Transparent),
        POOL_SAPLING => Some(PoolType::Shielded(ShieldedPool::Sapling)),
        POOL_ORCHARD => Some(PoolType::Shielded(ShieldedPool::Orchard)),
        POOL_IRONWOOD => Some(PoolType::Shielded(ShieldedPool::Ironwood)),
        _ => None,
    }
}

/// Every carrier note backing these holdings, as lockable output references.
pub fn carrier_output_refs(holdings: &[ZmapHolding]) -> Vec<OutputRef> {
    holdings.iter().flat_map(holding_output_refs).collect()
}

/// Selects notes worth exactly one carrier that carry a memo and are not spent **on chain**.
///
/// The value predicate is applied here *and* re-checked in [`holdings_from_rows`]. The duplication
/// is deliberate: the SQL keeps the scan small, the Rust check keeps the rule true for any other
/// caller that builds rows another way.
///
/// # Why "mined", and not merely "has a spend row"
///
/// This query previously excluded any note with a row in `v_received_output_spends`, mined or not.
/// That destroyed Happy Birthday #003 on 2026-08-23.
///
/// `create_proposed_transactions` marks inputs spent when it *builds*, before any broadcast. When
/// that transaction later expires unmined the note is still ours — but the spend row remains. Under
/// the old predicate the note dropped out of the carrier set, so it was never handed to
/// `lock_zmap_carriers`, so [`LockedInputPolicy::Exclude`] had nothing to exclude, and
/// `propose_transfer` saw an ordinary 10,000-zat note and took it as funding. Two carriers went into
/// tx `d222041394…`; one memo came out.
///
/// A note is therefore only excluded once a **mined** transaction has spent it. A carrier with an
/// in-flight spend stays locked — which is the safe direction: locking a note already committed to a
/// transaction costs nothing, and stops a second transaction claiming it.
///
/// This does not impede sending a carrier on purpose. `send_zmap_asset` overrides the lock for its
/// chosen target with `LockedInputPolicy::PreferLocked`; only *incidental* selection is blocked.
///
/// [`LockedInputPolicy::Exclude`]: zcash_client_backend::data_api::wallet::input_selection::LockedInputPolicy::Exclude
pub const CARRIER_SQL: &str = "\
    SELECT v.pool, v.id_within_pool_table, t.txid, v.output_index, v.value, v.memo
      FROM v_received_outputs v
      JOIN transactions t ON t.id_tx = v.transaction_id
     WHERE NOT EXISTS (
             SELECT 1
               FROM v_received_output_spends s
               JOIN transactions st ON st.id_tx = s.transaction_id
              WHERE s.received_output_id = v.id_within_pool_table
                AND s.pool = v.pool
                AND st.mined_height IS NOT NULL)
       AND v.memo IS NOT NULL
       AND v.value = ?1";

/// Read carrier candidates from an open connection.
///
/// Shared by the async pool path in `db.rs` and the synchronous transaction-building path, so both
/// see exactly the same set.
pub fn read_carrier_rows(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<OutputRow>> {
    let mut stmt = conn.prepare(CARRIER_SQL)?;
    let rows = stmt.query_map([CARRIER_ZAT as i64], |row| {
        let txid_vec: Vec<u8> = row.get(2)?;
        let mut txid = [0u8; 32];
        if txid_vec.len() == 32 {
            txid.copy_from_slice(&txid_vec);
        }
        Ok(OutputRow {
            pool: row.get(0)?,
            note_id: row.get(1)?,
            txid,
            output_index: row.get(3)?,
            value: row.get(4)?,
            memo: row.get(5)?,
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real memo from `FULL_NOMAD_MANIFEST.txt`, asset #042.
    const NOMAD_042: &str = "ZecBoat Cyber-Nomad #042. Image Hash: \
        67c356eea320c36142de2344239cd447f9b93e72a357e767912cd4eb859de5d4. Backing: 10,000 Zats.";

    fn row(value: i64, memo: Option<&str>) -> OutputRow {
        OutputRow {
            pool: POOL_IRONWOOD,
            note_id: 1,
            txid: [0xaa; 32],
            output_index: 0,
            value,
            memo: memo.map(|m| m.as_bytes().to_vec()),
        }
    }

    #[test]
    fn parses_legacy_prose() {
        let r = parse_memo(NOMAD_042.as_bytes()).expect("should parse");
        assert_eq!(r.dialect, Dialect::LegacyProse);
        assert_eq!(r.name, "ZecBoat Cyber-Nomad #042");
        assert_eq!(
            r.asset_id,
            "67c356eea320c36142de2344239cd447f9b93e72a357e767912cd4eb859de5d4"
        );
        assert_eq!(r.image_hash.as_deref(), Some(r.asset_id.as_str()));
    }

    /// The registry id is derived, not looked up. Verified live against zecboat.com on 2026-08-13.
    #[test]
    fn derives_known_collection_metadata_uri() {
        let r = parse_memo(NOMAD_042.as_bytes()).unwrap();
        assert_eq!(
            r.metadata_uri.as_deref(),
            Some("https://zecboat.com/collection/f142a387527e23556947d4743d9ed784e3c533795ca182eb39a1c5665f1dd3c3.json")
        );
    }

    #[test]
    fn unknown_collection_still_parses_without_metadata() {
        let memo = "Some Other Drop #7. Image Hash: \
            0000000000000000000000000000000000000000000000000000000000000001. Backing: 10,000 Zats.";
        let r = parse_memo(memo.as_bytes()).expect("should still parse");
        assert!(r.metadata_uri.is_none(), "must not guess a URI");
        assert_eq!(r.name, "Some Other Drop #7");
    }

    /// Minimal stand-ins for the three wallet relations [`CARRIER_SQL`] reads.
    fn carrier_fixture() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE transactions (
                 id_tx INTEGER PRIMARY KEY, txid BLOB, mined_height INTEGER, expiry_height INTEGER);
             CREATE TABLE v_received_outputs (
                 id_within_pool_table INTEGER, pool INTEGER, transaction_id INTEGER,
                 output_index INTEGER, value INTEGER, memo BLOB);
             CREATE TABLE v_received_output_spends (
                 received_output_id INTEGER, pool INTEGER, transaction_id INTEGER);

             -- tx 1 minted the carriers; tx 5 expired unmined; tx 9 is mined.
             INSERT INTO transactions VALUES (1, x'01', 3447455, NULL);
             INSERT INTO transactions VALUES (5, x'05', NULL,    3458022);
             INSERT INTO transactions VALUES (9, x'09', 3458293, 3458331);

             -- note 8: an expired spend only. Still ours.
             INSERT INTO v_received_outputs VALUES (8, 4, 1, 0, 10000, x'7b7d');
             INSERT INTO v_received_output_spends VALUES (8, 4, 5);

             -- note 9: never spent.
             INSERT INTO v_received_outputs VALUES (9, 4, 1, 1, 10000, x'7b7d');

             -- note 7: genuinely spent by a mined transaction. Gone.
             INSERT INTO v_received_outputs VALUES (7, 4, 1, 2, 10000, x'7b7d');
             INSERT INTO v_received_output_spends VALUES (7, 4, 9);",
        )
        .unwrap();
        conn
    }

    /// The Happy Birthday #003 burn, 2026-08-23.
    ///
    /// A carrier whose only spend belongs to an expired, never-mined transaction must stay in the
    /// carrier set. If it drops out it is never locked, and `propose_transfer` will spend it as
    /// ordinary funding — which is exactly how #003 was destroyed.
    #[test]
    fn expired_spend_does_not_release_a_carrier() {
        let conn = carrier_fixture();
        let ids: Vec<i64> = read_carrier_rows(&conn)
            .expect("query should run")
            .iter()
            .map(|r| r.note_id)
            .collect();

        assert!(
            ids.contains(&8),
            "note 8's spend expired unmined — it is still a carrier and must be lockable, \
             got {ids:?}"
        );
        assert!(ids.contains(&9), "unspent carrier must be present, got {ids:?}");
        assert!(
            !ids.contains(&7),
            "note 7 was spent by a mined transaction and must NOT be returned, got {ids:?}"
        );
    }

    /// A note with both an expired spend and a later mined spend is gone — the mined one wins.
    #[test]
    fn mined_spend_beats_an_earlier_expired_spend() {
        let conn = carrier_fixture();
        conn.execute("INSERT INTO v_received_output_spends VALUES (8, 4, 9)", [])
            .unwrap();
        let ids: Vec<i64> = read_carrier_rows(&conn)
            .unwrap()
            .iter()
            .map(|r| r.note_id)
            .collect();
        assert!(
            !ids.contains(&8),
            "once a mined transaction spends it the carrier is gone, got {ids:?}"
        );
    }

    #[test]
    fn parses_json_dialect() {
        let id = "a".repeat(64);
        let memo = format!(
            r#"{{"asset_id":"{id}","name":"Happy Birthday #001","symbol":"HBD","decimals":0,"metadata_uri":"https://zecboat.com/collection/{id}.json"}}"#
        );
        let r = parse_memo(memo.as_bytes()).expect("should parse");
        assert_eq!(r.dialect, Dialect::Json);
        assert_eq!(r.symbol.as_deref(), Some("HBD"));
        // asset_id doubles as the image hash when none is given separately.
        assert_eq!(r.image_hash.as_deref(), Some(id.as_str()));
    }

    #[test]
    fn rejects_no_memo_and_junk() {
        assert!(parse_memo(&[0xF6]).is_none(), "0xF6 is 'no memo'");
        assert!(parse_memo(&[]).is_none());
        assert!(parse_memo(b"hello from a normal payment").is_none());
        assert!(parse_memo(br#"{"asset_id":"tooshort"}"#).is_none());
    }

    #[test]
    fn strips_padding_from_a_full_512_byte_memo() {
        let mut padded = NOMAD_042.as_bytes().to_vec();
        padded.resize(512, 0);
        let r = parse_memo(&padded).expect("padded memo must parse");
        assert_eq!(r.name, "ZecBoat Cyber-Nomad #042");
    }

    /// The bug this module exists to fix: the previous detector checked only the memo, so any
    /// payment mentioning `asset_id` was reported as an asset.
    #[test]
    fn value_rule_is_enforced() {
        let id = "b".repeat(64);
        let memo = format!(r#"{{"asset_id":"{id}","name":"Not a carrier"}}"#);
        assert!(
            holdings_from_rows([row(4_985_000, Some(&memo))]).is_empty(),
            "a 0.0498 ZEC note is not a carrier however its memo reads"
        );
        assert_eq!(holdings_from_rows([row(10_000, Some(&memo))]).len(), 1);
    }

    /// Semi-fungible editions: many carriers, one identical memo, one asset.
    #[test]
    fn counts_quantity_rather_than_assuming_one() {
        let rows: Vec<_> = (0..5).map(|_| row(10_000, Some(NOMAD_042))).collect();
        let h = holdings_from_rows(rows);
        assert_eq!(h.len(), 1, "identical memos are one asset");
        assert_eq!(h[0].quantity, 5, "quantity must be counted, not assumed");
        assert_eq!(h[0].carriers.len(), 5);
    }

    /// Carriers must be convertible to lockable references — this is what the protection in
    /// `native_builder::lock_zmap_carriers` operates on. A holding whose pool code is unrecognised
    /// must be dropped rather than locked as the wrong pool.
    #[test]
    fn carriers_convert_to_output_refs() {
        let mut rows: Vec<_> = (0..3).map(|_| row(10_000, Some(NOMAD_042))).collect();
        rows[1].pool = POOL_ORCHARD;
        rows[2].pool = 99; // unknown pool
        let h = holdings_from_rows(rows);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].quantity, 3);

        let refs = carrier_output_refs(&h);
        assert_eq!(refs.len(), 2, "the unknown pool must be dropped, not guessed");
        assert!(refs.iter().any(|r| r.pool() == PoolType::Shielded(ShieldedPool::Ironwood)));
        assert!(refs.iter().any(|r| r.pool() == PoolType::Shielded(ShieldedPool::Orchard)));
    }

    /// The lock owner must be stable across restarts, or re-locking would fail against the
    /// previous run's locks instead of refreshing them.
    /// Owners must be stable across restarts (or re-locking would collide with the previous run's
    /// locks) and distinct per asset (or an override for one asset would admit another's carriers).
    #[test]
    fn lock_owners_are_stable_and_per_asset() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert_eq!(carrier_lock_owner(&a), carrier_lock_owner(&a), "must be deterministic");
        assert_ne!(
            carrier_lock_owner(&a),
            carrier_lock_owner(&b),
            "distinct assets must not share a lock owner, or spending one could burn the other"
        );
    }

    #[test]
    fn plans_a_transfer_that_reissues_the_exact_memo() {
        let h = holdings_from_rows([row(10_000, Some(NOMAD_042))]);
        let id = &h[0].asset_id;
        let plan = plan_asset_send(&h, id).expect("should plan");

        // The memo is the asset: it must be carried over byte-for-byte, not rebuilt from fields.
        assert_eq!(plan.memo, NOMAD_042.as_bytes(), "memo must be re-issued verbatim");
        assert_eq!(plan.amount, CARRIER_ZAT, "value is preserved; only custody moves");
        assert_eq!(plan.lock_owner, carrier_lock_owner(id), "override must be scoped to this asset");
        assert_eq!(plan.carrier.pool(), PoolType::Shielded(ShieldedPool::Ironwood));
    }

    /// Picking a carrier must be deterministic, so a retry resolves to the same note rather than
    /// quietly moving to another unit of the same asset.
    #[test]
    fn carrier_choice_is_deterministic() {
        let mut rows: Vec<_> = (0..3).map(|_| row(10_000, Some(NOMAD_042))).collect();
        for (i, r) in rows.iter_mut().enumerate() {
            r.txid = [i as u8; 32];
        }
        let h = holdings_from_rows(rows);
        let id = h[0].asset_id.clone();
        let a = plan_asset_send(&h, &id).unwrap();
        let b = plan_asset_send(&h, &id).unwrap();
        assert_eq!(a.carrier.txid(), b.carrier.txid());
    }

    #[test]
    fn refuses_to_plan_what_it_cannot_reproduce() {
        let h = holdings_from_rows([row(10_000, Some(NOMAD_042))]);
        assert!(plan_asset_send(&h, &"f".repeat(64)).is_err(), "asset not held");

        // A carrier whose memo no longer re-parses to its own id must not be transferred.
        let mut broken = h.clone();
        broken[0].carriers[0].memo = b"not a zmap memo".to_vec();
        assert!(
            plan_asset_send(&broken, &h[0].asset_id).is_err(),
            "must refuse when the identity cannot be reproduced exactly"
        );
    }

    /// **Cross-implementation check.** This memo was produced by `zecboat-mint` (a separate project
    /// with its own, independently written ZMAP implementation — see `~/zecboat_mint/BOUNDARY.md`)
    /// and pasted here as *data*, not linked as code.
    ///
    /// That is the point: the wallet's verification is only meaningful if it is a genuine second
    /// opinion. If the two implementations ever drift, this test fails — which is exactly the signal
    /// a shared parser would have hidden.
    #[test]
    fn parses_a_memo_emitted_by_the_mint() {
        const FROM_MINT: &str = r#"{"asset_id":"700983acb1832a2b0830405407bcaefaf0909c8631c1603cc5a72ecc4257e4d2","name":"Happy Birthday Test #002","symbol":"HBD","decimals":0,"metadata_uri":"https://zecboat.com/collection/700983acb1832a2b0830405407bcaefaf0909c8631c1603cc5a72ecc4257e4d2.json"}"#;

        let r = parse_memo(FROM_MINT.as_bytes()).expect("the wallet must parse what the mint emits");
        assert_eq!(r.dialect, Dialect::Json);
        assert_eq!(
            r.asset_id,
            "700983acb1832a2b0830405407bcaefaf0909c8631c1603cc5a72ecc4257e4d2"
        );
        assert_eq!(r.name, "Happy Birthday Test #002");
        assert_eq!(r.symbol.as_deref(), Some("HBD"));
        assert_eq!(r.decimals, 0);
        // The mint sets asset_id = sha256(image), so it doubles as the artwork commitment and
        // `verify_asset_image` can check the artwork with no trust in the registry.
        assert_eq!(r.image_hash.as_deref(), Some(r.asset_id.as_str()));
        assert!(r.metadata_uri.as_deref().unwrap().ends_with(&format!("{}.json", r.asset_id)));

        // And it must survive being padded into a real 512-byte memo field.
        let mut padded = FROM_MINT.as_bytes().to_vec();
        padded.resize(512, 0);
        assert_eq!(parse_memo(&padded).unwrap().asset_id, r.asset_id);
    }

    #[test]
    fn verify_image_matches_only_on_exact_hash() {
        let img = b"pretend png";
        let h = sha256_hex(img);
        assert!(verify_image(img, &h).unwrap());
        assert!(!verify_image(b"different bytes", &h).unwrap());
    }
}

/// Can this wallet pay a network fee, and therefore send anything at all?
///
/// **Why this needs a dedicated answer.** A carrier is exactly `CARRIER_ZAT` = 10,000 zat, and
/// the fee cannot be taken out of it: fees are inputs minus outputs, so shaving the carrier
/// would hand the recipient a sub-carrier note and **destroy the asset**. `send_zmap_asset`
/// therefore funds fees from separate notes — and the consequence, stated in `native_builder`'s
/// own module docs, is that **a wallet holding only carriers cannot send them**.
///
/// Without this check the failure surfaces as the backend's raw error:
///
/// ```text
/// InsufficientFunds { available: Zatoshis(10000), required: Zatoshis(20000) }
/// ```
///
/// against a balance the UI is simultaneously displaying as healthy. That is not a message
/// anyone can act on. It cost a day on 2026-09-03 when the cause was a pool mismatch rather
/// than this, and it will read identically to a user who simply holds no spendable ZEC.
///
/// `fee_zat` is an estimate, not a quote: the real fee is ZIP-317 over the action count, which
/// is not known until inputs are chosen. It is deliberately generous, because telling someone
/// they have enough when they do not is the failure this exists to prevent.
#[derive(Debug, serde::Serialize)]
pub struct FeeReadiness {
    /// Unspent value in notes that are NOT carriers — the only money a fee can come from.
    pub spendable_zat: u64,
    /// How many carriers are held. These are assets; spending one as ZEC destroys it.
    pub carrier_count: u64,
    /// Value locked in carriers. Shown so the arithmetic in the UI reconciles.
    pub carrier_zat: u64,
    /// A generous ZIP-317 estimate.
    pub fee_zat: u64,
    /// True when `spendable_zat` covers `fee_zat`.
    pub can_pay_fee: bool,
}

/// Rough upper bound on a ZIP-317 fee for a small transfer.
///
/// `max(actions - 2, 0) * 5_000 + 10_000`. A transfer with a carrier in, a carrier out and a
/// change note lands at 4 actions -> 20,000. Quoting that rather than the 10,000 minimum means
/// the check errs toward "you need a little more", never toward a surprise at send time.
pub const ESTIMATED_FEE_ZAT: u64 = 20_000;

pub fn fee_readiness(conn: &rusqlite::Connection) -> rusqlite::Result<FeeReadiness> {
    let mut stmt = conn.prepare(
        "SELECT v.value
           FROM v_received_outputs v
           LEFT JOIN v_received_output_spends s
             ON v.id_within_pool_table = s.received_output_id AND v.pool = s.pool
          WHERE s.transaction_id IS NULL",
    )?;
    let values = stmt.query_map([], |row| row.get::<_, i64>(0))?;

    let (mut spendable_zat, mut carrier_count, mut carrier_zat) = (0u64, 0u64, 0u64);
    for v in values {
        let v = v? as u64;
        // Exactly CARRIER_ZAT is the carrier test the rest of the codebase uses. A note of
        // exactly 10,000 zat that is NOT an asset is indistinguishable here and is treated as a
        // carrier -- erring toward protecting an asset rather than toward spending one.
        if v == CARRIER_ZAT {
            carrier_count += 1;
            carrier_zat += v;
        } else {
            spendable_zat += v;
        }
    }

    Ok(FeeReadiness {
        spendable_zat,
        carrier_count,
        carrier_zat,
        fee_zat: ESTIMATED_FEE_ZAT,
        can_pay_fee: spendable_zat >= ESTIMATED_FEE_ZAT,
    })
}
