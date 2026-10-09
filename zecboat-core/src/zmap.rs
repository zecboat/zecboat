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
    /// Identity v1: the issuance key and the description the asset id derives from, when the
    /// memo carries them. The one strict reading of a carrier memo, so the item list, the
    /// collection audit and Collections agree (review 2026-10-09, session 4, Issue E).
    pub ik: Option<String>,
    pub desc: Option<String>,
    /// ZMAP v0.5 §15: SHA-256 of the lading delivered with this carrier, when the sender
    /// committed to one. Absent means **unproven**, never invalid.
    pub consignment_hash: Option<String>,
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
    /// The memo's `consignment_hash`, if the sender committed to a lading (§15).
    pub consignment_hash: Option<String>,
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
    /// Notes carrying this asset's lineage without its memo (ZMAP v0.5 §5.4). Empty for every
    /// asset whose transfers were paired correctly.
    #[serde(default)]
    pub lineage: Vec<LineageRow>,
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
    // ZIP 302: a lead byte of 0xF5 or above is not text (0xF6 is "no memo", 0xF5 is arbitrary
    // data). Said outright since 0.7.1, because that is where a Knotline key travels: the bytes
    // after such a lead byte must never be offered for display or copying. (They never were:
    // 0xF5 cannot begin valid UTF-8, so the decoding below already refused them.)
    if memo.is_empty() || memo[0] >= 0xF5 {
        return None;
    }
    // Stop at the first NUL, which is where padding begins.
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
    ik: Option<String>,
    /// Identity v1: the description `asset_id` is derived from (with the memo's `ik`). A memo
    /// carrying it can drop `name`, `symbol` and `image_hash`: [`desc_fields`] recovers them.
    desc: Option<String>,
    name: Option<String>,
    symbol: Option<String>,
    decimals: Option<u8>,
    metadata_uri: Option<String>,
    image_hash: Option<String>,
    consignment_hash: Option<String>,
}

/// The `(name, symbol, image_sha256)` inside an identity-v1 description:
/// `zmap-desc-v1|collection|unit|name|symbol|image_sha256`. `None` for any other shape.
pub fn desc_fields(desc: &str) -> Option<(String, String, String)> {
    let p: Vec<&str> = desc.split('|').collect();
    if p.len() != 6 || p[0] != "zmap-desc-v1" {
        return None;
    }
    let img = p[5];
    if img.len() != 64 || !img.chars().all(|c| c.is_ascii_hexdigit()) || p[3].is_empty() {
        return None;
    }
    Some((p[3].to_string(), p[4].to_string(), img.to_ascii_lowercase()))
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
            // ZMAP §4: `asset_id` is 64 lower-case hex characters. An upper-case copy used to
            // be a holding of its own that sorted before the genuine unit and spoke for it in
            // the issuance check (review 2026-10-09, session 4, Issue B); it is not a unit.
            if j.asset_id.len() == 64 && j.asset_id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
                // ZMAP §4: an identity-v1 memo's asset id MUST derive from its ik and desc. A memo
                // that says otherwise is not a unit of anything and is not listed (audit
                // 2026-10-08, ZMAP K); until then the derivation was checked only when sending.
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let (Some(ik), Some(desc)) = (v.get("ik").and_then(|x| x.as_str()), v.get("desc").and_then(|x| x.as_str())) {
                        let derives = hex::decode(ik)
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .map(|ik| crate::issuance_v1::derive_asset_id(&ik, desc) == j.asset_id.to_ascii_lowercase())
                            .unwrap_or(false);
                        if !derives {
                            return None;
                        }
                    }
                }
                // A v1 memo carries `ik` + `desc` (a transfer memo, ZMAP v0.5 §15), and §4 says
                // its name, symbol and image hash are *derived* from the description the id
                // commits to. They are, and only from it: free `name`/`image_hash` fields in a
                // v1 memo are the sender's to write and used to win (review 2026-10-09,
                // session 4, Issue F). A pre-v1 memo has no description and keeps its fields.
                let from_desc = j.desc.as_deref().and_then(desc_fields);
                // Any memo carrying `ik` and `desc` is a v1 memo. One whose description is not
                // in the six-field form is not a unit of anything: it used to keep its free
                // fields and borrow a pinned issuer's name (review 2026-10-09, regression over
                // 12-13, Issue G).
                let v1 = j.ik.is_some() && j.desc.is_some();
                if v1 && from_desc.is_none() {
                    return None;
                }
                return Some(ZmapRecord {
                    name: if v1 {
                        from_desc.as_ref().map(|d| d.0.clone()).unwrap_or_default()
                    } else {
                        j.name
                            .clone()
                            .or_else(|| from_desc.as_ref().map(|d| d.0.clone()))
                            .unwrap_or_else(|| j.asset_id[..8].to_string())
                    },
                    // Pre-v1 memos: asset_id is the content hash, so it doubles as the image hash.
                    image_hash: if v1 {
                        from_desc.as_ref().map(|d| d.2.clone()).filter(|h| !h.is_empty())
                    } else {
                        j.image_hash
                            .clone()
                            .or_else(|| from_desc.as_ref().map(|d| d.2.clone()))
                            .or_else(|| Some(j.asset_id.clone()))
                    },
                    metadata_uri: j.metadata_uri.clone(),
                    symbol: if v1 { from_desc.as_ref().map(|d| d.1.clone()) } else { j.symbol.clone().or_else(|| from_desc.as_ref().map(|d| d.1.clone())) },
                    decimals: j.decimals.unwrap_or(0),
                    asset_id: j.asset_id,
                    ik: j.ik.map(|k| k.to_ascii_lowercase()),
                    desc: j.desc.clone(),
                    dialect: Dialect::Json,
                    consignment_hash: j
                        .consignment_hash
                        .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
                        .map(|h| h.to_ascii_lowercase()),
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
        ik: None,
        desc: None,
        dialect: Dialect::LegacyProse,
        consignment_hash: None,
    })
}

/// The carrier memo to write on a transfer that carries a lading (ZMAP v0.5 §15).
///
/// The JSON dialect gains (or replaces) `consignment_hash`; every other field is carried over
/// as parsed, so `asset_id`, and hence the asset's identity, is unchanged. The legacy prose
/// dialect has no room for the field: the memo is returned unchanged and the lading travels
/// unbound, which the verifier accepts (it hashes the delivered bytes but has nothing in the
/// memo to compare against).
///
/// Before chapter 8 the memo was copied byte for byte. §15 says the memo MUST carry the hash,
/// so a JSON memo now changes on every hop, by exactly this one field.
/// The carrier memo with no `consignment_hash`: an unproven send must not repeat the hash of a
/// lading the sender is not passing on, or the recipient waits for a lading that never comes
/// and shows Broken if it ever gets it (audit 2026-10-08, ZMAP L). Prose memos pass through.
pub fn memo_without_consignment_hash(memo: &[u8]) -> Result<Vec<u8>> {
    let Some(text) = memo_text(memo) else { return Ok(memo.to_vec()) };
    if !text.starts_with('{') {
        return Ok(memo.to_vec());
    }
    let mut v: serde_json::Value = serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("the carrier memo is not valid JSON: {e}"))?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("consignment_hash");
    }
    Ok(serde_json::to_vec(&v)?)
}

pub fn memo_with_consignment_hash(memo: &[u8], hash_hex: &str) -> Result<Vec<u8>> {
    let Some(text) = memo_text(memo) else {
        return Err(anyhow::anyhow!("the carrier memo is empty"));
    };
    if !text.starts_with('{') {
        return Ok(memo.to_vec());
    }
    let mut v: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| anyhow::anyhow!("the carrier memo is not valid JSON: {e}"))?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("the carrier memo is not a JSON object"))?;
    // Identity v1 (ZMAP v0.5 §15, 2026-10-02): a transfer memo carries each fact once:
    // asset_id, ik, desc, consignment_hash. name/symbol/image_hash repeat desc and are dropped;
    // readers recover them with `desc_fields`. Minted memos kept every field, and for BCN26 and
    // HBD10 that left no room for the hash (537 and 534 bytes).
    let v1 = match (obj.get("ik").and_then(|x| x.as_str()), obj.get("desc").and_then(|x| x.as_str())) {
        (Some(ik), Some(desc)) => {
            let ik_bytes: [u8; 32] = hex::decode(ik)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("the carrier memo's ik is not 32 bytes of hex"))?;
            let id = obj.get("asset_id").and_then(|x| x.as_str()).unwrap_or_default().to_ascii_lowercase();
            if crate::issuance_v1::derive_asset_id(&ik_bytes, desc) != id {
                return Err(anyhow::anyhow!(
                    "the carrier memo's asset id does not derive from its ik and desc; refusing to transfer a forged memo"
                ));
            }
            Some((id, ik.to_ascii_lowercase(), desc.to_string()))
        }
        _ => None,
    };
    if let Some((id, ik, desc)) = v1 {
        v = serde_json::json!({ "asset_id": id, "ik": ik, "desc": desc });
    }
    v.as_object_mut().unwrap().insert(
        "consignment_hash".to_string(),
        serde_json::Value::String(hash_hex.to_ascii_lowercase()),
    );
    let out = serde_json::to_vec(&v)?;
    if out.len() > 512 {
        return Err(anyhow::anyhow!(
            "the carrier memo with its consignment hash is {} bytes; the limit is 512",
            out.len()
        ));
    }
    // The identity must survive the edit, or the transfer would re-declare a different asset.
    let before = parse_memo(memo).map(|r| r.asset_id);
    let after = parse_memo(&out).map(|r| r.asset_id);
    if before.is_none() || before != after {
        return Err(anyhow::anyhow!("adding the consignment hash changed the asset's identity"));
    }
    Ok(out)
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
            consignment_hash: rec.consignment_hash.clone(),
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
                lineage: Vec::new(),
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
    plan_asset_send_preferring(holdings, asset_id, &|_| 0)
}

/// As [`plan_asset_send`], but the carrier with the highest `rank` is taken, ties by txid. The
/// send path ranks carriers by the outcome of verifying their lineage, so an unsolicited copy of
/// a unit (a carrier with the same memo, which anyone can send) is never the note spent while a
/// genuine unit sits beside it. Until 2026-10-09 the preference was "has a stored lading", and a
/// copy that brought its own lading, however broken, counted (review, regression Finding 2).
pub fn plan_asset_send_preferring(
    holdings: &[ZmapHolding],
    asset_id: &str,
    rank: &dyn Fn(&CarrierRef) -> u8,
) -> Result<AssetSendPlan> {
    let h = holdings
        .iter()
        .find(|h| h.asset_id == asset_id)
        .ok_or_else(|| anyhow::anyhow!("this wallet holds no asset {}", asset_id))?;

    // Take one carrier, deterministically, so a retry after a crash resolves to the same note
    // rather than silently moving to another unit of the same asset.
    let carrier = h
        .carriers
        .iter()
        .min_by_key(|c| (u8::MAX - rank(c), c.txid.clone(), c.output_index))
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


// ── Lineage (ZMAP v0.5 §5.4, §5.5; Wake chapter 2, 2026-09-25) ─────────────────────────────
//
// Consensus gives every spent note exactly one successor: the output in the same Action, whose
// `rho` is the spent note's nullifier. The asset's *identity* under v0.5 is that chain, not the
// memo. Before the wallet paired Actions deliberately, a transfer could put the carrier's memo on
// one output and its lineage on another (the sender's change); the lineage then sat in an
// unlocked, memo-less note and the next fee spend burned it silently.
//
// Two things below close that:
//   * `read_lineage_rows` finds every note of this wallet whose `rho` equals the nullifier of a
//     carrier this wallet spent, walked forward through further spends, so they can be locked
//     and shown ("lineage of <asset>, memo missing").
//   * `zmap_lineage_out` records, per carrier send, the spent nullifier and the successor output,
//     so the sender can regenerate a hop proof for a recipient who lost their lading.

/// A note that carries an asset's lineage without necessarily carrying its memo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageRow {
    pub pool: i64,
    pub pool_name: String,
    pub note_id: i64,
    pub txid: String,
    #[serde(skip)]
    pub txid_bytes: [u8; 32],
    pub output_index: i64,
    /// The asset whose spent carrier this note descends from.
    pub asset_id: String,
    /// Whether this note also carries the asset's memo (then it is an ordinary carrier and is
    /// locked by the memo pass; it is listed here only so the chain is complete).
    pub is_carrier: bool,
    /// Whether a mined transaction has spent it (then it is history, not a holding).
    pub spent: bool,
}

/// Lock owner for lineage notes: distinct from the carrier owner so the UI can tell the two
/// reasons apart, and derived so re-locking is idempotent.
pub fn lineage_lock_owner(asset_id: &str) -> LockOwner {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"zecboat:zmap-lineage-lock:v1:");
    h.update(asset_id.as_bytes());
    LockOwner::new(h.finalize().into())
}

/// Every note of this wallet that descends, by `rho == nf`, from a carrier this wallet spent
/// in a mined transaction, walked forward through further mined spends.
///
/// Works per pool table: the `rho` link never crosses bundles, so an Orchard carrier's lineage
/// stays in `orchard_received_notes` and an Ironwood one in `ironwood_received_notes`.
pub fn read_lineage_rows(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<LineageRow>> {
    let mut out = Vec::new();
    for (pool, table) in [(POOL_IRONWOOD, "ironwood"), (POOL_ORCHARD, "orchard")] {
        // Seeds: the nullifiers of carriers this wallet spent, with their asset ids.
        let seed_sql = format!(
            "SELECT n.nf, n.memo
               FROM {t}_received_notes n
               JOIN {t}_received_note_spends s ON s.{t}_received_note_id = n.id
               JOIN transactions st ON st.id_tx = s.transaction_id
              WHERE st.mined_height IS NOT NULL
                AND n.value = ?1 AND n.memo IS NOT NULL AND n.nf IS NOT NULL",
            t = table
        );
        let mut frontier: Vec<(Vec<u8>, String)> = {
            let mut stmt = conn.prepare(&seed_sql)?;
            let rows = stmt.query_map([CARRIER_ZAT as i64], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            let mut v = Vec::new();
            for r in rows {
                let (nf, memo) = r?;
                if let Some(rec) = parse_memo(&memo) {
                    v.push((nf, rec.asset_id));
                }
            }
            v
        };

        let hop_sql = format!(
            "SELECT n.id, t.txid, n.action_index, n.nf, n.value, n.memo,
                    EXISTS (SELECT 1 FROM {t}_received_note_spends s
                              JOIN transactions st ON st.id_tx = s.transaction_id
                             WHERE s.{t}_received_note_id = n.id
                               AND st.mined_height IS NOT NULL) AS spent
               FROM {t}_received_notes n
               JOIN transactions t ON t.id_tx = n.transaction_id
              WHERE n.rho = ?1",
            t = table
        );
        let mut stmt = conn.prepare(&hop_sql)?;
        let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
        while !frontier.is_empty() {
            let mut next = Vec::new();
            for (nf, asset_id) in frontier.drain(..) {
                let rows = stmt.query_map([nf.as_slice()], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<Vec<u8>>>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Option<Vec<u8>>>(5)?,
                        r.get::<_, i64>(6)? != 0,
                    ))
                })?;
                for r in rows {
                    let (id, txid, action_index, next_nf, value, memo, spent) = r?;
                    if !seen.insert(id) {
                        continue;
                    }
                    let is_carrier = value as u64 == CARRIER_ZAT
                        && memo.as_deref().and_then(parse_memo).is_some();
                    let mut txid_bytes = [0u8; 32];
                    if txid.len() == 32 {
                        txid_bytes.copy_from_slice(&txid);
                    }
                    out.push(LineageRow {
                        pool,
                        pool_name: pool_name(pool).to_string(),
                        note_id: id,
                        txid: hex::encode(txid_bytes.iter().rev().copied().collect::<Vec<u8>>()),
                        txid_bytes,
                        output_index: action_index,
                        asset_id: asset_id.clone(),
                        is_carrier,
                        spent,
                    });
                    if spent {
                        if let Some(nf) = next_nf {
                            next.push((nf, asset_id.clone()));
                        }
                    }
                }
            }
            frontier = next;
        }
    }
    Ok(out)
}

/// Lineage notes that must be locked: unspent, and not already locked as carriers by the memo
/// pass. Grouped by lock owner, one owner per asset.
pub fn lineage_locks(rows: &[LineageRow]) -> Vec<(LockOwner, Vec<OutputRef>)> {
    let mut by_asset: std::collections::BTreeMap<String, Vec<OutputRef>> = Default::default();
    for r in rows.iter().filter(|r| !r.spent && !r.is_carrier) {
        let Some(pool) = pool_type(r.pool) else { continue };
        let Ok(idx) = u32::try_from(r.output_index) else { continue };
        by_asset
            .entry(r.asset_id.clone())
            .or_default()
            .push(OutputRef::new(TxId::from_bytes(r.txid_bytes), pool, idx));
    }
    by_asset
        .into_iter()
        .map(|(asset, refs)| (lineage_lock_owner(&asset), refs))
        .collect()
}

/// Attach lineage notes to the holdings the UI shows. A memo-less lineage note of an asset the
/// wallet also holds a carrier of joins that holding; one whose asset has no carrier here gets a
/// holding of its own, quantity 0, named so the user knows what it is and why it is locked.
pub fn attach_lineage(holdings: &mut Vec<ZmapHolding>, rows: Vec<LineageRow>) {
    for r in rows.into_iter().filter(|r| !r.spent && !r.is_carrier) {
        if let Some(h) = holdings.iter_mut().find(|h| h.asset_id == r.asset_id) {
            h.lineage.push(r);
        } else {
            let short: String = r.asset_id.chars().take(10).collect();
            holdings.push(ZmapHolding {
                asset_id: r.asset_id.clone(),
                name: format!("lineage of {short}… — memo missing"),
                symbol: None,
                decimals: 0,
                metadata_uri: None,
                image_hash: None,
                dialect: Dialect::Json,
                quantity: 0,
                carriers: Vec::new(),
                lineage: vec![r],
            });
        }
    }
}

/// What a carrier send records about where the lineage went (`zmap_lineage_out`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageOut {
    pub asset_id: String,
    pub spent_txid: [u8; 32],
    pub spent_action_index: u32,
    pub spent_nf: [u8; 32],
    pub successor_txid: [u8; 32],
    pub successor_action_index: u32,
    pub successor_cmx: [u8; 32],
    pub recipient: String,
}

/// Create the sender-side lineage table if it does not exist. Lives beside the wallet's own
/// tables, prefixed like `ext_zecboat_*`, and is never read by the backend.
pub fn ensure_lineage_out_table(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ext_zecboat_zmap_lineage_out (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT NOT NULL,
            spent_txid BLOB NOT NULL,
            spent_action_index INTEGER NOT NULL,
            spent_nf BLOB NOT NULL UNIQUE,
            successor_txid BLOB NOT NULL,
            successor_action_index INTEGER NOT NULL,
            successor_cmx BLOB NOT NULL,
            recipient TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        [],
    )?;
    Ok(())
}

/// Record one carrier send's lineage. Idempotent on the spent nullifier.
pub fn record_lineage_out(conn: &rusqlite::Connection, rec: &LineageOut) -> rusqlite::Result<()> {
    ensure_lineage_out_table(conn)?;
    conn.execute(
        "INSERT OR IGNORE INTO ext_zecboat_zmap_lineage_out
            (asset_id, spent_txid, spent_action_index, spent_nf,
             successor_txid, successor_action_index, successor_cmx, recipient)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            rec.asset_id,
            rec.spent_txid.as_slice(),
            rec.spent_action_index,
            rec.spent_nf.as_slice(),
            rec.successor_txid.as_slice(),
            rec.successor_action_index,
            rec.successor_cmx.as_slice(),
            rec.recipient,
        ],
    )?;
    Ok(())
}

/// A stored lading (ZMAP v0.5 §15 "consignment"), one row per delivered or produced lading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consignment {
    pub id: i64,
    pub asset_id: String,
    pub unit: Option<u32>,
    /// The carrier note this lading arrived with, when it was received; `None` for the copy a
    /// sender keeps of what it delivered.
    pub received_note_id: Option<i64>,
    #[serde(skip)]
    pub json: Vec<u8>,
    /// SHA-256 of `json` exactly as delivered; the memo's `consignment_hash`.
    pub sha256: String,
    pub verified_at_height: Option<u32>,
    pub created_at: String,
    /// Where it came from: "knotline", "memo", "dropbox", "file", "sent"; None before 2026-10-08.
    pub source: Option<String>,
}

/// Create the consignment table if it does not exist. Lives in `wallet.db` beside the
/// wallet's own tables so backups carry it (§15: wallets MUST include consignments in backups).
pub fn ensure_consignments_table(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ext_zecboat_zmap_consignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id TEXT NOT NULL,
            unit INTEGER,
            received_note_id INTEGER,
            json BLOB NOT NULL,
            sha256 BLOB NOT NULL UNIQUE,
            verified_at_height INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        [],
    )?;
    // 2026-10-02 (Wake review H2): the transaction a sender's extended lading belongs to.
    // A lading stored for a send that never mined must not be the one later reads pick up.
    let has_sent: bool = conn
        .prepare("SELECT 1 FROM pragma_table_info('ext_zecboat_zmap_consignments') WHERE name = 'sent_txid'")?
        .exists([])?;
    if !has_sent {
        conn.execute("ALTER TABLE ext_zecboat_zmap_consignments ADD COLUMN sent_txid BLOB", [])?;
    }
    // 0.7.1: whether a sent lading reached a drop-box. Until now delivery was tried once and a
    // failure was a console line; the wallet could not say which ladings never left.
    // 2026-10-08 (audit, Knotline A): where a lading came from ("knotline", "memo", "dropbox",
    // "file", "sent"). A sender chains a knot only to a line it rebuilt itself.
    // 2026-10-09 (review, Knotline F and H): the key and transaction a Knotline walk started
    // from, and how many knots it followed, so a sender chains only to exactly that pair and
    // starts a new line before the reader's bound.
    for (col, ty) in [("delivered_at", "TEXT"), ("delivery_note", "TEXT"), ("source", "TEXT"), ("knot_key", "BLOB"), ("knot_txid", "BLOB"), ("walked", "INTEGER")] {
        let has: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('ext_zecboat_zmap_consignments') WHERE name = ?1")?
            .exists([col])?;
        if !has {
            conn.execute(&format!("ALTER TABLE ext_zecboat_zmap_consignments ADD COLUMN {col} {ty}"), [])?;
        }
    }
    Ok(())
}

/// A lading this wallet made for a send, with where it was going and whether it got there.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OutgoingConsignment {
    pub asset_id: String,
    pub sha256: String,
    /// The transfer it belongs to, display order.
    pub txid: String,
    pub recipient: String,
    pub delivered_at: Option<String>,
    pub delivery_note: Option<String>,
    pub created_at: String,
    /// Whole days since it was made.
    pub age_days: i64,
    #[serde(skip)]
    pub json: Vec<u8>,
}

/// Every lading stored for a send, newest first, joined to the recipient it was sealed to.
pub fn outgoing_consignments(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<OutgoingConsignment>> {
    if !consignments_table_exists(conn)? {
        return Ok(Vec::new());
    }
    ensure_consignments_table(conn)?;
    ensure_lineage_out_table(conn)?;
    let mut stmt = conn.prepare(
        "SELECT c.asset_id, c.sha256, c.sent_txid, l.recipient, c.delivered_at, c.delivery_note, c.created_at, c.json,
                CAST(julianday('now') - julianday(c.created_at) AS INTEGER)
           FROM ext_zecboat_zmap_consignments c
           JOIN ext_zecboat_zmap_lineage_out l
             ON l.successor_txid = c.sent_txid AND l.asset_id = c.asset_id
          WHERE c.sent_txid IS NOT NULL
          ORDER BY c.id DESC",
    )?;
    let rows = stmt.query_map([], |r| {
        let sha: Vec<u8> = r.get(1)?;
        let mut txid: Vec<u8> = r.get(2)?;
        txid.reverse();
        Ok(OutgoingConsignment {
            asset_id: r.get(0)?,
            sha256: hex::encode(sha),
            txid: hex::encode(txid),
            recipient: r.get(3)?,
            delivered_at: r.get(4)?,
            delivery_note: r.get(5)?,
            created_at: r.get(6)?,
            age_days: r.get::<_, Option<i64>>(8)?.unwrap_or(0),
            json: r.get(7)?,
        })
    })?;
    rows.collect()
}

/// The note kept on a lading that travelled inside its own transfer: nothing was delivered
/// anywhere, so the UI must not say "delivered".
pub const CARRIED_IN_TRANSFER: &str = "in the transfer";

/// Record that a lading travelled inside the transfer itself.
pub fn mark_consignment_carried(conn: &rusqlite::Connection, sha256_hex: &str) -> rusqlite::Result<()> {
    ensure_consignments_table(conn)?;
    let Ok(raw) = hex::decode(sha256_hex) else { return Ok(()) };
    conn.execute(
        "UPDATE ext_zecboat_zmap_consignments SET delivered_at = datetime('now'), delivery_note = ?2 WHERE sha256 = ?1",
        rusqlite::params![raw.as_slice(), CARRIED_IN_TRANSFER],
    )?;
    Ok(())
}

/// Record the outcome of a delivery attempt: `Ok` stamps the time and clears the note, `Err`
/// keeps the reason and leaves a previous success untouched.
pub fn mark_consignment_delivery(
    conn: &rusqlite::Connection,
    sha256_hex: &str,
    outcome: std::result::Result<(), &str>,
) -> rusqlite::Result<()> {
    ensure_consignments_table(conn)?;
    let Ok(raw) = hex::decode(sha256_hex) else { return Ok(()) };
    match outcome {
        Ok(()) => conn.execute(
            "UPDATE ext_zecboat_zmap_consignments SET delivered_at = datetime('now'), delivery_note = NULL WHERE sha256 = ?1",
            [raw.as_slice()],
        )?,
        Err(why) => conn.execute(
            "UPDATE ext_zecboat_zmap_consignments SET delivery_note = ?2 WHERE sha256 = ?1 AND delivered_at IS NULL",
            rusqlite::params![raw.as_slice(), why],
        )?,
    };
    Ok(())
}

/// Store a lading. Idempotent on its hash. Returns the hash, lower-case hex.
pub fn store_consignment(
    conn: &rusqlite::Connection,
    asset_id: &str,
    unit: Option<u32>,
    received_note_id: Option<i64>,
    json: &[u8],
    sent_txid: Option<&[u8; 32]>,
) -> rusqlite::Result<String> {
    ensure_consignments_table(conn)?;
    let hash = zmap_wake::lading::lading_hash(json);
    conn.execute(
        "INSERT OR IGNORE INTO ext_zecboat_zmap_consignments
            (asset_id, unit, received_note_id, json, sha256, sent_txid)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![asset_id, unit, received_note_id, json, hash.as_slice(), sent_txid.map(|t| t.as_slice())],
    )?;
    Ok(hex::encode(hash))
}

fn consignment_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Consignment> {
    let sha: Vec<u8> = r.get(5)?;
    Ok(Consignment {
        id: r.get(0)?,
        asset_id: r.get(1)?,
        unit: r.get::<_, Option<i64>>(2)?.map(|u| u as u32),
        received_note_id: r.get(3)?,
        json: r.get(4)?,
        sha256: hex::encode(sha),
        verified_at_height: r.get::<_, Option<i64>>(6)?.map(|h| h as u32),
        created_at: r.get(7)?,
        source: r.get(8)?,
    })
}

const CONSIGNMENT_COLS: &str =
    "id, asset_id, unit, received_note_id, json, sha256, verified_at_height, created_at, source";

/// The column list for reads: `source` is NULL on a connection that may not ALTER (read-only
/// send-path lookups) and whose table predates the column.
fn consignment_cols(conn: &rusqlite::Connection) -> rusqlite::Result<String> {
    let has: bool = conn
        .prepare("SELECT 1 FROM pragma_table_info('ext_zecboat_zmap_consignments') WHERE name = 'source'")?
        .exists([])?;
    Ok(if has { CONSIGNMENT_COLS.to_string() } else { CONSIGNMENT_COLS.replace(", source", ", NULL AS source") })
}

/// Record where a stored lading came from (see [`ensure_consignments_table`]).
/// Record that a lading was rebuilt from the line under `key` starting at `txid` (stored byte
/// order), `walked` knots long. The sender chains its next knot only to exactly that pair.
pub fn mark_consignment_knotline(conn: &rusqlite::Connection, sha256_hex: &str, key: &[u8; 32], txid: &[u8; 32], walked: usize) -> rusqlite::Result<()> {
    let raw = hex::decode(sha256_hex).unwrap_or_default();
    ensure_consignments_table(conn)?;
    conn.execute(
        "UPDATE ext_zecboat_zmap_consignments SET source = 'knotline', knot_key = ?2, knot_txid = ?3, walked = ?4 WHERE sha256 = ?1",
        rusqlite::params![raw, key.as_slice(), txid.as_slice(), walked as i64],
    )?;
    Ok(())
}

/// `(key, txid, walked)` recorded for a lading rebuilt from a Knotline, if any.
pub fn consignment_knotline(conn: &rusqlite::Connection, sha256_hex: &str) -> rusqlite::Result<Option<([u8; 32], [u8; 32], usize)>> {
    let has: bool = conn
        .prepare("SELECT 1 FROM pragma_table_info('ext_zecboat_zmap_consignments') WHERE name = 'knot_key'")?
        .exists([])?;
    if !has {
        return Ok(None);
    }
    let raw = hex::decode(sha256_hex).unwrap_or_default();
    let mut stmt = conn.prepare("SELECT knot_key, knot_txid, walked FROM ext_zecboat_zmap_consignments WHERE sha256 = ?1 AND knot_key IS NOT NULL")?;
    let mut rows = stmt.query([raw.as_slice()])?;
    match rows.next()? {
        Some(r) => {
            let k: Vec<u8> = r.get(0)?;
            let t: Vec<u8> = r.get(1)?;
            let w: i64 = r.get::<_, Option<i64>>(2)?.unwrap_or(0);
            match (<[u8; 32]>::try_from(k), <[u8; 32]>::try_from(t)) {
                (Ok(k), Ok(t)) => Ok(Some((k, t, w as usize))),
                _ => Ok(None),
            }
        }
        None => Ok(None),
    }
}

/// Walks that failed, by carrier outpoint, with a back-off that doubles and survives a restart
/// (review 2026-10-09, Knotline A: an in-memory back-off restarted every walk at every launch).
pub fn ensure_walk_failures_table(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ext_zecboat_zmap_walk_failures (
            txid TEXT NOT NULL,
            output_index INTEGER NOT NULL,
            failures INTEGER NOT NULL,
            next_after INTEGER NOT NULL,
            last_error TEXT NOT NULL,
            PRIMARY KEY (txid, output_index)
        )",
        [],
    )?;
    Ok(())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Ten minutes after the first failure, doubling each time, at most a day.
pub fn record_walk_failure(conn: &rusqlite::Connection, txid_hex: &str, output_index: i64, error: &str) -> rusqlite::Result<()> {
    ensure_walk_failures_table(conn)?;
    let failures: i64 = conn
        .query_row("SELECT failures FROM ext_zecboat_zmap_walk_failures WHERE txid = ?1 AND output_index = ?2", rusqlite::params![txid_hex, output_index], |r| r.get(0))
        .unwrap_or(0)
        + 1;
    let delay = (600i64 * (1i64 << (failures - 1).min(8))).min(86_400);
    conn.execute(
        "INSERT OR REPLACE INTO ext_zecboat_zmap_walk_failures (txid, output_index, failures, next_after, last_error) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![txid_hex, output_index, failures, now_secs() + delay, error],
    )?;
    Ok(())
}

/// A failure that is the source's, not the line's (a server that did not answer): one short,
/// flat delay, and the failure count is not advanced (review 2026-10-09, Issue F).
pub fn record_walk_failure_transient(conn: &rusqlite::Connection, txid_hex: &str, output_index: i64, error: &str) -> rusqlite::Result<()> {
    ensure_walk_failures_table(conn)?;
    let failures: i64 = conn
        .query_row("SELECT failures FROM ext_zecboat_zmap_walk_failures WHERE txid = ?1 AND output_index = ?2", rusqlite::params![txid_hex, output_index], |r| r.get(0))
        .unwrap_or(0);
    conn.execute(
        "INSERT OR REPLACE INTO ext_zecboat_zmap_walk_failures (txid, output_index, failures, next_after, last_error) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![txid_hex, output_index, failures, now_secs() + 60, error],
    )?;
    Ok(())
}

/// `(last_error, failures, seconds until the next try)` when a carrier's walk is in back-off.
pub fn walk_failure(conn: &rusqlite::Connection, txid_hex: &str, output_index: i64) -> rusqlite::Result<Option<(String, i64, i64)>> {
    let exists: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ext_zecboat_zmap_walk_failures'")?
        .exists([])?;
    if !exists {
        return Ok(None);
    }
    let r: Option<(String, i64, i64)> = conn
        .query_row(
            "SELECT last_error, failures, next_after FROM ext_zecboat_zmap_walk_failures WHERE txid = ?1 AND output_index = ?2",
            rusqlite::params![txid_hex, output_index],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    Ok(r.map(|(e, f, next)| (e, f, next - now_secs())))
}

/// Lift a walk's delay and keep its count of failures: the next pass may try at once, but the
/// copy still comes after those that never failed (gate second pass, Issue E).
pub fn clear_walk_delay(conn: &rusqlite::Connection, txid_hex: &str, output_index: i64) -> rusqlite::Result<()> {
    ensure_walk_failures_table(conn)?;
    conn.execute("UPDATE ext_zecboat_zmap_walk_failures SET next_after = 0 WHERE txid = ?1 AND output_index = ?2", rusqlite::params![txid_hex, output_index])?;
    Ok(())
}

pub fn clear_walk_failure(conn: &rusqlite::Connection, txid_hex: &str, output_index: i64) -> rusqlite::Result<()> {
    ensure_walk_failures_table(conn)?;
    conn.execute("DELETE FROM ext_zecboat_zmap_walk_failures WHERE txid = ?1 AND output_index = ?2", rusqlite::params![txid_hex, output_index])?;
    Ok(())
}

pub fn mark_consignment_source(conn: &rusqlite::Connection, sha256_hex: &str, source: &str) -> rusqlite::Result<()> {
    let Ok(raw) = hex::decode(sha256_hex) else { return Ok(()) };
    conn.execute("UPDATE ext_zecboat_zmap_consignments SET source = ?2 WHERE sha256 = ?1", rusqlite::params![raw, source])?;
    Ok(())
}

/// Whether the table exists. Readers use this instead of [`ensure_consignments_table`] so a
/// read-only connection (the send path's lookup) never tries to create it.
fn consignments_table_exists(conn: &rusqlite::Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ext_zecboat_zmap_consignments'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
}

/// The most recently stored lading for `asset_id`, if any. **Not** the right choice for a
/// carrier: see [`consignment_for_carrier`]. Kept for the estimate and for tests.
pub fn latest_consignment(
    conn: &rusqlite::Connection,
    asset_id: &str,
) -> rusqlite::Result<Option<Consignment>> {
    Ok(consignments_for_asset(conn, asset_id)?.into_iter().next())
}

/// The lading that belongs to one carrier. Until 2026-10-08 the wallet took the newest lading
/// stored for the asset id, so a second carrier with a copied memo and its own lading (anyone
/// can send one) displaced the genuine lading: the genuine unit showed Broken, could not be
/// sent, and a poisoned lading could be extended and committed onward (audit, ZMAP B /
/// Zecboat C / ZMAP I). A carrier's lading is the one its memo commits to by hash. A carrier
/// whose memo commits to nothing (a unit at its first holder, or a sender before 0.7.0) gets
/// only a lading that **arrived with this note** (`received_note_id`) and ends at it; until
/// 2026-10-09 it got the newest lading for the asset that ended at the note's ρ, and ρ is
/// public, so a copy sent by anyone could still displace it (review, regression Finding 1).
/// A lading stored before notes were recorded (no `received_note_id`) is adopted by the first
/// note it ends at, once. A lading that fits neither is nobody's and is never shown against
/// this carrier.
pub fn consignment_for_carrier(
    conn: &rusqlite::Connection,
    asset_id: &str,
    committed_hash: Option<&str>,
    rho: &[u8; 32],
    note_id: Option<i64>,
) -> rusqlite::Result<Option<Consignment>> {
    if let Some(h) = committed_hash {
        return consignment_by_hash(conn, h);
    }
    let Some(me) = note_id else { return Ok(None) };
    let mut adoptable: Option<Consignment> = None;
    for c in consignments_for_asset(conn, asset_id)? {
        if !lading_ends_at(&c.json, rho) {
            continue;
        }
        match c.received_note_id {
            Some(n) if n == me => return Ok(Some(c)),
            None if c.source.as_deref() != Some("sent") && adoptable.is_none() => adoptable = Some(c),
            _ => {}
        }
    }
    if let Some(mut c) = adoptable {
        // Adoption writes once. On a read-only connection (the send and the estimate open one)
        // nothing is written and nothing is handed over: the row is adopted by the next pass
        // that can write (the item's badge), never assumed adopted, since the write is also
        // the check that no send made it (`sent_txid`; gate second pass, Issue I). A lading
        // made for a send is never adopted, whatever its `source` says.
        let raw = hex::decode(&c.sha256).unwrap_or_default();
        let n = conn
            .execute(
                "UPDATE ext_zecboat_zmap_consignments SET received_note_id = ?2 WHERE sha256 = ?1 AND received_note_id IS NULL AND sent_txid IS NULL",
                rusqlite::params![raw, me],
            )
            .unwrap_or(0);
        if n == 0 {
            return Ok(None);
        }
        c.received_note_id = Some(me);
        return Ok(Some(c));
    }
    Ok(None)
}

/// A lading that arrived for a carrier and failed the oracle-free checks (hash, canonical form,
/// proofs, chain rule, ρ) before it was stored. Kept per note, as evidence about the sender of
/// that copy: the copy shows Broken; nothing else is touched (review 2026-10-09, regression
/// Findings 1 and 11).
pub fn ensure_rejected_table(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ext_zecboat_zmap_rejected_ladings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_note_id INTEGER NOT NULL,
            sha256 BLOB NOT NULL,
            source TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        [],
    )?;
    // One row per (copy, lading): a rejection used to be re-inserted on every pass (review
    // 2026-10-09, regression over 12-13, Issue I).
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ext_zecboat_zmap_rejected_once ON ext_zecboat_zmap_rejected_ladings (received_note_id, sha256)",
        [],
    )?;
    Ok(())
}

pub fn record_rejected_lading(conn: &rusqlite::Connection, note_id: i64, sha256: &[u8; 32], source: &str, reason: &str) -> rusqlite::Result<()> {
    ensure_rejected_table(conn)?;
    conn.execute(
        "INSERT OR IGNORE INTO ext_zecboat_zmap_rejected_ladings (received_note_id, sha256, source, reason) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![note_id, sha256.as_slice(), source, reason],
    )?;
    Ok(())
}

/// `(reason, source, sha256 hex)` of the newest rejected lading for a note, if any.
pub fn rejected_lading_for_note(conn: &rusqlite::Connection, note_id: i64) -> rusqlite::Result<Option<(String, String, String)>> {
    let exists: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ext_zecboat_zmap_rejected_ladings'")?
        .exists([])?;
    if !exists {
        return Ok(None);
    }
    let mut stmt = conn.prepare(
        "SELECT reason, source, sha256 FROM ext_zecboat_zmap_rejected_ladings WHERE received_note_id = ?1 ORDER BY id DESC LIMIT 1",
    )?;
    let mut rows = stmt.query([note_id])?;
    match rows.next()? {
        Some(r) => {
            let sha: Vec<u8> = r.get(2)?;
            Ok(Some((r.get(0)?, r.get(1)?, hex::encode(sha))))
        }
        None => Ok(None),
    }
}

/// Whether the lading's last proof reveals nullifier `rho`, i.e. the note with that ρ is the
/// one it was made for. Unreadable ladings never match.
pub fn lading_ends_at(json: &[u8], rho: &[u8; 32]) -> bool {
    let Ok(l) = zmap_wake::lading::Lading::parse(json) else { return false };
    let Some(last) = l.hops.last() else { return false };
    last.instance.get(2).and_then(|h| zmap_wake::oracle::decode_hex_32(h).ok()).map(|nf| nf == *rho).unwrap_or(false)
}

/// Every stored lading for `asset_id`, newest first, leaving out ladings made for a send that
/// has expired unmined.
pub fn consignments_for_asset(
    conn: &rusqlite::Connection,
    asset_id: &str,
) -> rusqlite::Result<Vec<Consignment>> {
    if !consignments_table_exists(conn)? {
        return Ok(Vec::new());
    }
    // A lading stored for a send counts only while that send can still mine. Once the
    // transaction has expired unmined, the carrier it extended is still this wallet's, and the
    // lading before it is the live one again. The tip is the wallet's own scanned height; with
    // no `transactions` table (tests) nothing is excluded.
    let has_txs: bool = conn
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'transactions'")?
        .exists([])?;
    let tip: u32 = if has_txs {
        conn.query_row("SELECT COALESCE(MAX(height), 0) FROM blocks", [], |r| r.get::<_, i64>(0)).unwrap_or(0) as u32
    } else {
        0
    };
    // A wallet whose table predates 2026-10-02 has no `sent_txid` column until something
    // writes a consignment (store_consignment adds it). Reading must work before that, and
    // on a connection that may not be allowed to ALTER: the filter applies only when the
    // column exists. Showcase hit this on 2026-10-02: "no such column: sent_txid".
    let has_sent_col: bool = conn
        .prepare("SELECT 1 FROM pragma_table_info('ext_zecboat_zmap_consignments') WHERE name = 'sent_txid'")?
        .exists([])?;
    let filter = if has_txs && has_sent_col {
        "AND (sent_txid IS NULL OR NOT EXISTS (
             SELECT 1 FROM transactions t WHERE t.txid = sent_txid
                AND t.mined_height IS NULL AND t.expiry_height IS NOT NULL
                AND t.expiry_height > 0 AND t.expiry_height <= ?2))"
    } else {
        "AND ?2 = ?2"
    };
    let mut stmt = conn.prepare(&format!(
        "SELECT {} FROM ext_zecboat_zmap_consignments
          WHERE asset_id = ?1 {filter} ORDER BY id DESC", consignment_cols(conn)?
    ))?;
    let rows = stmt.query_map(rusqlite::params![asset_id, tip], consignment_from_row)?;
    rows.collect()
}

/// The lading with this hash (hex), if stored.
pub fn consignment_by_hash(
    conn: &rusqlite::Connection,
    sha256_hex: &str,
) -> rusqlite::Result<Option<Consignment>> {
    if !consignments_table_exists(conn)? {
        return Ok(None);
    }
    let Ok(raw) = hex::decode(sha256_hex) else { return Ok(None) };
    let mut stmt = conn.prepare(&format!(
        "SELECT {} FROM ext_zecboat_zmap_consignments WHERE sha256 = ?1", consignment_cols(conn)?
    ))?;
    let mut rows = stmt.query([raw.as_slice()])?;
    match rows.next()? {
        Some(r) => Ok(Some(consignment_from_row(r)?)),
        None => Ok(None),
    }
}

/// Every stored lading, oldest first.
pub fn list_consignments(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<Consignment>> {
    if !consignments_table_exists(conn)? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(&format!(
        "SELECT {} FROM ext_zecboat_zmap_consignments ORDER BY id", consignment_cols(conn)?
    ))?;
    let rows = stmt.query_map([], consignment_from_row)?;
    rows.collect()
}

/// Record that a lading verified against the node at `height` (or clear it with `None`).
pub fn mark_consignment_verified(
    conn: &rusqlite::Connection,
    sha256_hex: &str,
    height: Option<u32>,
) -> rusqlite::Result<()> {
    ensure_consignments_table(conn)?;
    let raw = hex::decode(sha256_hex).unwrap_or_default();
    conn.execute(
        "UPDATE ext_zecboat_zmap_consignments SET verified_at_height = ?2 WHERE sha256 = ?1",
        rusqlite::params![raw.as_slice(), height.map(|h| h as i64)],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memo_gains_a_consignment_hash_and_keeps_its_identity() {
        let id = "a21c64a9012d95a0b923f825f3d16b483a76804393948ff085715509f278c837";
        let memo = format!(r#"{{"asset_id":"{id}","name":"Wake Test #002","symbol":"WKT","decimals":0}}"#);
        let h = "0cc8e1c098d1d992e15e56067b0edafefcb855d8b681ed9bb26fa652c92427e1";
        let out = memo_with_consignment_hash(memo.as_bytes(), &h.to_uppercase()).unwrap();
        let rec = parse_memo(&out).unwrap();
        assert_eq!(rec.asset_id, id);
        assert_eq!(rec.consignment_hash.as_deref(), Some(h));
        assert_eq!(rec.name, "Wake Test #002");
        // A second hop replaces, not appends.
        let h2 = "1".repeat(64);
        let out2 = memo_with_consignment_hash(&out, &h2).unwrap();
        assert_eq!(parse_memo(&out2).unwrap().consignment_hash.as_deref(), Some(h2.as_str()));
        assert_eq!(String::from_utf8_lossy(&out2).matches("consignment_hash").count(), 1);
    }

    #[test]
    fn legacy_memo_is_left_alone() {
        let out = memo_with_consignment_hash(NOMAD_042.as_bytes(), &"2".repeat(64)).unwrap();
        assert_eq!(out, NOMAD_042.as_bytes());
        assert_eq!(parse_memo(&out).unwrap().consignment_hash, None);
    }

    #[test]
    fn malformed_consignment_hash_in_a_memo_reads_as_absent() {
        let id = "a21c64a9012d95a0b923f825f3d16b483a76804393948ff085715509f278c837";
        let memo = format!(r#"{{"asset_id":"{id}","consignment_hash":"nope"}}"#);
        assert_eq!(parse_memo(memo.as_bytes()).unwrap().consignment_hash, None);
    }

    #[test]
    fn walk_failures_back_off_and_double_and_survive_in_the_database() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        assert!(walk_failure(&conn, "aa", 0).unwrap().is_none());
        record_walk_failure(&conn, "aa", 0, "no knot").unwrap();
        let (e, f, wait) = walk_failure(&conn, "aa", 0).unwrap().unwrap();
        assert_eq!((e.as_str(), f), ("no knot", 1));
        assert!(wait > 500 && wait <= 600, "{wait}");
        record_walk_failure(&conn, "aa", 0, "no knot").unwrap();
        let (_, f, wait) = walk_failure(&conn, "aa", 0).unwrap().unwrap();
        assert!(f == 2 && wait > 1100 && wait <= 1200, "{f} {wait}");
        for _ in 0..12 {
            record_walk_failure(&conn, "aa", 0, "x").unwrap();
        }
        assert!(walk_failure(&conn, "aa", 0).unwrap().unwrap().2 <= 86_400, "capped at a day");
        assert!(walk_failure(&conn, "aa", 1).unwrap().is_none(), "keyed on the outpoint");
        clear_walk_failure(&conn, "aa", 0).unwrap();
        assert!(walk_failure(&conn, "aa", 0).unwrap().is_none());
    }

    #[test]
    fn consignments_store_and_read_back() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let json = br#"{"wake_lading":1,"genesis":{"txid":"00","action_index":0},"hops":[]}"#;
        let h = store_consignment(&conn, "asset-a", Some(1), Some(7), json, None).unwrap();
        assert_eq!(h.len(), 64);
        // idempotent on the hash
        let h2 = store_consignment(&conn, "asset-a", Some(1), Some(7), json, None).unwrap();
        assert_eq!(h, h2);
        assert_eq!(list_consignments(&conn).unwrap().len(), 1);
        let c = latest_consignment(&conn, "asset-a").unwrap().unwrap();
        assert_eq!(c.json, json);
        assert_eq!(c.received_note_id, Some(7));
        assert_eq!(c.verified_at_height, None);
        mark_consignment_verified(&conn, &h, Some(3_497_364)).unwrap();
        let c = consignment_by_hash(&conn, &h).unwrap().unwrap();
        assert_eq!(c.verified_at_height, Some(3_497_364));
        assert!(latest_consignment(&conn, "asset-b").unwrap().is_none());
        assert!(consignment_by_hash(&conn, "zz").unwrap().is_none());
    }

    #[test]
    fn a_carrier_gets_the_lading_its_memo_commits_to_not_the_newest_for_the_asset() {
        // Audit 2026-10-08 (ZMAP B): a decoy carrier with a copied memo brings its own lading;
        // stored later, it used to displace the genuine one for every carrier of the asset.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        // Built with `to_bytes`: only the canonical encoding parses as a lading.
        let lading = |txid: &str, nf: &str, height: u32| {
            use zmap_wake::lading::{Genesis, Lading, ProofEntry};
            Lading {
                wake_lading: 1,
                genesis: Genesis { txid: txid.repeat(32), action_index: 0 },
                hops: vec![ProofEntry {
                    kind: "wake-v1".into(),
                    circuit: "genesis".into(),
                    instance: ["0".repeat(64), "0".repeat(64), nf.repeat(64)],
                    anchor_height: height,
                    proof: String::new(),
                }],
            }
            .to_bytes()
        };
        let genuine = lading("aa", "1", 1);
        let decoy = lading("bb", "2", 1);
        let h_genuine = store_consignment(&conn, "asset-a", None, Some(1), &genuine, None).unwrap();
        let h_decoy = store_consignment(&conn, "asset-a", None, Some(2), &decoy, None).unwrap();
        assert_eq!(latest_consignment(&conn, "asset-a").unwrap().unwrap().sha256, h_decoy, "newest for the asset is the decoy");
        // By committed hash: each carrier gets its own.
        let rho_genuine = [0x11u8; 32];
        assert_eq!(consignment_for_carrier(&conn, "asset-a", Some(&h_genuine), &rho_genuine, Some(1)).unwrap().unwrap().sha256, h_genuine);
        assert_eq!(consignment_for_carrier(&conn, "asset-a", Some(&h_decoy), &rho_genuine, Some(2)).unwrap().unwrap().sha256, h_decoy);
        // A hash nothing was stored under: nothing, never "the newest".
        assert!(consignment_for_carrier(&conn, "asset-a", Some(&"0".repeat(64)), &rho_genuine, Some(1)).unwrap().is_none());
        // No committed hash (a unit at its first holder, an old sender): only a lading that
        // arrived with THIS note. A copy sent later with a lading that ends at the same ρ
        // (ρ is public) used to displace it (review 2026-10-09, regression Finding 1).
        let copy = lading("cc", "1", 2);
        let h_copy = store_consignment(&conn, "asset-a", None, Some(9), &copy, None).unwrap();
        assert_eq!(latest_consignment(&conn, "asset-a").unwrap().unwrap().sha256, h_copy);
        assert_eq!(consignment_for_carrier(&conn, "asset-a", None, &rho_genuine, Some(1)).unwrap().unwrap().sha256, h_genuine);
        assert_eq!(consignment_for_carrier(&conn, "asset-a", None, &rho_genuine, Some(9)).unwrap().unwrap().sha256, h_copy);
        assert!(consignment_for_carrier(&conn, "asset-a", None, &rho_genuine, Some(3)).unwrap().is_none(), "a lading is never a third note's");
        assert!(consignment_for_carrier(&conn, "asset-a", None, &rho_genuine, None).unwrap().is_none());
        assert!(consignment_for_carrier(&conn, "asset-a", None, &[0x33u8; 32], Some(1)).unwrap().is_none());
        // A lading stored before notes were recorded is adopted by the first note it ends at, once.
        let old = lading("dd", "4", 1);
        let h_old = store_consignment(&conn, "asset-a", None, None, &old, None).unwrap();
        assert_eq!(consignment_for_carrier(&conn, "asset-a", None, &[0x44u8; 32], Some(5)).unwrap().unwrap().sha256, h_old);
        assert!(consignment_for_carrier(&conn, "asset-a", None, &[0x44u8; 32], Some(6)).unwrap().is_none(), "adopted once");
        // A rejected lading is remembered for its note, and for no other.
        record_rejected_lading(&conn, 9, &[7u8; 32], "knotline", "BadProof(0)").unwrap();
        record_rejected_lading(&conn, 9, &[7u8; 32], "memo", "BadProof(0)").unwrap();
        assert_eq!(rejected_lading_for_note(&conn, 9).unwrap().map(|r| r.0), Some("BadProof(0)".into()));
        assert_eq!(conn.query_row("SELECT COUNT(*) FROM ext_zecboat_zmap_rejected_ladings", [], |r| r.get::<_, i64>(0)).unwrap(), 1, "recorded once per copy and lading");
        assert!(rejected_lading_for_note(&conn, 1).unwrap().is_none());
    }

    #[test]
    fn a_knotline_key_memo_is_never_text() {
        let key_memo = zmap_wake::knotline::key_memo(&[b'A'; 32]); // a key made of printable bytes
        assert_eq!(memo_text(&key_memo), None);
        let chunk = zmap_wake::knotline::chunks(zmap_wake::knotline::KNOT_TAG, b"plain text inside a knot").unwrap();
        assert_eq!(memo_text(&chunk[0]), None);
        assert_eq!(memo_text(&[0xF6]), None);
        assert_eq!(memo_text(b"hello\0\0").as_deref(), Some("hello"));
    }

    /// 0.7.1: a sent lading is listed with its recipient and delivery state; a failure is kept
    /// as a note, a success stamps the time, and a later failure does not undo a success.
    #[test]
    fn outgoing_consignments_carry_their_delivery_state() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        assert!(outgoing_consignments(&conn).unwrap().is_empty(), "no tables yet");
        let sent = [7u8; 32];
        let h = store_consignment(&conn, "asset-a", None, None, br#"{"sent":1}"#, Some(&sent)).unwrap();
        // A received lading and a sent one with no lineage row are not outgoing deliveries.
        store_consignment(&conn, "asset-a", None, Some(3), br#"{"received":1}"#, None).unwrap();
        store_consignment(&conn, "asset-c", None, None, br#"{"orphan":1}"#, Some(&[9u8; 32])).unwrap();
        record_lineage_out(&conn, &LineageOut {
            asset_id: "asset-a".into(),
            spent_txid: [1u8; 32],
            spent_action_index: 0,
            spent_nf: [2u8; 32],
            successor_txid: sent,
            successor_action_index: 1,
            successor_cmx: [3u8; 32],
            recipient: "u1recipient".into(),
        }).unwrap();

        let out = outgoing_consignments(&conn).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].sha256.as_str(), out[0].recipient.as_str()), (h.as_str(), "u1recipient"));
        assert_eq!(out[0].txid, "07".repeat(32));
        assert_eq!(out[0].json, br#"{"sent":1}"#);
        assert!(out[0].delivered_at.is_none() && out[0].delivery_note.is_none());
        assert_eq!(out[0].age_days, 0);
        conn.execute("UPDATE ext_zecboat_zmap_consignments SET created_at = datetime('now', '-40 days') WHERE sent_txid = ?1", [sent.as_slice()]).unwrap();
        assert_eq!(outgoing_consignments(&conn).unwrap()[0].age_days, 40);

        mark_consignment_delivery(&conn, &h, Err("HTTP 404")).unwrap();
        let out = outgoing_consignments(&conn).unwrap();
        assert_eq!(out[0].delivery_note.as_deref(), Some("HTTP 404"));
        assert!(out[0].delivered_at.is_none());

        mark_consignment_delivery(&conn, &h, Ok(())).unwrap();
        let out = outgoing_consignments(&conn).unwrap();
        assert!(out[0].delivered_at.is_some());
        assert!(out[0].delivery_note.is_none());

        mark_consignment_delivery(&conn, &h, Err("later failure")).unwrap();
        let out = outgoing_consignments(&conn).unwrap();
        assert!(out[0].delivered_at.is_some() && out[0].delivery_note.is_none(), "a success stands");

        mark_consignment_carried(&conn, &h).unwrap();
        let out = outgoing_consignments(&conn).unwrap();
        assert!(out[0].delivered_at.is_some());
        assert_eq!(out[0].delivery_note.as_deref(), Some(CARRIED_IN_TRANSFER));
    }

    /// A table made before 0.7.1 gains the delivery columns on first use and keeps its rows.
    #[test]
    fn an_older_consignments_table_is_upgraded_in_place() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE ext_zecboat_zmap_consignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT NOT NULL, unit INTEGER,
                received_note_id INTEGER, json BLOB NOT NULL, sha256 BLOB NOT NULL UNIQUE,
                verified_at_height INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')));
             INSERT INTO ext_zecboat_zmap_consignments (asset_id, json, sha256) VALUES ('old', x'7b7d', x'00');",
        ).unwrap();
        assert!(outgoing_consignments(&conn).unwrap().is_empty());
        let cols: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('ext_zecboat_zmap_consignments')").unwrap()
            .query_map([], |r| r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
        for c in ["sent_txid", "delivered_at", "delivery_note"] {
            assert!(cols.iter().any(|x| x == c), "{c} missing from {cols:?}");
        }
        assert_eq!(list_consignments(&conn).unwrap().len(), 1);
    }

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

    /// The two note tables and their spend tables, as `read_lineage_rows` reads them.
    ///
    /// Story: carrier A (note 1, memo, nf A) was spent in mined tx 20. Its lineage went to the
    /// sender's change: note 2 (rho = A, no memo). Note 2 was then spent in mined tx 30, whose
    /// successor is note 3 (rho = nf of note 2), still unspent. Note 4 is unrelated change.
    /// Carrier B (note 5) was spent in tx 40, and its successor note 6 IS a memo carrier (a
    /// correctly paired self-send), so it is listed but not lock-eligible here.
    fn lineage_fixture() -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE transactions (id_tx INTEGER PRIMARY KEY, txid BLOB, mined_height INTEGER);
             CREATE TABLE ironwood_received_notes (
                 id INTEGER PRIMARY KEY, transaction_id INTEGER, action_index INTEGER,
                 value INTEGER, rho BLOB, nf BLOB, memo BLOB);
             CREATE TABLE ironwood_received_note_spends (ironwood_received_note_id INTEGER, transaction_id INTEGER);
             CREATE TABLE orchard_received_notes (
                 id INTEGER PRIMARY KEY, transaction_id INTEGER, action_index INTEGER,
                 value INTEGER, rho BLOB, nf BLOB, memo BLOB);
             CREATE TABLE orchard_received_note_spends (orchard_received_note_id INTEGER, transaction_id INTEGER);
             INSERT INTO transactions VALUES (10, x'0a', 100), (20, x'14', 200), (30, x'1e', 300), (40, x'28', 400);",
        )
        .unwrap();
        let memo_a = format!(r#"{{"asset_id":"{}","name":"A"}}"#, "aa".repeat(32));
        let memo_b = format!(r#"{{"asset_id":"{}","name":"B"}}"#, "bb".repeat(32));
        let mut ins = |id: i64, tx: i64, idx: i64, value: i64, rho: &[u8], nf: &[u8], memo: Option<&str>| {
            conn.execute(
                "INSERT INTO ironwood_received_notes VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![id, tx, idx, value, rho, nf, memo.map(str::as_bytes)],
            )
            .unwrap();
        };
        // note 1: carrier A, memo, spent in tx 20
        ins(1, 10, 0, 10000, &[0x00], &[0xaa], Some(&memo_a));
        // note 2: change of tx 20 carrying A's lineage (rho = aa), no memo, spent in tx 30
        ins(2, 20, 1, 15000, &[0xaa], &[0xbb], None);
        // note 3: successor of note 2 (rho = bb), unspent, no memo
        ins(3, 30, 0, 5000, &[0xbb], &[0xcc], None);
        // note 4: unrelated change
        ins(4, 20, 0, 999, &[0xee], &[0xff], None);
        // note 5: carrier B, spent in tx 40; note 6: its paired successor WITH memo
        ins(5, 10, 1, 10000, &[0x01], &[0xb5], Some(&memo_b));
        ins(6, 40, 1, 10000, &[0xb5], &[0xb6], Some(&memo_b));
        conn.execute_batch(
            "INSERT INTO ironwood_received_note_spends VALUES (1, 20), (2, 30), (5, 40);",
        )
        .unwrap();
        conn
    }

    #[test]
    fn lineage_rows_follow_the_chain_and_locks_skip_carriers_and_spent() {
        let conn = lineage_fixture();
        let rows = read_lineage_rows(&conn).unwrap();
        let mut ids: Vec<i64> = rows.iter().map(|r| r.note_id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![2, 3, 6], "notes 2 and 3 carry A's chain; 6 carries B's");
        let by_id = |id: i64| rows.iter().find(|r| r.note_id == id).unwrap();
        let a = "aa".repeat(32);
        assert_eq!(by_id(2).asset_id, a);
        assert!(by_id(2).spent && !by_id(2).is_carrier);
        assert_eq!(by_id(3).asset_id, a);
        assert!(!by_id(3).spent && !by_id(3).is_carrier);
        assert_eq!(by_id(6).asset_id, "bb".repeat(32));
        assert!(by_id(6).is_carrier);

        // Only note 3 needs a lineage lock: unspent and memo-less.
        let locks = lineage_locks(&rows);
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].0, lineage_lock_owner(&a));
        assert_eq!(locks[0].1.len(), 1);

        // The UI gets a synthetic holding for "a" (no carrier held) with note 3 attached.
        let mut holdings = Vec::new();
        attach_lineage(&mut holdings, rows);
        assert_eq!(holdings.len(), 1);
        assert_eq!(holdings[0].asset_id, a);
        assert_eq!(holdings[0].quantity, 0);
        assert_eq!(holdings[0].lineage.len(), 1);
        assert!(holdings[0].name.contains("memo missing"));
    }

    #[test]
    fn lineage_out_table_round_trips_and_is_idempotent() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let rec = LineageOut {
            asset_id: "a".into(),
            spent_txid: [1; 32],
            spent_action_index: 4,
            spent_nf: [2; 32],
            successor_txid: [3; 32],
            successor_action_index: 1,
            successor_cmx: [4; 32],
            recipient: "u1…".into(),
        };
        record_lineage_out(&conn, &rec).unwrap();
        record_lineage_out(&conn, &rec).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM ext_zecboat_zmap_lineage_out", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
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
        // A shielded note with no commitment-tree position can never be an input: no
        // witness can be built for it. Counting it here told the user they could pay a
        // fee they could not pay (A5). Transparent outputs have no position and pass.
        "SELECT v.value
           FROM v_received_outputs v
           LEFT JOIN v_received_output_spends s
             ON v.id_within_pool_table = s.received_output_id AND v.pool = s.pool
          WHERE s.transaction_id IS NULL
            AND CASE v.pool
                  WHEN 2 THEN (SELECT commitment_tree_position IS NOT NULL FROM sapling_received_notes  WHERE id = v.id_within_pool_table)
                  WHEN 3 THEN (SELECT commitment_tree_position IS NOT NULL FROM orchard_received_notes  WHERE id = v.id_within_pool_table)
                  WHEN 4 THEN (SELECT commitment_tree_position IS NOT NULL FROM ironwood_received_notes WHERE id = v.id_within_pool_table)
                  ELSE 1 END",
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

/// ZMAP v0.5 §15 transfer memos for identity v1 (2026-10-02): each fact carried once.
#[cfg(test)]
mod memo_v1_tests {
    use super::*;

    // Real minted memos, unit #010 of each collection (public: readable with the published UFVK).
    const HBD10_010: &str = r#"{"asset_id":"0e0e1a530132ab5033d350c250fb0913cb54d88368c3f379413a7b6a1823efc7","ik":"1ba0bd2f1a1891d616ce912b5e02c38069a9ec87d6b33769bdd8a00741ce1fa0","desc":"zmap-desc-v1|Happy Birthday Zcash 10|10|Happy Birthday Zcash 10 #010|HBD10|ceb6c397f3b19dedcaf4f17467fc22357b798a0fd0383e5d60bd653190997eb5","name":"Happy Birthday Zcash 10 #010","symbol":"HBD10","decimals":0,"image_hash":"ceb6c397f3b19dedcaf4f17467fc22357b798a0fd0383e5d60bd653190997eb5"}"#;
    const BCN26_010: &str = r#"{"asset_id":"4b52e4b2abea2e94f7c6d34e70e638c9f8ec2abb051f50e2ec11248b228dc929","ik":"d289030848144bc321be1030051f90dbf170f0c6752ab8dbf6ed029658d1a820","desc":"zmap-desc-v1|Barcelona Post Card 2026|10|Barcelona Post Card 2026 #010|BCN26|a86fd58e2f0800fe897dd0d1da1aa378ed53f096108a6eea6e1af4381d603b2e","name":"Barcelona Post Card 2026 #010","symbol":"BCN26","decimals":0,"image_hash":"a86fd58e2f0800fe897dd0d1da1aa378ed53f096108a6eea6e1af4381d603b2e"}"#;
    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The minted memos were too long to transfer (534 / 537 bytes); the short form fits.
    #[test]
    fn real_bcn26_and_hbd10_memos_now_transfer() {
        for (memo, expect_len) in [(HBD10_010, 386usize), (BCN26_010, 388)] {
            assert_eq!(memo.len(), if expect_len == 386 { 448 } else { 451 });
            let out = memo_with_consignment_hash(memo.as_bytes(), HASH).expect("must transfer");
            assert_eq!(out.len(), expect_len, "{}", String::from_utf8_lossy(&out));
            let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
            assert_eq!(keys, ["asset_id", "consignment_hash", "desc", "ik"]);
            // Identity and every displayed fact survive, read back from desc.
            let before = parse_memo(memo.as_bytes()).unwrap();
            let after = parse_memo(&out).unwrap();
            assert_eq!(after.asset_id, before.asset_id);
            assert_eq!(after.name, before.name);
            assert_eq!(after.symbol, before.symbol);
            assert_eq!(after.image_hash, before.image_hash);
            assert_eq!(after.consignment_hash.as_deref(), Some(HASH));
        }
    }

    /// A second hop replaces the hash and stays the same size: the memo no longer grows.
    #[test]
    fn second_hop_replaces_the_hash_without_growing() {
        let hop1 = memo_with_consignment_hash(BCN26_010.as_bytes(), HASH).unwrap();
        let hop2 = memo_with_consignment_hash(&hop1, &"f".repeat(64)).unwrap();
        assert_eq!(hop1.len(), hop2.len());
        assert_eq!(parse_memo(&hop2).unwrap().consignment_hash.as_deref(), Some(&*"f".repeat(64)));
    }

    /// A memo whose asset id does not derive from its ik and desc is a forgery: never re-issued.
    #[test]
    fn an_upper_case_asset_id_is_not_a_unit() {
        // ZMAP §4: lower-case hex. An upper-case copy used to be a holding of its own that
        // sorted before the genuine unit and spoke for it in the issuance check (review
        // 2026-10-09, session 4, Issue B).
        let lower = parse_memo(BCN26_010.as_bytes()).expect("the genuine memo parses");
        let upper = BCN26_010.replace(&lower.asset_id, &lower.asset_id.to_ascii_uppercase());
        assert_ne!(upper, BCN26_010);
        assert!(parse_memo(upper.as_bytes()).is_none());
    }

    #[test]
    fn a_v1_memo_takes_name_symbol_and_image_hash_from_its_description_only() {
        // §4: a v1 reader derives them from `desc`; free fields are the sender's to write
        // (review 2026-10-09, session 4, Issue F).
        let r = parse_memo(BCN26_010.as_bytes()).unwrap();
        let (name, symbol, image) = desc_fields(r.desc.as_deref().unwrap()).unwrap();
        assert_eq!((r.name.as_str(), r.symbol.as_deref(), r.image_hash.as_deref()), (name.as_str(), Some(symbol.as_str()), Some(image.as_str())));
        let mut v: serde_json::Value = serde_json::from_str(BCN26_010).unwrap();
        v["name"] = serde_json::Value::String("Not this".into());
        v["image_hash"] = serde_json::Value::String("f".repeat(64));
        let r2 = parse_memo(v.to_string().as_bytes()).unwrap();
        assert_eq!((r2.name, r2.image_hash), (r.name, r.image_hash), "free fields do not win over the description");
        assert_eq!(r2.ik.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn a_v1_memo_whose_id_does_not_derive_is_not_a_unit() {
        // ZMAP §4 at parse time (audit 2026-10-08, ZMAP K; test added 2026-10-09, regression
        // Finding 13): a memo carrying ik and desc with an asset id that does not derive from
        // them is refused here, not only when sending.
        assert!(parse_memo(BCN26_010.as_bytes()).is_some(), "the genuine memo parses");
        let forged = BCN26_010.replace("4b52e4b2", "deadbeef");
        assert!(parse_memo(forged.as_bytes()).is_none(), "a forged id is not listed");
    }

    #[test]
    fn an_unproven_send_strips_the_stale_consignment_hash() {
        // ZMAP L (2026-10-08), test added 2026-10-09: the memo copied for an unproven send must
        // not repeat the hash of a lading that is not being passed on.
        let with = memo_with_consignment_hash(BCN26_010.as_bytes(), HASH).unwrap();
        let t = memo_text(&with).unwrap();
        assert!(t.contains("consignment_hash"));
        let without = memo_without_consignment_hash(&with).unwrap();
        let u = memo_text(&without).unwrap();
        assert!(!u.contains("consignment_hash"), "{u}");
        let a = parse_memo(&with).unwrap();
        let b = parse_memo(&without).unwrap();
        assert_eq!((a.asset_id, a.name), (b.asset_id, b.name), "the identity is unchanged");
        assert_eq!(b.consignment_hash, None);
    }

    #[test]
    fn forged_v1_memo_is_refused_on_transfer() {
        let forged = BCN26_010.replace("4b52e4b2", "deadbeef");
        let err = memo_with_consignment_hash(forged.as_bytes(), HASH).unwrap_err().to_string();
        assert!(err.contains("does not derive"), "{err}");
    }

    #[test]
    fn desc_fields_reads_a_v1_description_only() {
        let (n, s, h) = desc_fields("zmap-desc-v1|C|3|C #003|SYM|".to_string().as_str()).map_or(("".into(), "".into(), "".into()), |x| x);
        assert!(n.is_empty() && s.is_empty() && h.is_empty(), "no image hash → None");
        let d = format!("zmap-desc-v1|Col|7|Col #007|CL|{}", "A".repeat(64));
        let (n, s, h) = desc_fields(&d).unwrap();
        assert_eq!((n.as_str(), s.as_str()), ("Col #007", "CL"));
        assert_eq!(h, "a".repeat(64));
        assert!(desc_fields("Lagos Post Card #001. Image Hash: abc").is_none());
    }

    /// A pre-v1 JSON memo (no ik/desc) is carried over whole, exactly as before.
    #[test]
    fn legacy_json_memo_keeps_every_field() {
        let legacy = r#"{"asset_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","name":"Old #1","symbol":"OLD","decimals":0}"#;
        let out = memo_with_consignment_hash(legacy.as_bytes(), HASH).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["name"], "Old #1");
        assert_eq!(v["consignment_hash"], HASH);
    }

    /// Wake review H2: the lading stored for a send that expired unmined is not the live one.
    #[test]
    fn a_table_without_the_sent_txid_column_still_reads() {
        // The table as every wallet had it before 2026-10-02: today's schema minus the
        // column, plus the tables the filter would join.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        ensure_consignments_table(&conn).unwrap();
        conn.execute_batch(
            "ALTER TABLE ext_zecboat_zmap_consignments DROP COLUMN sent_txid;
             CREATE TABLE transactions (txid BLOB, mined_height INTEGER, expiry_height INTEGER);
             CREATE TABLE blocks (height INTEGER);
             INSERT INTO ext_zecboat_zmap_consignments (asset_id, json, sha256) VALUES ('a', x'7b7d', x'00');",
        )
        .unwrap();
        let c = latest_consignment(&conn, "a").expect("a legacy table must not error").unwrap();
        assert_eq!(c.asset_id, "a");
    }

    #[test]
    fn lading_of_an_expired_unmined_send_is_skipped() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE transactions (txid BLOB, mined_height INTEGER, expiry_height INTEGER);
             CREATE TABLE blocks (height INTEGER);
             INSERT INTO blocks VALUES (1000);",
        ).unwrap();
        let before = br#"{"wake_lading":1,"genesis":{"txid":"00","action_index":0},"hops":[]}"#;
        let extended = br#"{"wake_lading":1,"genesis":{"txid":"00","action_index":0},"hops":[1]}"#;
        let h_before = store_consignment(&conn, "a", None, Some(1), before, None).unwrap();
        let send = [7u8; 32];
        let h_ext = store_consignment(&conn, "a", None, None, extended, Some(&send)).unwrap();
        // The send is in the mempool (expiry ahead of the tip): the extended lading is live.
        conn.execute("INSERT INTO transactions VALUES (?1, NULL, 1040)", [send.as_slice()]).unwrap();
        assert_eq!(latest_consignment(&conn, "a").unwrap().unwrap().sha256, h_ext);
        // The send expired without mining: the earlier lading is live again.
        conn.execute("UPDATE transactions SET expiry_height = 900", []).unwrap();
        assert_eq!(latest_consignment(&conn, "a").unwrap().unwrap().sha256, h_before);
        // Mined: the extended lading is the one.
        conn.execute("UPDATE transactions SET mined_height = 950", []).unwrap();
        assert_eq!(latest_consignment(&conn, "a").unwrap().unwrap().sha256, h_ext);
    }
}
