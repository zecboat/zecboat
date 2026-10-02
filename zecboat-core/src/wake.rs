//! Wake chapter 8: the wallet carries the lading (ZMAP v0.5 §15, §9 check 7; WAKE-v1 §8).
//!
//! What this module adds to a carrier transfer, in order:
//!
//! 1. **Prove before send.** The sender proves its own carrier note (a genesis proof if the
//!    issuer's manifest names this note as the asset's issuance output, a hop proof otherwise,
//!    appended to the lading it received) and hashes the resulting lading. The memo written on
//!    the new carrier commits to that hash. If the sender holds no lading and the note is not a
//!    genesis output, the unit can only travel *unproven*, and only if the user said so.
//! 2. **Deliver.** The lading is sealed to the recipient's address (`zmap_wake::seal`) and put
//!    in a drop-box keyed by its hash. The drop-box is a directory (`file://`) or an HTTP
//!    endpoint (`ZECBOAT_DROPBOX`, default `{registry}/dropbox`). Never plaintext, never listed.
//! 3. **Receive.** A carrier whose memo carries `consignment_hash` and no stored lading triggers
//!    a fetch; what comes back must open with this wallet's keys and hash to the memo's value.
//! 4. **Verify.** `verify_chain` against the node named by `ZECBOAT_ZEBRAD_RPC`, with the note
//!    in hand's ρ. The badge has four states and never collapses them (see [`WakeState`]).
//!
//! Every wallet read here is of *this* wallet's database, which is the one case the Wake
//! crate's `.AppVault` guard does not cover: the guard protects copies from being confused with
//! the live file, and here the live file is the point.

use anyhow::{anyhow, Result};
use rusqlite::Connection;
use serde::Serialize;
use std::path::PathBuf;
use zcash_protocol::consensus::{MainNetwork, Network};
use zmap_wake::lading::{lading_hash, Lading, ProofEntry};
use zmap_wake::oracle::{reversed, OracleTrust, ZebradOracle, MIN_DEPTH};
use zmap_wake::wallet_notes::{received_notes_in_tx_conn, witness_at, ReceivedNote};
use zmap_wake::{prove_genesis, prove_hop, verify_chain, WakeFailure};

type Db<P> = zcash_client_sqlite::WalletDb<Connection, P, zcash_client_sqlite::util::SystemClock, rand::rngs::OsRng>;

/// The node the wallet verifies and proves against.
pub fn oracle() -> ZebradOracle {
    ZebradOracle::new(crate::rpc::zebrad_rpc_endpoint())
}

// ── genesis lookup ───────────────────────────────────────────────────────────────────────────

/// Where a carrier's genesis outpoint came from, for the badge's wording.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisSource {
    /// `ZECBOAT_WAKE_MANIFEST`: a local v0.5 manifest file (a throwaway collection under test).
    LocalManifest,
    /// A pinned issuer's manifest, signature verified (`issuance.rs`).
    PinnedManifest,
    /// A3b phase 4: the manifest etched on chain, from a collection found in the pinned Zecboat
    /// Registry whose audit passed; signature verified the same way.
    Registry,
}

/// `(txid display hex, action_index, source)` of the asset's genesis output, or `None` if no
/// manifest this wallet trusts names one. Tried in order: the local manifest override, then the
/// pinned issuers over the network.
pub async fn genesis_outpoint(asset_id: &str) -> Option<(String, u32, GenesisSource)> {
    if let Some((t, i)) = genesis_from_local_manifest(asset_id) {
        return Some((t, i, GenesisSource::LocalManifest));
    }
    crate::issuance::genesis_outpoint(asset_id)
        .await
        .map(|(t, i, via_registry)| (t, i, if via_registry { GenesisSource::Registry } else { GenesisSource::PinnedManifest }))
}

/// The local manifest override alone (`ZECBOAT_WAKE_MANIFEST`), for headless callers.
pub fn genesis_from_local_manifest(asset_id: &str) -> Option<(String, u32)> {
    let path = std::env::var("ZECBOAT_WAKE_MANIFEST").ok()?;
    let bytes = std::fs::read(&path).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    // v0.5 shape as the mint tool writes it: entries[{asset_id, index: "3/4" | unit: 3,
    // txid?, output_index?}] + genesis[{unit, txid, action_index}]. The entry's own
    // (txid, output_index) is accepted when present; otherwise genesis[] is joined on the unit.
    let entry = v
        .get("entries")?
        .as_array()?
        .iter()
        .find(|e| e.get("asset_id").and_then(|a| a.as_str()) == Some(asset_id))?;
    if let (Some(t), Some(i)) = (
        entry.get("txid").and_then(|t| t.as_str()),
        entry.get("output_index").and_then(|i| i.as_u64()),
    ) {
        return Some((t.to_ascii_lowercase(), i as u32));
    }
    let unit = entry.get("unit").or_else(|| entry.get("index"))?;
    let unit = match unit {
        serde_json::Value::Number(n) => n.as_u64()?,
        serde_json::Value::String(s) => s.split('/').next()?.trim().parse().ok()?,
        _ => return None,
    };
    let g = v
        .get("genesis")?
        .as_array()?
        .iter()
        .find(|g| g.get("unit").and_then(|u| u.as_u64()) == Some(unit))?;
    Some((
        g.get("txid")?.as_str()?.to_ascii_lowercase(),
        g.get("action_index")?.as_u64()? as u32,
    ))
}

// ── the note behind a carrier ────────────────────────────────────────────────────────────────

/// The received note of carrier `(txid_internal, output_index)`, with its keys and position.
/// `txid_internal` is the stored (byte-reversed) order, as `CarrierRef::txid_bytes` holds it.
pub fn carrier_note(conn: &Connection, txid_internal: &[u8; 32], output_index: u32) -> Result<ReceivedNote> {
    let display = reversed(*txid_internal);
    let notes = received_notes_in_tx_conn(conn, Network::MainNetwork, &display)?;
    notes
        .into_iter()
        .find(|n| n.action_index == output_index)
        .ok_or_else(|| anyhow!("carrier output {} of {} is not among this wallet's received notes", output_index, hex::encode(display)))
}

// ── proving before send ──────────────────────────────────────────────────────────────────────

/// What `send_zmap_asset` needs to know about Wake before it builds the transfer.
#[derive(Clone, Debug, Default)]
pub struct SendOptions {
    /// The asset's genesis outpoint per a trusted manifest, looked up by the async caller.
    pub genesis: Option<(String, u32)>,
    /// The user acknowledged that the unit arrives unproven if no lading can be made.
    pub acknowledge_unproven: bool,
}

/// A lading produced for a transfer, ready to hash into the memo and deliver.
#[derive(Clone, Debug)]
pub struct SendLading {
    pub bytes: Vec<u8>,
    pub hash_hex: String,
    pub hops: usize,
}

/// Prefix of the error a send returns when the unit would arrive unproven and the user has not
/// acknowledged it. The UI keys its dialog on this.
pub const UNPROVEN_PREFIX: &str = "WAKE_UNPROVEN:";

/// Prove the carrier the sender is about to spend and extend (or start) its lading.
///
/// Returns `Ok(None)` when no lading can honestly be made: the wallet holds none for this asset
/// and no trusted manifest names this note as the genesis output. A proof failure is an error;
/// the caller aborts the send (chapter 8: "prove_hop BEFORE broadcast; abort send if proving
/// fails").
pub fn prepare_send_lading<P: zcash_protocol::consensus::Parameters>(
    wallet_db: &Db<P>,
    conn: &Connection,
    asset_id: &str,
    carrier_txid_internal: &[u8; 32],
    output_index: u32,
    genesis: Option<&(String, u32)>,
    oracle: &ZebradOracle,
) -> Result<Option<SendLading>> {
    let note = carrier_note(conn, carrier_txid_internal, output_index)?;
    let note_txid_hex = hex::encode(note.txid_display);
    let note_rho = note.note.rho().to_bytes();

    let mut lading = match crate::zmap::latest_consignment(conn, asset_id)? {
        Some(c) => {
            let l = Lading::parse(&c.json).map_err(|e| anyhow!("the stored lading for {asset_id} is unreadable: {e}"))?;
            let last = l.hops.last().ok_or_else(|| anyhow!("the stored lading for {asset_id} has no proofs"))?;
            let last_nf = zmap_wake::oracle::decode_hex_32(&last.instance[2])?;
            if last_nf != note_rho {
                return Err(anyhow!(
                    "the stored lading for {asset_id} does not end at the carrier being spent \
                     (its last nullifier is not this note's rho); refusing to extend a chain \
                     this note is not on"
                ));
            }
            l
        }
        None => match genesis {
            Some((g_txid, g_idx)) if g_txid.eq_ignore_ascii_case(&note_txid_hex) && *g_idx == note.action_index => {
                Lading::new(&note_txid_hex, note.action_index)
            }
            _ => return Ok(None),
        },
    };

    // The anchor is the note's own mined height: the deepest tree state that contains it, so
    // the recipient's verifier is not made to wait for confirmations the chain already has.
    let ts = oracle
        .ironwood_tree_state(note.mined_height)
        .map_err(|e| anyhow!("could not fetch the tree state at height {} from the node: {e}", note.mined_height))?;
    let w = witness_at(wallet_db, &note, &ts)?;
    let proof = if lading.hops.is_empty() { prove_genesis(&w) } else { prove_hop(&w) }
        .map_err(|e| anyhow!("Wake proof failed: {e:?}"))?;
    lading.hops.push(ProofEntry::from_proof(&proof, note.mined_height));

    let bytes = lading.to_bytes();
    let hash_hex = hex::encode(lading_hash(&bytes));
    Ok(Some(SendLading { hops: lading.hops.len(), bytes, hash_hex }))
}

// ── sealing and the drop-box ─────────────────────────────────────────────────────────────────

/// Seal `bytes` to the Orchard receiver of `recipient_ua`.
pub fn seal_for(recipient_ua: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let addr = match zcash_keys::address::Address::decode(&MainNetwork, recipient_ua) {
        Some(zcash_keys::address::Address::Unified(ua)) => *ua
            .orchard()
            .ok_or_else(|| anyhow!("the recipient's unified address has no Orchard receiver"))?,
        _ => return Err(anyhow!("a lading can only be sealed to a unified address")),
    };
    let sealed = zmap_wake::seal::seal(&addr, bytes, &mut rand::rngs::OsRng)?;
    Ok(sealed.to_bytes())
}

/// The drop-box base. `file://<dir>` for a shared directory, otherwise an HTTP base URL.
pub fn dropbox_base() -> String {
    std::env::var("ZECBOAT_DROPBOX")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{}/dropbox", crate::rpc::registry_base()))
}

fn dropbox_file(base: &str, hash_hex: &str) -> PathBuf {
    PathBuf::from(base.trim_start_matches("file://")).join(format!("{hash_hex}.json"))
}

/// Put a sealed lading under its hash. Overwrites nothing: the first delivery stands.
pub fn dropbox_put(hash_hex: &str, sealed: &[u8]) -> Result<()> {
    let base = dropbox_base();
    if base.starts_with("file://") {
        let path = dropbox_file(&base, hash_hex);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        if !path.exists() {
            std::fs::write(&path, sealed)?;
        }
        return Ok(());
    }
    let url = format!("{base}/{hash_hex}");
    let res = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?
        .put(&url)
        .header("content-type", "application/json")
        .body(sealed.to_vec())
        .send()
        .map_err(|e| anyhow!("{url}: {e}"))?;
    if !res.status().is_success() {
        return Err(anyhow!("{url}: HTTP {}", res.status()));
    }
    Ok(())
}

/// Fetch a sealed lading by hash. `Ok(None)` when the drop-box has nothing under it.
pub fn dropbox_get(hash_hex: &str) -> Result<Option<Vec<u8>>> {
    let base = dropbox_base();
    if base.starts_with("file://") {
        let path = dropbox_file(&base, hash_hex);
        return match std::fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        };
    }
    let url = format!("{base}/{hash_hex}");
    let res = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?
        .get(&url)
        .send()
        .map_err(|e| anyhow!("{url}: {e}"))?;
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !res.status().is_success() {
        return Err(anyhow!("{url}: HTTP {}", res.status()));
    }
    Ok(Some(res.bytes()?.to_vec()))
}

/// Deliver a lading for a sent carrier: seal to the recipient and put it in the drop-box.
pub fn deliver(recipient_ua: &str, lading: &SendLading) -> Result<()> {
    let sealed = seal_for(recipient_ua, &lading.bytes)?;
    dropbox_put(&lading.hash_hex, &sealed)
}

// ── receiving ────────────────────────────────────────────────────────────────────────────────

/// What a fetch pass did.
#[derive(Clone, Debug, Default, Serialize)]
pub struct FetchReport {
    pub fetched: usize,
    pub already_held: usize,
    pub not_in_dropbox: usize,
    pub failed: Vec<String>,
}

/// For every held carrier whose memo commits to a lading this wallet does not hold, try the
/// drop-box. What comes back must open with this wallet's keys and hash to the memo's value.
pub fn fetch_missing_consignments(db_path: &str) -> Result<FetchReport> {
    let conn = Connection::open(db_path)?;
    let holdings = crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn)?);
    let mut report = FetchReport::default();
    for h in &holdings {
        for c in &h.carriers {
            let Some(hash) = c.consignment_hash.as_deref() else { continue };
            if crate::zmap::consignment_by_hash(&conn, hash)?.is_some() {
                report.already_held += 1;
                continue;
            }
            let sealed = match dropbox_get(hash) {
                Ok(Some(b)) => b,
                Ok(None) => { report.not_in_dropbox += 1; continue; }
                Err(e) => { report.failed.push(format!("{}: {e}", h.name)); continue; }
            };
            let result = (|| -> Result<()> {
                let note = carrier_note(&conn, &c.txid_bytes, c.output_index as u32)?;
                let sealed = zmap_wake::seal::Sealed::parse(&sealed)?;
                let bytes = zmap_wake::seal::open(&note.fvk, &sealed)?;
                if hex::encode(lading_hash(&bytes)) != hash {
                    return Err(anyhow!("the delivered lading does not hash to the memo's consignment_hash"));
                }
                Lading::parse(&bytes)?;
                crate::zmap::store_consignment(&conn, &h.asset_id, None, Some(c.note_id), &bytes, None)?;
                Ok(())
            })();
            match result {
                Ok(()) => report.fetched += 1,
                Err(e) => report.failed.push(format!("{}: {e}", h.name)),
            }
        }
    }
    Ok(report)
}

/// Async wrapper for the UI: fetch whatever is missing, off the executor.
pub async fn fetch_consignments() -> Result<FetchReport> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    tokio::task::spawn_blocking(move || fetch_missing_consignments(&db_path))
        .await
        .map_err(|e| anyhow!("fetch did not finish: {e}"))?
}

// ── verification and the badge ───────────────────────────────────────────────────────────────

/// The lineage badge. Four states, never one tick (ZMAP v0.5 §9 check 7).
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WakeState {
    /// The lading verified against a full node this wallet chose, and its genesis output is the
    /// one a trusted manifest names for this asset.
    Verified {
        hops: usize,
        min_anchor_depth: u32,
        genesis_txid: String,
        genesis_action_index: u32,
        genesis_source: GenesisSource,
        consignment_hash: String,
    },
    /// The proofs and chain rule held, but something outside them could not be confirmed: the
    /// oracle only relays a server's answers, an anchor is not yet deep enough, or no trusted
    /// manifest confirms the genesis output. **Not** a verdict against the asset.
    Unverified { detail: String, consignment_hash: Option<String> },
    /// No lading is held for this asset. Unproven, distinct from forged.
    NoWake { detail: String },
    /// The lading is evidence of forgery or tampering: a proof failed, the chain rule broke,
    /// the genesis commitment is not on chain, the bytes do not match the memo's hash, or the
    /// note in hand is not the chain's final note.
    Broken { failure: String, detail: String },
}

fn classify(e: &WakeFailure) -> bool {
    matches!(
        e,
        WakeFailure::LadingHashMismatch
            | WakeFailure::GenesisNotOnChain
            | WakeFailure::BadProof(_)
            | WakeFailure::ChainBreak(_)
            | WakeFailure::RhoMismatch
    )
}

/// Verify the lading held for `asset_id` against the node, for the carrier the wallet would
/// spend next (the same deterministic choice `plan_asset_send` makes).
pub fn verify_holding(db_path: &str, asset_id: &str, genesis: Option<&(String, u32, GenesisSource)>) -> Result<WakeState> {
    let conn = Connection::open(db_path)?;
    let holdings = crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn)?);
    let Some(h) = holdings.iter().find(|h| h.asset_id == asset_id) else {
        return Ok(WakeState::NoWake { detail: "this wallet holds no carrier of that asset".into() });
    };
    let Some(carrier) = h.carriers.iter().min_by_key(|c| (c.txid.clone(), c.output_index)) else {
        return Ok(WakeState::NoWake { detail: "no unspent carrier".into() });
    };
    let Some(consignment) = crate::zmap::latest_consignment(&conn, asset_id)? else {
        return Ok(WakeState::NoWake {
            detail: match &carrier.consignment_hash {
                Some(hh) => format!("the memo commits to lading {}… but it has not been fetched", &hh[..16]),
                None => "the sender attached no lading (the memo carries no consignment_hash)".into(),
            },
        });
    };

    let note = carrier_note(&conn, &carrier.txid_bytes, carrier.output_index as u32)?;
    let expected = carrier
        .consignment_hash
        .as_deref()
        .and_then(|hh| hex::decode(hh).ok())
        .and_then(|v| <[u8; 32]>::try_from(v).ok());
    let oracle = oracle();
    let lading = Lading::parse(&consignment.json).map_err(|e| anyhow!("stored lading unreadable: {e}"))?;

    match verify_chain(&consignment.json, expected, &note.note.rho(), &oracle, MIN_DEPTH) {
        Ok(v) => {
            let g_ok = genesis.map(|(t, i, _)| t.eq_ignore_ascii_case(&lading.genesis.txid) && *i == lading.genesis.action_index);
            if v.trust != OracleTrust::FullNode {
                return Ok(WakeState::Unverified {
                    detail: format!("the Wake oracle at {} is not a node on this machine, so its anchors are a server's word, not checked against your own headers; set ZECBOAT_ZEBRAD_RPC to your own zebrad for Verified", crate::rpc::zebrad_rpc_endpoint()),
                    consignment_hash: Some(consignment.sha256.clone()),
                });
            }
            match g_ok {
                Some(true) => {
                    let _ = crate::zmap::mark_consignment_verified(&conn, &consignment.sha256, Some(oracle.tip_height().unwrap_or(0)));
                    Ok(WakeState::Verified {
                        hops: v.hops,
                        min_anchor_depth: v.min_anchor_depth,
                        genesis_txid: lading.genesis.txid.clone(),
                        genesis_action_index: lading.genesis.action_index,
                        genesis_source: genesis.map(|g| g.2.clone()).unwrap_or(GenesisSource::PinnedManifest),
                        consignment_hash: consignment.sha256.clone(),
                    })
                }
                Some(false) => Ok(WakeState::Broken {
                    failure: "GenesisMismatch".into(),
                    detail: format!(
                        "the lading descends from {}… output {}, but the issuer's manifest names a different genesis output for this asset",
                        &lading.genesis.txid[..16],
                        lading.genesis.action_index
                    ),
                }),
                None => Ok(WakeState::Unverified {
                    detail: format!(
                        "the chain of {} proof(s) verified against the node, but no trusted manifest could confirm that {}… output {} is this asset's genesis",
                        v.hops,
                        &lading.genesis.txid[..16],
                        lading.genesis.action_index
                    ),
                    consignment_hash: Some(consignment.sha256.clone()),
                }),
            }
        }
        Err(e) if classify(&e) => {
            let _ = crate::zmap::mark_consignment_verified(&conn, &consignment.sha256, None);
            Ok(WakeState::Broken { failure: format!("{e:?}").split(|c: char| !c.is_alphanumeric()).next().unwrap_or("Failure").to_string(), detail: e.to_string() })
        }
        Err(e) => Ok(WakeState::Unverified { detail: e.to_string(), consignment_hash: Some(consignment.sha256.clone()) }),
    }
}

/// The lineage badge for one asset, for the UI.
pub async fn verify_lineage(asset_id: String) -> Result<WakeState> {
    let genesis = genesis_outpoint(&asset_id).await;
    let db_path = crate::paths::as_string::wallet_db_path()?;
    tokio::task::spawn_blocking(move || verify_holding(&db_path, &asset_id, genesis.as_ref()))
        .await
        .map_err(|e| anyhow!("verification did not finish: {e}"))?
}

/// After a restore: re-verify every held asset that has a lading, and say how it went. Never
/// fails the restore; the wallet is back either way.
pub async fn reverify_after_restore() -> String {
    let Ok(db_path) = crate::paths::as_string::wallet_db_path() else { return String::new() };
    let holdings = {
        let p = db_path.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<String>> {
            let conn = Connection::open(&p)?;
            let mut ids: Vec<String> = crate::zmap::list_consignments(&conn)?.into_iter().map(|c| c.asset_id).collect();
            ids.sort();
            ids.dedup();
            Ok(ids)
        })
        .await
    };
    let ids = match holdings {
        Ok(Ok(ids)) => ids,
        _ => return String::new(),
    };
    if ids.is_empty() {
        return " No ladings were in the backup.".to_string();
    }
    let (mut ok, mut other, mut broken) = (0, 0, 0);
    for id in ids {
        match verify_lineage(id).await {
            Ok(WakeState::Verified { .. }) => ok += 1,
            Ok(WakeState::Broken { .. }) => broken += 1,
            _ => other += 1,
        }
    }
    format!(
        " Ladings restored: {ok} verified against the node, {other} could not be verified right now, {broken} broken."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_manifest_lookup_reads_the_v05_shape() {
        let dir = std::env::temp_dir().join(format!("wake-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("m.json");
        std::fs::write(&p, br#"{"entries":[{"asset_id":"aa","index":"2/4"},{"asset_id":"bb","unit":1},
            {"asset_id":"dd","index":"4/4","txid":"AB","output_index":7}],
            "genesis":[{"unit":1,"txid":"14B8","action_index":2},{"unit":2,"txid":"14b8","action_index":0}]}"#).unwrap();
        std::env::set_var("ZECBOAT_WAKE_MANIFEST", &p);
        assert_eq!(genesis_from_local_manifest("aa"), Some(("14b8".into(), 0)));
        assert_eq!(genesis_from_local_manifest("bb"), Some(("14b8".into(), 2)));
        assert_eq!(genesis_from_local_manifest("dd"), Some(("ab".into(), 7)));
        assert_eq!(genesis_from_local_manifest("cc"), None);
        std::env::remove_var("ZECBOAT_WAKE_MANIFEST");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_dropbox_round_trip() {
        let dir = std::env::temp_dir().join(format!("wake-dropbox-{}", std::process::id()));
        std::env::set_var("ZECBOAT_DROPBOX", format!("file://{}", dir.display()));
        let h = "ab".repeat(32);
        assert_eq!(dropbox_get(&h).unwrap(), None);
        dropbox_put(&h, b"sealed-1").unwrap();
        dropbox_put(&h, b"sealed-2").unwrap(); // first delivery stands
        assert_eq!(dropbox_get(&h).unwrap().as_deref(), Some(&b"sealed-1"[..]));
        std::env::remove_var("ZECBOAT_DROPBOX");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seal_for_needs_a_unified_address_with_orchard() {
        assert!(seal_for("t1abc", b"x").is_err());
    }
}
