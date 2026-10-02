//! A3b phase 2: audit one registered collection, in the wallet, from its viewing key alone.
//!
//! Written from `~/collections/audit/METHODOLOGY.md` §3–4, **not** from the mint's `audit.rs`
//! (`BOUNDARY.md` rule 3). The mint's `audit` and this must reach the same verdict; a disagreement
//! is a bug in one of them.
//!
//! 1. A view-only wallet for the collection's issuance account, in its own file under
//!    `collection_audits/` (public data only; never the user's `wallet.db`), synced from 8,000
//!    blocks before the registered mint height with the wallet's own engine.
//! 2. Every transaction the account took part in is fetched in full and decrypted with the
//!    viewing key: incoming outputs with the IVK, outgoing ones with the OVK.
//! 3. The 14 checks of METHODOLOGY §4, plus three that tie the result to the registration.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::collections::{trim, Registration};
use crate::issuance_v1::{derive_asset_id, verify_bip340};

pub const CLOSE_PREFIX: &[u8; 13] = b"zmap:close:v1";
pub const PIN_PREFIX: &[u8; 16] = b"zmap:manifest:v1";
const KIND_MANIFEST: u8 = 0;
const KIND_SIGNATURE: u8 = 1;
const CARRIER_ZAT: u64 = 10_000;
/// How far before the registered mint height the scan starts, so the account's funding is seen
/// (check 14 needs the notes the mint spent).
pub const BIRTHDAY_MARGIN: u32 = 8_000;

// ── formats (METHODOLOGY §3) ─────────────────────────────────────────────────────────────────

/// `"zmap:close:v1"(13) ‖ mode(1) ‖ generation(4) ‖ N(4) ‖ sha256(manifest)(32) ‖ ik(32) ‖ body`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close {
    pub generation: u32,
    pub count: u32,
    pub manifest_sha256: [u8; 32],
    pub ik: [u8; 32],
    /// Mode 0: the genesis commitments, in unit order.
    pub cmx: Vec<[u8; 32]>,
    /// Mode 1: sha256(cmx_1 ‖ … ‖ cmx_N).
    pub cmx_digest: Option<[u8; 32]>,
}

pub fn parse_close(memo: &[u8]) -> Option<Close> {
    let m = trim(memo);
    const FIXED: usize = 13 + 1 + 4 + 4 + 32 + 32;
    if m.len() < FIXED || &m[..13] != CLOSE_PREFIX {
        return None;
    }
    let mode = m[13];
    let generation = u32::from_be_bytes(m[14..18].try_into().ok()?);
    let count = u32::from_be_bytes(m[18..22].try_into().ok()?);
    let manifest_sha256: [u8; 32] = m[22..54].try_into().ok()?;
    let ik: [u8; 32] = m[54..86].try_into().ok()?;
    let body = &m[FIXED..];
    match mode {
        0 => {
            // Trailing zero padding was trimmed; a final cmx ending in zero bytes is restored by
            // padding the body back to N × 32. More than that is malformed.
            // `count` comes off the chain. Mode 0 carries the commitments inline, and a memo
            // holds 512 bytes, so more than 16 is malformed; without this bound a crafted count
            // asked for count × 32 bytes (registry review F2: 137 GB from u32::MAX).
            if count == 0 || count > 16 {
                return None;
            }
            let want = count as usize * 32;
            if body.len() > want {
                return None;
            }
            let mut b = body.to_vec();
            b.resize(want, 0);
            Some(Close { generation, count, manifest_sha256, ik, cmx: b.chunks(32).map(|c| c.try_into().unwrap()).collect(), cmx_digest: None })
        }
        1 => {
            if body.len() > 32 {
                return None;
            }
            let mut b = body.to_vec();
            b.resize(32, 0);
            Some(Close { generation, count, manifest_sha256, ik, cmx: vec![], cmx_digest: Some(b.try_into().unwrap()) })
        }
        _ => None,
    }
}

/// A 52-byte pin: `"zmap:manifest:v1"(16) ‖ generation(4) ‖ sha256(manifest)(32)`. The pin is
/// fixed-length, so it is read untrimmed-to-52 (a hash ending in zero bytes survives).
pub fn pin_matches(memo: &[u8], generation: u32, manifest_sha256: &[u8; 32]) -> bool {
    let m = trim(memo);
    if m.len() > 52 || m.len() < 20 || &m[..16] != PIN_PREFIX {
        return false;
    }
    let mut p = m.to_vec();
    p.resize(52, 0);
    p[16..20] == generation.to_be_bytes() && p[20..52] == manifest_sha256[..]
}

// ── the report ───────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub n: u32,
    pub label: String,
    pub pass: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unit {
    pub unit: u32,
    pub asset_id: String,
    pub desc: String,
    pub name: String,
    pub image_sha256: String,
    pub genesis_txid: String,
    pub genesis_action: u32,
    pub genesis_cmx: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub ik: String,
    pub name: String,
    pub passed: bool,
    pub checks: Vec<Check>,
    pub units: Vec<Unit>,
    pub close_height: Option<u32>,
    pub close_txid: Option<String>,
    pub count: Option<u32>,
    pub birthday: u32,
    pub audited_to: u32,
    pub node: String,
    pub audited_at: String,
    /// The manifest exactly as etched in the closing transaction (hex), and its BIP-340
    /// signature (hex). Phase 4: the issuance badge verifies these instead of a copy from
    /// zecboat.com. Absent in audits cached before phase 4.
    #[serde(default)]
    pub manifest_hex: Option<String>,
    #[serde(default)]
    pub signature_hex: Option<String>,
}

/// One decrypted output of a transaction the account took part in.
#[derive(Debug, Clone)]
pub struct Out {
    pub height: u32,
    pub txid: String,
    pub index: usize,
    pub value: u64,
    /// Extracted commitment of the Ironwood action at `index`, when the output is Ironwood.
    pub cmx: Option<[u8; 32]>,
    pub memo: Vec<u8>,
    pub outgoing: bool,
}

/// Per-transaction value flow, for check 14.
#[derive(Debug, Clone)]
pub struct Flow {
    pub txid: String,
    pub spent_known: u64,
    pub readable_out: u64,
    /// `None` when the transaction has transparent inputs (their value is not in the bundle).
    pub fee: Option<i64>,
    pub has_outgoing: bool,
}

/// F1 (2026-10-02 review): the outputs the account **issued**. Decryption proves only that a
/// key in the published UFVK can read an output: the IVK reads anything sent *to* the account,
/// and the OVK is public too, so anyone can craft an output that decrypts as "outgoing". What no
/// stranger can do is spend the account's notes. An output is the issuer's statement only when
/// its transaction spent at least one of the account's own notes (`spent_known > 0`). Without
/// this, one note sent to the issuance address with a crafted memo would fail checks 1, 9 and
/// 10 for everyone, forever; a legitimate return of a unit would fail check 9.
pub fn issued_outputs(outs: Vec<Out>, flows: &[Flow]) -> Vec<Out> {
    let issued: std::collections::HashSet<&str> =
        flows.iter().filter(|f| f.spent_known > 0).map(|f| f.txid.as_str()).collect();
    outs.into_iter().filter(|o| issued.contains(o.txid.as_str())).collect()
}

/// Check 14. Returns (violations, unaccountable). Both must be empty to pass.
pub fn value_accounting(flows: &[Flow]) -> (Vec<String>, Vec<String>) {
    let (mut bad, mut unknown) = (vec![], vec![]);
    for f in flows {
        let short = &f.txid[..f.txid.len().min(16)];
        if f.spent_known == 0 {
            if f.has_outgoing {
                unknown.push(format!("{short}…: sends value but none of its inputs were seen (birthday after the funding?)"));
            }
            continue;
        }
        let Some(fee) = f.fee else {
            unknown.push(format!("{short}…: transparent inputs; the fee cannot be derived"));
            continue;
        };
        let accounted = f.readable_out as i64 + fee;
        let spent = f.spent_known as i64;
        if spent > accounted {
            bad.push(format!("{short}…: {} zat left to outputs the published key cannot read", spent - accounted));
        } else if spent < accounted {
            unknown.push(format!("{short}…: more out than the inputs seen ({} zat); some inputs predate the birthday", accounted - spent));
        }
    }
    (bad, unknown)
}

/// The 14 checks and the registration cross-checks, over decrypted outputs. Pure: no network.
pub fn run_checks(reg: &Registration, ufvk: &str, outs: &[Out], flows: &[Flow]) -> (Vec<Check>, Vec<Unit>, Option<(u32, String, u32)>) {
    let mut checks = Vec::new();
    let mut add = |n: u32, label: &str, pass: bool, detail: Option<String>| {
        checks.push(Check { n, label: label.to_string(), pass, detail });
    };

    let closes: Vec<(&Out, Close)> = outs.iter().filter_map(|o| parse_close(&o.memo).map(|c| (o, c))).collect();
    add(1, "exactly one close memo", closes.len() == 1, Some(format!("{} found", closes.len())));
    let Some((close_out, close)) = closes.first().cloned() else {
        return (checks, vec![], None);
    };
    let close_height = close_out.height;
    let in_close: Vec<Vec<u8>> = outs.iter().filter(|o| o.txid == close_out.txid).map(|o| o.memo.clone()).collect();

    let manifest = crate::collections::reassemble(KIND_MANIFEST, &in_close);
    let sig = crate::collections::reassemble(KIND_SIGNATURE, &in_close);
    add(2, "manifest and signature reassemble from the close transaction's chunks", manifest.is_ok() && sig.is_ok(),
        manifest.as_ref().err().or(sig.as_ref().err()).cloned());
    let manifest = manifest.unwrap_or_default();
    // The signature is 64 bytes; trimming may have cut trailing zero bytes of its last chunk.
    let mut sig = sig.unwrap_or_default();
    if !sig.is_empty() && sig.len() < 64 {
        sig.resize(64, 0);
    }
    let mhash: [u8; 32] = Sha256::digest(&manifest).into();
    add(3, "sha256(etched manifest) equals the close memo's hash", mhash == close.manifest_sha256, None);
    add(4, "pin in the same transaction names the same generation and hash",
        in_close.iter().any(|m| pin_matches(m, close.generation, &mhash)), None);
    add(5, "BIP-340 signature over the manifest verifies under the close memo's ik",
        verify_bip340(&close.ik, &manifest, &sig), None);

    let v: serde_json::Value = serde_json::from_slice(&manifest).unwrap_or_default();
    let close_ik = hex::encode(close.ik);
    add(6, "manifest's ik equals the close memo's ik",
        v["identity"]["ik"].as_str().map(|s| s.eq_ignore_ascii_case(&close_ik)) == Some(true), None);
    add(7, "manifest names this viewing key as its issuance account",
        v["identity"]["issuance_ufvk"].as_str().map(str::trim) == Some(ufvk.trim()), None);

    // Carriers: JSON memos with asset_id and desc; a memo that names an ik must name this one.
    let carriers: Vec<(&Out, String, String)> = outs
        .iter()
        .filter(|o| o.memo.first() == Some(&b'{'))
        .filter_map(|o| {
            let j: serde_json::Value = serde_json::from_slice(&o.memo).ok()?;
            if let Some(mik) = j["ik"].as_str() {
                if !mik.eq_ignore_ascii_case(&close_ik) {
                    return None;
                }
            }
            Some((o, j["asset_id"].as_str()?.to_ascii_lowercase(), j["desc"].as_str()?.to_string()))
        })
        .collect();
    let before: Vec<&(&Out, String, String)> = carriers.iter().filter(|c| c.0.height < close_height).collect();
    let after = carriers.len() - before.len();
    add(8, "carriers issued before the close equal the close memo's count", before.len() as u32 == close.count,
        Some(format!("{} carriers, count {}", before.len(), close.count)));
    add(9, "no carrier issued by this account at or after the close", after == 0,
        (after > 0).then(|| format!("{after} after the close")));
    add(10, "every carrier's id derives from ik and its own description",
        !carriers.is_empty() && carriers.iter().all(|c| derive_asset_id(&close.ik, &c.2) == c.1), None);
    add(11, "every carrier is exactly 10,000 zat", before.iter().all(|c| c.0.value == CARRIER_ZAT), None);

    // Genesis, in unit order (the unit number is the description's third field).
    let mut by_unit: Vec<(u32, &Out, String, String)> = before
        .iter()
        .filter_map(|c| c.2.split('|').nth(2)?.parse::<u32>().ok().map(|u| (u, c.0, c.1.clone(), c.2.clone())))
        .collect();
    by_unit.sort_by_key(|x| x.0);
    let chain_cmx: Vec<[u8; 32]> = by_unit.iter().map(|x| x.1.cmx.unwrap_or([0; 32])).collect();
    let genesis_ok = match close.cmx_digest {
        None => chain_cmx == close.cmx,
        Some(d) => {
            let mut h = Sha256::new();
            chain_cmx.iter().for_each(|c| h.update(c));
            <[u8; 32]>::from(h.finalize()) == d
        }
    };
    add(12, "carrier commitments on chain equal the close memo's genesis list", genesis_ok && by_unit.len() == before.len(), None);
    let manifest_cmx: Vec<(String, String)> = v["assets"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| Some((x["asset_id"].as_str()?.to_ascii_lowercase(), x["issuance"]["cmx"].as_str()?.to_ascii_lowercase()))).collect())
        .unwrap_or_default();
    let manifest_ok = manifest_cmx.len() == by_unit.len()
        && by_unit.iter().all(|(_, o, id, _)| manifest_cmx.iter().any(|(mid, mc)| mid == id && *mc == hex::encode(o.cmx.unwrap_or([0; 32]))));
    add(13, "manifest's per-unit commitment equals the chain's, for every unit", manifest_ok, None);

    let (bad, unknown) = value_accounting(flows);
    let spending = flows.iter().filter(|f| f.spent_known > 0).count();
    let detail = bad.iter().chain(unknown.iter()).cloned().collect::<Vec<_>>().join("; ");
    add(14, "value accounting: every zatoshi spent went to readable outputs or the fee",
        bad.is_empty() && unknown.is_empty(),
        Some(if detail.is_empty() { format!("{spending} spending transaction(s)") } else { detail }));

    // Tie the audit to the registration that led here (registry claim C6).
    add(15, "registration's ik equals the close memo's ik", reg.ik.eq_ignore_ascii_case(&close_ik), None);
    add(16, "registration's closing transaction and height are the ones found", reg.close_txid.eq_ignore_ascii_case(&close_out.txid) && reg.close_height == close_height, None);
    add(17, "registration's manifest hash equals the etched manifest's", reg.manifest_sha256.eq_ignore_ascii_case(&hex::encode(mhash)), None);

    let units = by_unit
        .iter()
        .map(|(u, o, id, desc)| {
            let parts: Vec<&str> = desc.split('|').collect();
            Unit {
                unit: *u,
                asset_id: id.clone(),
                desc: desc.clone(),
                name: parts.get(3).unwrap_or(&"").to_string(),
                image_sha256: parts.get(5).unwrap_or(&"").to_string(),
                genesis_txid: o.txid.clone(),
                genesis_action: o.index as u32,
                genesis_cmx: hex::encode(o.cmx.unwrap_or([0; 32])),
            }
        })
        .collect();
    (checks, units, Some((close_height, close_out.txid.clone(), close.count)))
}

// ── the scan ─────────────────────────────────────────────────────────────────────────────────

fn audit_db_path(ufvk: &str) -> Result<String> {
    let tag = hex::encode(&Sha256::digest(ufvk.trim().as_bytes())[..8]);
    let dir = crate::paths::app_data_dir()?.join("collection_audits");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{tag}.db")).to_string_lossy().into_owned())
}

async fn client() -> Result<zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient<tonic::transport::Channel>> {
    let endpoint = crate::rpc::grpc_endpoint();
    zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient::connect(endpoint.clone())
        .await
        .map_err(|e| anyhow!("could not reach the node at {endpoint}: {e}"))
}

async fn ensure_account(db_path: &str, ufvk: &zcash_keys::keys::UnifiedFullViewingKey, birthday: u32) -> Result<()> {
    use zcash_client_backend::data_api::{chain::ChainState, AccountBirthday, AccountPurpose, WalletRead, WalletWrite};
    use zcash_client_sqlite::{util::SystemClock, WalletDb};
    use zcash_protocol::consensus::MainNetwork;

    let has_account = {
        let mut db = WalletDb::for_path(db_path, MainNetwork, SystemClock, rand::rngs::OsRng).map_err(|e| anyhow!("{e:?}"))?;
        zcash_client_sqlite::wallet::init::init_wallet_db(&mut db, None).map_err(|e| anyhow!("{e:?}"))?;
        !db.get_account_ids().map_err(|e| anyhow!("{e:?}"))?.is_empty()
    };
    if has_account {
        return Ok(());
    }
    let ts = client()
        .await?
        .get_tree_state(tonic::Request::new(zcash_client_backend::proto::service::BlockId { height: u64::from(birthday - 1), hash: vec![] }))
        .await
        .map_err(|e| anyhow!("cannot read the tree state at {}: {e}", birthday - 1))?
        .into_inner();
    let cs: ChainState = ts.to_chain_state().map_err(|e| anyhow!("malformed tree state: {e:?}"))?;
    let mut db = WalletDb::for_path(db_path, MainNetwork, SystemClock, rand::rngs::OsRng).map_err(|e| anyhow!("{e:?}"))?;
    db.import_account_ufvk("collection audit", ufvk, &AccountBirthday::from_parts(cs, None), AccountPurpose::ViewOnly, None)
        .map_err(|e| anyhow!("could not import the collection's viewing key: {e:?}"))?;
    Ok(())
}

async fn sync_to_tip(db_path: &str, floor: u32) -> Result<u32> {
    let mut retreat = 0usize;
    for _ in 0..100_000 {
        match crate::rpc::sync_pass(db_path).await? {
            crate::rpc::SyncStep::Advanced(_) => {}
            crate::rpc::SyncStep::AtTip(tip) => return Ok(tip),
            crate::rpc::SyncStep::Continuity(at) => {
                let steps = crate::rpc::SYNC_RETREAT_STEPS;
                let target = u32::from(at).saturating_sub(steps[retreat.min(steps.len() - 1)]).max(floor);
                crate::rpc::truncate_wallet_to(db_path, target)?;
                retreat += 1;
            }
        }
    }
    Err(anyhow!("the scan did not reach the tip"))
}

/// Fetch a transaction in full: (raw bytes, mined height).
async fn fetch_tx(txid_internal: &[u8]) -> Result<(Vec<u8>, u32)> {
    let mut last = None;
    for attempt in 0..5u64 {
        match client().await {
            Ok(mut c) => {
                let r = c
                    .get_transaction(tonic::Request::new(zcash_client_backend::proto::service::TxFilter {
                        block: None,
                        index: 0,
                        hash: txid_internal.to_vec(),
                    }))
                    .await;
                match r {
                    Ok(r) => {
                        let r = r.into_inner();
                        return Ok((r.data, r.height as u32));
                    }
                    Err(e) => last = Some(anyhow!("{e}")),
                }
            }
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2 * (attempt + 1))).await;
    }
    Err(last.unwrap_or_else(|| anyhow!("fetch failed")))
}

/// The account's mined transactions, and the value of its own notes each one spent (every
/// pool). Synchronous, so no database handle is held across an await.
fn read_account_txs(db_path: &str) -> Result<(Vec<(Vec<u8>, u32)>, HashMap<Vec<u8>, u64>)> {
    let conn = rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let txs: Vec<(Vec<u8>, u32)> = conn
        .prepare("SELECT txid, mined_height FROM transactions WHERE mined_height IS NOT NULL ORDER BY mined_height, id_tx")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let mut spent: HashMap<Vec<u8>, u64> = HashMap::new();
    let mut st = conn.prepare(
        "SELECT t.txid, v.value FROM v_received_output_spends s
           JOIN v_received_outputs v ON v.id_within_pool_table = s.received_output_id AND v.pool = s.pool
           JOIN transactions t ON t.id_tx = s.transaction_id",
    )?;
    for row in st.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))? {
        let (t, v) = row?;
        *spent.entry(t).or_default() += v as u64;
    }
    Ok((txs, spent))
}

/// Scan the collection's account, then decrypt every transaction it took part in.
async fn decrypted(db_path: &str, ufvk: &zcash_keys::keys::UnifiedFullViewingKey) -> Result<(Vec<Out>, Vec<Flow>)> {
    use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};

    let (txs, spent) = read_account_txs(db_path)?;

    let mut ufvks = HashMap::new();
    ufvks.insert(0u32, ufvk.clone());
    let mut outs = Vec::new();
    let mut flows = Vec::new();
    for (txid_internal, height) in txs {
        let mut disp = txid_internal.clone();
        disp.reverse();
        let txid = hex::encode(&disp);
        let (raw, _) = fetch_tx(&txid_internal).await.map_err(|e| anyhow!("fetch {}…: {e}", &txid[..12]))?;
        let tx = zcash_primitives::transaction::Transaction::read(&raw[..], BranchId::for_height(&MainNetwork, BlockHeight::from_u32(height)))
            .map_err(|e| anyhow!("{txid}: {e}"))?;
        let iw_cmx: Vec<[u8; 32]> = tx.ironwood_bundle().map(|b| b.actions().iter().map(|a| a.cmx().to_bytes()).collect()).unwrap_or_default();
        let fee: Option<i64> = {
            let mut f: i64 = 0;
            if let Some(b) = tx.sapling_bundle() { f += i64::from(*b.value_balance()); }
            if let Some(b) = tx.orchard_bundle() { f += i64::from(*b.value_balance()); }
            if let Some(b) = tx.ironwood_bundle() { f += i64::from(*b.value_balance()); }
            match tx.transparent_bundle() {
                Some(t) if !t.vin.is_empty() => None,
                Some(t) => Some(f - t.vout.iter().map(|o| u64::from(o.value()) as i64).sum::<i64>()),
                None => Some(f),
            }
        };
        let h = BlockHeight::from_u32(height);
        let d = zcash_client_backend::decrypt_transaction(&MainNetwork, Some(h), Some(h), &tx, &ufvks);
        let mut readable = 0u64;
        let mut has_outgoing = false;
        let mut push = |index: usize, value: u64, memo: &[u8], outgoing: bool, cmx: Option<[u8; 32]>| {
            readable += value;
            has_outgoing |= outgoing;
            outs.push(Out { height, txid: txid.clone(), index, value, cmx, memo: trim(memo).to_vec(), outgoing });
        };
        use zcash_client_backend::TransferType;
        for o in d.sapling_outputs() {
            push(o.index(), o.note_value().into_u64(), o.memo().as_slice(), matches!(o.transfer_type(), TransferType::Outgoing), None);
        }
        for o in d.orchard_outputs() {
            push(o.index(), o.note().0.value().inner(), o.memo().as_slice(), matches!(o.transfer_type(), TransferType::Outgoing), None);
        }
        for o in d.ironwood_outputs() {
            push(o.index(), o.note().0.value().inner(), o.memo().as_slice(), matches!(o.transfer_type(), TransferType::Outgoing), iw_cmx.get(o.index()).copied());
        }
        flows.push(Flow { txid, spent_known: spent.get(&txid_internal).copied().unwrap_or(0), readable_out: readable, fee, has_outgoing });
    }
    Ok((outs, flows))
}

/// One audit at a time.
static AUDITING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Audit a registered collection. The result is cached (see [`cached_audit`]).
pub async fn audit(reg: &Registration) -> Result<AuditReport> {
    let _one = AUDITING.try_lock().map_err(|_| anyhow!("an audit is already running"))?;
    if !reg.valid {
        return Err(anyhow!("this registration is invalid ({}); there is nothing trustworthy to audit", reg.reason.clone().unwrap_or_default()));
    }
    let ufvk_str = reg.ufvk.clone().ok_or_else(|| anyhow!("the registration carries no viewing key"))?;
    let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&zcash_protocol::consensus::MainNetwork, ufvk_str.trim())
        .map_err(|e| anyhow!("not a mainnet viewing key: {e}"))?;
    let birthday = reg.mint_height.saturating_sub(BIRTHDAY_MARGIN).max(1);
    let db = audit_db_path(&ufvk_str)?;
    ensure_account(&db, &ufvk, birthday).await?;
    let tip = sync_to_tip(&db, birthday).await?;
    let (outs, flows) = decrypted(&db, &ufvk).await?;
    let outs = issued_outputs(outs, &flows);
    let (checks, units, close) = run_checks(reg, &ufvk_str, &outs, &flows);
    let etched = close.as_ref().map(|c| etched_manifest(&outs, &c.1));
    let passed = checks.len() == 17 && checks.iter().all(|c| c.pass);
    let report = AuditReport {
        ik: reg.ik.clone(),
        name: reg.name.clone(),
        passed,
        checks,
        units,
        close_height: close.as_ref().map(|c| c.0),
        close_txid: close.as_ref().map(|c| c.1.clone()),
        count: close.as_ref().map(|c| c.2),
        birthday,
        audited_to: tip,
        node: crate::rpc::grpc_endpoint(),
        audited_at: chrono_now(),
        manifest_hex: etched.as_ref().map(|e| hex::encode(&e.0)),
        signature_hex: etched.as_ref().map(|e| hex::encode(&e.1)),
    };
    Ok(report)
}

/// The manifest and signature reassembled from the closing transaction's chunks.
fn etched_manifest(outs: &[Out], close_txid: &str) -> (Vec<u8>, Vec<u8>) {
    let memos: Vec<Vec<u8>> = outs.iter().filter(|o| o.txid == close_txid).map(|o| o.memo.clone()).collect();
    let manifest = crate::collections::reassemble(KIND_MANIFEST, &memos).unwrap_or_default();
    let mut sig = crate::collections::reassemble(KIND_SIGNATURE, &memos).unwrap_or_default();
    if !sig.is_empty() && sig.len() < 64 {
        sig.resize(64, 0);
    }
    (manifest, sig)
}

/// Phase 4: the registered collection whose **passed** audit lists `asset_id`, with the manifest
/// and signature it rebuilt from the chain. `None` if no passed audit lists it. No network.
pub fn audited_collection_listing(asset_id: &str) -> Option<AuditReport> {
    pick_listing(cached_audits().ok()?.into_iter().map(|(_, a)| a), asset_id)
}

/// The selection rule, pure: a report counts only if every one of the 17 checks passed, it kept
/// the etched manifest and signature, and it lists the unit.
pub fn pick_listing(reports: impl IntoIterator<Item = AuditReport>, asset_id: &str) -> Option<AuditReport> {
    reports.into_iter().find(|a| {
        a.passed
            && a.checks.len() == 17
            && a.checks.iter().all(|c| c.pass)
            && a.manifest_hex.is_some()
            && a.signature_hex.is_some()
            && a.units.iter().any(|u| u.asset_id.eq_ignore_ascii_case(asset_id))
    })
}

/// Seconds since the Unix epoch, as text; the UI formats it.
fn chrono_now() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{secs}")
}

// ── the cache, in registry.db ────────────────────────────────────────────────────────────────

fn cache() -> Result<rusqlite::Connection> {
    let c = rusqlite::Connection::open(crate::paths::registry_db_path()?)?;
    c.execute(
        "CREATE TABLE IF NOT EXISTS ext_zecboat_collection_audit (
            ik TEXT NOT NULL, registration_txid TEXT NOT NULL, report_json TEXT NOT NULL,
            PRIMARY KEY (ik, registration_txid))",
        [],
    )?;
    Ok(c)
}

/// The last audit of this registration, if any. No network.
pub fn cached_audit(ik: &str, registration_txid: &str) -> Result<Option<AuditReport>> {
    let c = cache()?;
    let json: Option<String> = c
        .query_row(
            "SELECT report_json FROM ext_zecboat_collection_audit WHERE ik = ?1 AND registration_txid = ?2",
            [ik, registration_txid],
            |r| r.get(0),
        )
        .ok();
    Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
}

/// Every cached audit, keyed `ik:registration_txid`. No network.
pub fn cached_audits() -> Result<Vec<(String, AuditReport)>> {
    let c = cache()?;
    let mut st = c.prepare("SELECT ik, registration_txid, report_json FROM ext_zecboat_collection_audit")?;
    let rows: Vec<(String, String, String)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
    Ok(rows
        .into_iter()
        .filter_map(|(ik, tx, j)| serde_json::from_str(&j).ok().map(|a| (format!("{tx}:{ik}"), a)))
        .collect())
}

/// Store under the registration it came from.
pub fn store_for(registration_txid: &str, r: &AuditReport) -> Result<()> {
    cache()?.execute(
        "INSERT OR REPLACE INTO ext_zecboat_collection_audit (ik, registration_txid, report_json) VALUES (?1, ?2, ?3)",
        rusqlite::params![r.ik, registration_txid, serde_json::to_string(r)?],
    )?;
    Ok(())
}

/// Audit the registration identified by `(ik, registration_txid)` from the last registry scan.
pub async fn audit_registered(ik: &str, registration_txid: &str) -> Result<AuditReport> {
    let reg = crate::collections::registry_view()?
        .registrations
        .into_iter()
        .find(|r| r.ik.eq_ignore_ascii_case(ik) && r.registration_txid.eq_ignore_ascii_case(registration_txid))
        .ok_or_else(|| anyhow!("that registration is not in the registry as last read; refresh first"))?;
    let report = audit(&reg).await?;
    store_for(registration_txid, &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(spent: u64, readable: u64, fee: Option<i64>, outgoing: bool) -> Flow {
        Flow { txid: "ab".repeat(32), spent_known: spent, readable_out: readable, fee, has_outgoing: outgoing }
    }

    #[test]
    fn value_accounting_passes_honest_flows() {
        let (b, u) = value_accounting(&[flow(300_000, 245_000, Some(55_000), true), flow(0, 300_000, Some(15_000), false)]);
        assert!(b.is_empty() && u.is_empty(), "{b:?} {u:?}");
    }

    #[test]
    fn value_to_an_unreadable_output_is_a_violation() {
        let (b, _) = value_accounting(&[flow(300_000, 235_000, Some(55_000), true)]);
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn unseen_inputs_and_transparent_inputs_are_unaccountable_not_passed() {
        assert_eq!(value_accounting(&[flow(0, 245_000, Some(55_000), true)]).1.len(), 1);
        assert_eq!(value_accounting(&[flow(100_000, 150_000, Some(5_000), false)]).1.len(), 1);
        assert_eq!(value_accounting(&[flow(100_000, 90_000, None, false)]).1.len(), 1);
    }

    fn close_memo(mode: u8, cmx: &[[u8; 32]]) -> Vec<u8> {
        let mut m = CLOSE_PREFIX.to_vec();
        m.push(mode);
        m.extend_from_slice(&1u32.to_be_bytes());
        m.extend_from_slice(&(cmx.len() as u32).to_be_bytes());
        m.extend_from_slice(&[0x11; 32]);
        m.extend_from_slice(&[0x22; 32]);
        if mode == 0 {
            cmx.iter().for_each(|c| m.extend_from_slice(c));
        } else {
            let mut h = Sha256::new();
            cmx.iter().for_each(|c| h.update(c));
            m.extend_from_slice(&h.finalize());
        }
        m.resize(512, 0);
        m
    }

    #[test]
    fn close_memos_parse_in_both_modes_including_a_trailing_zero_commitment() {
        let mut last = [0x33u8; 32];
        last[30] = 0;
        last[31] = 0;
        let cmx = vec![[0x44; 32], last];
        let c = parse_close(&close_memo(0, &cmx)).unwrap();
        assert_eq!((c.generation, c.count, c.ik), (1, 2, [0x22; 32]));
        assert_eq!(c.cmx, cmx, "a commitment ending in zero bytes must survive padding");
        let c = parse_close(&close_memo(1, &cmx)).unwrap();
        assert!(c.cmx_digest.is_some() && c.cmx.is_empty());
        assert!(parse_close(b"zmap:close:v1").is_none());
        let mut bad = close_memo(0, &cmx);
        bad[13] = 9;
        assert!(parse_close(&bad).is_none(), "unknown mode");
    }

    fn report(passed: bool, failing: Option<u32>, with_manifest: bool, unit: &str) -> AuditReport {
        AuditReport {
            ik: "ab".repeat(32),
            name: "Lagos Post Card".into(),
            passed,
            checks: (1..=17).map(|n| Check { n, label: String::new(), pass: Some(n) != failing, detail: None }).collect(),
            units: vec![Unit {
                unit: 7,
                asset_id: unit.into(),
                desc: String::new(),
                name: String::new(),
                image_sha256: String::new(),
                genesis_txid: String::new(),
                genesis_action: 6,
                genesis_cmx: String::new(),
            }],
            close_height: Some(1),
            close_txid: None,
            count: Some(10),
            birthday: 1,
            audited_to: 2,
            node: String::new(),
            audited_at: String::new(),
            manifest_hex: with_manifest.then(|| "7b7d".into()),
            signature_hex: with_manifest.then(|| "00".repeat(64)),
        }
    }

    /// Phase 4 trusts a registry collection only on a complete, passed audit that kept the
    /// etched manifest and lists the unit. Anything less must not become a Verified badge.
    #[test]
    fn only_a_fully_passed_audit_with_its_manifest_listing_the_unit_is_trusted() {
        let id = "5b742dc8".repeat(8);
        assert!(pick_listing(vec![report(true, None, true, &id)], &id).is_some());
        assert!(pick_listing(vec![report(false, Some(9), true, &id)], &id).is_none(), "a failed audit");
        assert!(pick_listing(vec![report(true, Some(14), true, &id)], &id).is_none(), "passed flag set but a check failed");
        assert!(pick_listing(vec![report(true, None, false, &id)], &id).is_none(), "audit cached before phase 4");
        assert!(pick_listing(vec![report(true, None, true, &"00".repeat(32))], &id).is_none(), "unit not listed");
        assert_eq!(pick_listing(vec![report(false, Some(9), true, &id), report(true, None, true, &id)], &id).map(|a| a.passed), Some(true));
    }

    #[test]
    fn pin_survives_a_hash_ending_in_zero() {
        let mut h = [0x55u8; 32];
        h[31] = 0;
        let mut m = PIN_PREFIX.to_vec();
        m.extend_from_slice(&7u32.to_be_bytes());
        m.extend_from_slice(&h);
        m.resize(512, 0);
        assert!(pin_matches(&m, 7, &h));
        assert!(!pin_matches(&m, 8, &h));
    }

    /// F1: a stranger's note sent to the issuance address (no spend by the account) is not an
    /// issuer statement, whatever its memo says; the account's own sends are.
    #[test]
    fn only_outputs_of_spending_transactions_count_as_issued() {
        let out = |txid: &str, memo: &[u8]| Out {
            height: 1, txid: txid.to_string(), index: 0, value: 10_000, cmx: None, memo: memo.to_vec(), outgoing: true,
        };
        let outs = vec![
            out("aa", b"{\"asset_id\":\"00\",\"ik\":\"11\",\"desc\":\"x\"}"),
            out("bb", b"zmap:close:v1 forged"),
            out("cc", b"{\"asset_id\":\"real\"}"),
        ];
        let flows = vec![
            Flow { txid: "aa".into(), spent_known: 0, readable_out: 10_000, fee: None, has_outgoing: true },
            Flow { txid: "bb".into(), spent_known: 0, readable_out: 1, fee: None, has_outgoing: true },
            Flow { txid: "cc".into(), spent_known: 50_000, readable_out: 10_000, fee: Some(10_000), has_outgoing: true },
        ];
        let kept: Vec<String> = issued_outputs(outs, &flows).into_iter().map(|o| o.txid).collect();
        assert_eq!(kept, vec!["cc".to_string()]);
    }

    /// F2: a close memo claiming u32::MAX inline commitments must be rejected, not allocated.
    #[test]
    fn a_huge_inline_count_is_malformed_not_allocated() {
        let mut m = b"zmap:close:v1".to_vec();
        m.push(0); // mode 0
        m.extend_from_slice(&1u32.to_be_bytes()); // generation
        m.extend_from_slice(&u32::MAX.to_be_bytes()); // count
        m.extend_from_slice(&[0x11; 32]); // manifest hash
        m.extend_from_slice(&[0x22; 32]); // ik
        assert!(parse_close(&m).is_none());
        let mut ok = m.clone();
        ok[18..22].copy_from_slice(&1u32.to_be_bytes());
        ok.extend_from_slice(&[0x33; 32]);
        assert_eq!(parse_close(&ok).map(|c| c.count), Some(1));
    }
}
