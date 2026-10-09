//! Wake chapter 8: the wallet carries the lading (ZMAP v0.5 §15, §9 check 7; WAKE-v1 §8).
//!
//! What this module adds to a carrier transfer, in order:
//!
//! 1. **Prove before send.** The sender proves its own carrier note (a genesis proof if the
//!    issuer's manifest names this note as the asset's issuance output, a hop proof otherwise,
//!    appended to the lading it received) and hashes the resulting lading. The memo written on
//!    the new carrier commits to that hash. If the sender holds no lading and the note is not a
//!    genesis output, the unit can only travel *unproven*, and only if the user said so.
//! 2. **Deliver.** 0.7.1: the lading travels in the transfer itself (Knotline, `wake_memo`).
//!    The sealed-file route remains for the cases that does not cover, and a drop-box
//!    (a `file://` folder or an `https://` endpoint) only if the user names one; none is
//!    contacted by default. Never plaintext, never listed.
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
use zmap_wake::oracle::{reversed, AnchorStatus, ChainOracle, IronwoodAction, IronwoodTreeState, OracleTrust, ZebradOracle, MIN_DEPTH};
use zmap_wake::oracle_lightwalletd::LightwalletdOracle;
use zmap_wake::wallet_notes::{received_notes_in_tx_conn, witness_at, ReceivedNote};
use zmap_wake::{prove_genesis, prove_hop, verify_chain, WakeFailure};

type Db<P> = zcash_client_sqlite::WalletDb<Connection, P, zcash_client_sqlite::util::SystemClock, rand::rngs::OsRng>;

/// Where this wallet asks the chain its lineage and issuance questions (0.7.1).
///
/// Wake asks three things only: the tree state at a height, a mined transaction's outputs, and
/// the tip. A zebrad answers them, and so does any lightwalletd-protocol server. Until 0.7.1 the
/// wallet could only ask a zebrad, so a wallet without one could neither check a lineage nor
/// send a unit that had one.
pub enum Chain {
    /// A zebrad answered at `ZECBOAT_ZEBRAD_RPC`. Self-validated only when it is on this machine.
    Node(ZebradOracle, String),
    /// No node answered: the wallet's own provider, the light server chosen in Settings.
    Provider(LightwalletdOracle),
}

/// Who answers questions about the chain. `Auto`: the node if it answers at that moment,
/// otherwise the provider. `Node`: the node at `ZECBOAT_ZEBRAD_RPC`, and nobody else; when it
/// does not answer the result is "could not be checked right now". `Provider`: the light
/// server from Settings, always.
///
/// Until 2026-10-08 the choice was always `Auto`, so a wallet whose node was briefly silent
/// (starting up, say) asked the provider instead, without a word: the provider learnt the
/// blocks of every transfer in a line, which the wallet had promised nobody would (audit,
/// Knotline C). A node user who chooses `Node` gets no silent fallback. The choice is made in
/// Settings and restored at start like the lineage route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainChoice {
    Auto,
    Node,
    Provider,
}

static CHAIN_CHOICE: std::sync::Mutex<Option<ChainChoice>> = std::sync::Mutex::new(None);

/// From Settings: `auto`, `node`, `provider`, or empty for the default (`auto`).
pub fn set_chain_choice(choice: &str) -> Result<()> {
    set_chain_choice_in_memory(choice)?;
    if let Some(f) = chain_choice_file() {
        let _ = std::fs::write(f, choice.trim());
    }
    Ok(())
}

/// For the UI: `(choice, source)` where source is `settings`, `default (decided at start)`.
pub fn chain_choice_with_source() -> (&'static str, &'static str) {
    match effective_chain_choice() {
        (ChainChoice::Node, true) => ("node", "settings"),
        (ChainChoice::Provider, true) => ("provider", "settings"),
        (ChainChoice::Auto, true) => ("auto", "settings"),
        (ChainChoice::Node, false) => ("node", "default (decided at start)"),
        (ChainChoice::Provider, false) => ("provider", "default (decided at start)"),
        (ChainChoice::Auto, false) => ("auto", "default"),
    }
}

/// The file beside the wallet that keeps the user's chain-source choice across restarts. Until
/// 2026-10-09 the choice lived in the webview's storage only and a fresh profile silently
/// returned to the fallback (review, regression Finding 7).
fn chain_choice_file() -> Option<std::path::PathBuf> {
    crate::paths::app_data_dir().ok().map(|d| d.join("chain_source"))
}

static STARTUP_CHOICE: std::sync::Mutex<Option<ChainChoice>> = std::sync::Mutex::new(None);
static PERSISTED_LOADED: std::sync::Once = std::sync::Once::new();

/// `(choice, chosen by the user)`. With no user choice the default is decided **once**, at the
/// first chain question of the process: the wallet's own node when a loopback zebrad answers
/// then, the provider otherwise. It does not move afterwards, so a node that goes quiet makes
/// the badge say "could not be verified right now" instead of silently becoming the provider's
/// word (review 2026-10-09, regression Finding 7). `auto`, the per-call fallback, remains a
/// choice the user can make in Settings.
fn effective_chain_choice() -> (ChainChoice, bool) {
    PERSISTED_LOADED.call_once(|| {
        if let Some(f) = chain_choice_file() {
            if let Ok(text) = std::fs::read_to_string(f) {
                let _ = set_chain_choice_in_memory(text.trim());
            }
        }
    });
    if let Some(c) = *CHAIN_CHOICE.lock().unwrap() {
        return (c, true);
    }
    // Decided at the first question, and moved in one direction only: a default that landed on
    // the provider because the node was silent at that moment (the ordinary boot race) asks the
    // node again at every later question and switches to it the moment it answers; it never
    // goes back. One silent moment used to send the whole session to the provider (review
    // 2026-10-09, regression over 12-13, Issue C).
    let mut startup = STARTUP_CHOICE.lock().unwrap();
    let endpoint = crate::rpc::zebrad_rpc_endpoint();
    match *startup {
        Some(ChainChoice::Node) => (ChainChoice::Node, false),
        _ => {
            let answers = zmap_wake::oracle::is_local_url(&endpoint) && ZebradOracle::new(endpoint).tip_height().is_ok();
            let c = if answers { ChainChoice::Node } else { ChainChoice::Provider };
            *startup = Some(c);
            (c, false)
        }
    }
}

fn set_chain_choice_in_memory(choice: &str) -> Result<()> {
    let c = match choice.trim() {
        "" => None,
        "node" => Some(ChainChoice::Node),
        "provider" => Some(ChainChoice::Provider),
        "auto" => Some(ChainChoice::Auto),
        other => return Err(anyhow!("unknown chain source {other:?}")),
    };
    *CHAIN_CHOICE.lock().unwrap() = c;
    Ok(())
}

/// The chain source for this call, by [`ChainChoice`].
///
/// The probe is one `getblockcount`; with no node on the machine it is refused at once.
pub fn chain() -> Chain {
    let endpoint = crate::rpc::zebrad_rpc_endpoint();
    let node = ZebradOracle::new(endpoint.clone());
    let choice = effective_chain_choice().0;
    let provider = || LightwalletdOracle::new(crate::rpc::grpc_endpoint(), Network::MainNetwork);
    match choice {
        ChainChoice::Node => Chain::Node(node, endpoint),
        ChainChoice::Provider => match provider() {
            Ok(p) => Chain::Provider(p),
            Err(_) => Chain::Node(node, endpoint),
        },
        ChainChoice::Auto => {
            if node.tip_height().is_ok() {
                return Chain::Node(node, endpoint);
            }
            match provider() {
                Ok(p) => Chain::Provider(p),
                Err(_) => Chain::Node(node, endpoint),
            }
        }
    }
}

impl Chain {
    /// The address being asked, for messages.
    pub fn endpoint(&self) -> String {
        match self {
            Chain::Node(_, url) => url.clone(),
            Chain::Provider(p) => p.url().to_string(),
        }
    }

    pub fn tip_height(&self) -> Result<u32> {
        match self {
            Chain::Node(n, _) => n.tip_height(),
            Chain::Provider(p) => p.tip_height(),
        }
    }

    pub fn ironwood_tree_state(&self, height: u32) -> Result<IronwoodTreeState> {
        match self {
            Chain::Node(n, _) => n.ironwood_tree_state(height),
            Chain::Provider(p) => p.ironwood_tree_state(height),
        }
    }

    /// The Ironwood Actions of a mined transaction; `txid_hex` in display order.
    pub fn ironwood_actions(&self, txid_hex: &str) -> Result<Option<(u32, Vec<IronwoodAction>)>> {
        match self {
            Chain::Node(n, _) => n.ironwood_actions(txid_hex),
            Chain::Provider(p) => p.ironwood_actions(&zmap_wake::oracle::decode_hex_32(txid_hex)?),
        }
    }

    /// Say which block a transaction is mined in (`txid_hex` in display order), when that is
    /// already known. A provider then fetches it among the other transactions of that block,
    /// and so is not told which transaction this wallet wanted. A node of one's own needs no
    /// such cover.
    pub fn hint_height(&self, txid_hex: &str, height: u32) {
        if let Chain::Provider(p) = self {
            if let Ok(txid) = zmap_wake::oracle::decode_hex_32(txid_hex) {
                p.hint_height(&txid, height);
            }
        }
    }

    /// The raw bytes and height of a mined transaction; `txid_internal` in stored byte order.
    pub fn raw_transaction(&self, txid_internal: &[u8; 32]) -> Result<Option<(u32, Vec<u8>)>> {
        let display = reversed(*txid_internal);
        match self {
            Chain::Node(n, _) => n.raw_transaction(&hex::encode(display)),
            Chain::Provider(p) => p.raw_transaction(&display),
        }
    }

    /// In words, for a badge: who answered.
    pub fn described(&self) -> String {
        match self {
            Chain::Node(n, url) if n.trust() == OracleTrust::FullNode => format!("your own node at {url}"),
            Chain::Node(_, url) => format!("the node at {url}, which is not on this machine"),
            Chain::Provider(p) => format!("your provider {}", p.url()),
        }
    }
}

impl ChainOracle for Chain {
    fn trust(&self) -> OracleTrust {
        match self {
            Chain::Node(n, _) => n.trust(),
            Chain::Provider(p) => p.trust(),
        }
    }

    fn anchor_at(&self, root: &orchard::tree::Anchor, height: u32) -> Result<AnchorStatus> {
        match self {
            Chain::Node(n, _) => n.anchor_at(root, height),
            Chain::Provider(p) => p.anchor_at(root, height),
        }
    }

    fn cmx_at(&self, txid: &[u8; 32], action_index: u32) -> Result<Option<orchard::note::ExtractedNoteCommitment>> {
        match self {
            Chain::Node(n, _) => n.cmx_at(txid, action_index),
            Chain::Provider(p) => p.cmx_at(txid, action_index),
        }
    }
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

/// The local manifest override alone (`ZECBOAT_WAKE_MANIFEST`), for headless callers. Read only
/// by a build with `--features test-overrides` (`crate::test_override`).
pub fn genesis_from_local_manifest(asset_id: &str) -> Option<(String, u32)> {
    let path = crate::test_override("ZECBOAT_WAKE_MANIFEST")?;
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
    oracle: &Chain,
) -> Result<Option<SendLading>> {
    // The lading this carrier's memo commits to, never "the newest for the asset" (audit
    // 2026-10-08, ZMAP B): a stored lading that fits another carrier is not this one's.
    let carrier_ref = crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(conn)?)
        .iter()
        .flat_map(|h| h.carriers.iter())
        .find(|c| c.txid_bytes == *carrier_txid_internal && c.output_index as u32 == output_index)
        .cloned();
    // An Orchard-pool carrier (before NU6.3) has no Wake lineage: WAKE-v1 section 2 is Ironwood
    // only, and the note is not among the Ironwood notes `carrier_note` reads. It moves unproven;
    // it used to fail here as "not among this wallet's received notes" (review 2026-10-09,
    // regression over 12-13, Issue E).
    if carrier_ref.as_ref().map(|c| !is_ironwood(c)).unwrap_or(false) {
        return Ok(None);
    }
    let note = carrier_note(conn, carrier_txid_internal, output_index)?;
    let note_txid_hex = hex::encode(note.txid_display);
    let note_rho = note.note.rho().to_bytes();
    let committed = carrier_ref.as_ref().and_then(|c| c.consignment_hash.clone());
    let note_id = carrier_ref.as_ref().map(|c| c.note_id);
    let mut lading = match crate::zmap::consignment_for_carrier(conn, asset_id, committed.as_deref(), &note_rho, note_id)? {
        Some(c) => {
            // Never extend a lading this wallet has not checked: the proofs, the chain rule and
            // the note's ρ are verified here, with no oracle, before a hop is proved on top. A
            // lading that fails is refused, whoever stored it (review 2026-10-09, regression
            // Finding 1: a decoy's garbage used to be extended and committed onward).
            let (l, _) = zmap_wake::verify_local(&c.json, None, &note.note.rho()).map_err(|f| {
                anyhow!("the lading held for this carrier fails its own checks ({f:?}); refusing to extend it")
            })?;
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
        .map_err(|e| anyhow!("could not fetch the tree state at height {} from {}: {e}", note.mined_height, oracle.described()))?;
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

/// The drop-box chosen in Settings (0.7.1). Empty: no choice made, so the environment or the
/// default applies. `off`: no drop-box at all; ladings are handed over as files.
static DROPBOX_CHOICE: once_cell::sync::Lazy<std::sync::Mutex<String>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(String::new()));

/// Largest sealed lading the wallet will accept from a drop-box or a file. A lading grows by
/// about 7 KB per hop; this leaves room for several hundred.
pub const MAX_SEALED_BYTES: usize = 4 * 1024 * 1024;

/// Set the drop-box from Settings: an `https://` base, a `file://` folder, `off`, or empty for
/// the automatic choice.
pub fn set_dropbox_choice(choice: &str) -> Result<()> {
    let c = choice.trim().trim_end_matches('/').to_string();
    // Plain http:// was accepted until 2026-10-08 (audit, ZMAP Q); ZMAP §15 says https.
    if !(c.is_empty() || c == "off" || c.starts_with("https://") || c.starts_with("file://")) {
        return Err(anyhow!("a drop-box is an https:// address, a file:// folder, or off"));
    }
    *DROPBOX_CHOICE.lock().unwrap() = c;
    Ok(())
}

/// What Settings last set: empty, `off`, or a base.
pub fn dropbox_choice() -> String {
    DROPBOX_CHOICE.lock().unwrap().clone()
}

fn dropbox_from_env() -> Option<String> {
    // The same rule as the Settings path: https or a local folder, nothing else (review
    // 2026-10-09, session 4, Issue M: the environment value was not checked).
    std::env::var("ZECBOAT_DROPBOX")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .filter(|s| {
            let ok = s.starts_with("https://") || s.starts_with("file://");
            if !ok {
                eprintln!("[wake] ZECBOAT_DROPBOX={s:?} is neither https:// nor file://; ignored");
            }
            ok
        })
}

/// Whether any drop-box is in use: only when one is named, in Settings or by `ZECBOAT_DROPBOX`.
///
/// Until 2026-10-06 a wallet with no choice fell back to `{registry}/dropbox`, that is
/// zecboat.com. The owner rejected that: its operator would see the network address of both
/// sides of every transfer. With the Knotline the record travels in the transfer itself, so
/// nothing is contacted by default.
pub fn dropbox_enabled() -> bool {
    let chosen = dropbox_choice();
    chosen != "off" && (!chosen.is_empty() || dropbox_from_env().is_some())
}

/// The drop-box base, or an empty string when none is in use. `file://<dir>` for a shared
/// directory, otherwise an HTTP base URL. Order: the choice made in Settings, then
/// `ZECBOAT_DROPBOX`.
pub fn dropbox_base() -> String {
    let chosen = dropbox_choice();
    if chosen == "off" {
        return String::new();
    }
    if !chosen.is_empty() {
        return chosen;
    }
    dropbox_from_env().unwrap_or_default()
}

fn dropbox_file(base: &str, hash_hex: &str) -> PathBuf {
    PathBuf::from(base.trim_start_matches("file://")).join(format!("{hash_hex}.json"))
}

/// Put a sealed lading under its hash. Overwrites nothing: the first delivery stands.
pub fn dropbox_put(hash_hex: &str, sealed: &[u8]) -> Result<()> {
    if !dropbox_enabled() {
        return Err(anyhow!("no drop-box is in use (Settings); hand the lineage file to the recipient yourself"));
    }
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
        .no_proxy()
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
    if !dropbox_enabled() {
        return Ok(None);
    }
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
        .no_proxy()
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
    if res.content_length().map(|n| n as usize > MAX_SEALED_BYTES).unwrap_or(false) {
        return Err(anyhow!("{url}: the drop-box answered with more than {MAX_SEALED_BYTES} bytes; refused"));
    }
    let bytes = res.bytes()?.to_vec();
    if bytes.len() > MAX_SEALED_BYTES {
        return Err(anyhow!("{url}: the drop-box answered with more than {MAX_SEALED_BYTES} bytes; refused"));
    }
    Ok(Some(bytes))
}

/// Deliver a lading for a sent carrier: seal to the recipient and put it in the drop-box.
pub fn deliver(recipient_ua: &str, lading: &SendLading) -> Result<()> {
    let sealed = seal_for(recipient_ua, &lading.bytes)?;
    dropbox_put(&lading.hash_hex, &sealed)
}

// ── receiving ────────────────────────────────────────────────────────────────────────────────

/// What a fetch pass did.
/// Lines being walked right now, by the memo's consignment hash: the item list, the estimate
/// and the send each start a fetch pass, and a slow but valid line used to be walked several
/// times at once (review 2026-10-09, regression Finding 9).
static WALKS_IN_PROGRESS: std::sync::Mutex<Option<std::collections::HashSet<String>>> = std::sync::Mutex::new(None);

struct WalkGuard(String);

impl WalkGuard {
    /// `None` when the same line is already being walked by another pass.
    fn start(key: &str) -> Option<WalkGuard> {
        let key = key.to_string();
        let mut g = WALKS_IN_PROGRESS.lock().ok()?;
        let set = g.get_or_insert_with(Default::default);
        if set.insert(key.clone()) {
            Some(WalkGuard(key))
        } else {
            None
        }
    }
}

impl Drop for WalkGuard {
    fn drop(&mut self) {
        if let Ok(mut g) = WALKS_IN_PROGRESS.lock() {
            if let Some(set) = g.as_mut() {
                set.remove(&self.0);
            }
        }
    }
}

/// The key of a walk: the carrier's outpoint, not the memo's hash. Keyed on the hash, a copy
/// that repeated the genuine memo's hash and failed its walk muted the genuine unit for ten
/// minutes (review 2026-10-09, regression over 12-13, Issue I).
fn walk_key(c: &crate::zmap::CarrierRef) -> String {
    format!("{}#{}", c.txid.to_ascii_lowercase(), c.output_index)
}

/// Whether a walk for this carrier is running in another pass right now.
pub fn walk_in_progress(c: &crate::zmap::CarrierRef) -> bool {
    WALKS_IN_PROGRESS
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|set| set.contains(&walk_key(c))))
        .unwrap_or(false)
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct FetchReport {
    pub fetched: usize,
    pub already_held: usize,
    pub not_in_dropbox: usize,
    pub failed: Vec<String>,
    /// Carriers (`txid#index`) whose line another pass was still walking when this one looked.
    /// A caller that needs the lading (the send) waits or refuses; it never reads "in progress"
    /// as "absent" (review 2026-10-09, regression over 12-13, Issue B).
    pub in_progress: Vec<String>,
    /// Carriers whose asset nobody vouches for, left for the user to ask about.
    pub not_known: Vec<String>,
}

/// The user asked for one asset's lineage: walk it whatever its collection, with a larger budget.
pub fn collect_lineage(db_path: &str, asset_id: &str) -> Result<FetchReport> {
    let conn = Connection::open(db_path)?;
    for h in crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn)?) {
        if h.asset_id.eq_ignore_ascii_case(asset_id) {
            for c in &h.carriers {
                let _ = crate::zmap::clear_walk_failure(&conn, &c.txid, c.output_index);
            }
        }
    }
    drop(conn);
    fetch_missing_consignments_scoped(db_path, FetchScope::on_demand(asset_id))
}

/// For every held carrier whose memo commits to a lading this wallet does not hold, try the
/// drop-box. What comes back must open with this wallet's keys and hash to the memo's value.
/// What one fetch pass is for (review 2026-10-09, Knotline A).
pub struct FetchScope {
    /// Only this asset's carriers; `None` for every holding.
    pub asset: Option<String>,
    /// Walk lines of assets no pinned manifest or passed audit names (the user asked for it).
    pub include_unknown: bool,
    /// How long to wait for a walk another pass is running before reporting it in progress.
    pub wait: std::time::Duration,
    /// Time and bytes the pass may spend on walks through the chain source.
    pub budget: crate::wake_memo::WalkBudget,
}

impl FetchScope {
    /// The unattended pass: every known asset, no waiting, a modest budget.
    pub fn background() -> FetchScope {
        FetchScope {
            asset: None,
            include_unknown: false,
            wait: std::time::Duration::ZERO,
            budget: crate::wake_memo::WalkBudget::new(std::time::Duration::from_secs(120), 32 * 1024 * 1024),
        }
    }
    /// Before a send or an estimate: this asset only, waiting for a running walk.
    pub fn for_send(asset_id: &str) -> FetchScope {
        FetchScope {
            asset: Some(asset_id.to_string()),
            include_unknown: true,
            wait: std::time::Duration::from_secs(90),
            budget: crate::wake_memo::WalkBudget::new(std::time::Duration::from_secs(120), 32 * 1024 * 1024),
        }
    }
    /// The user asked for this asset's lineage: unknown assets too, a larger budget.
    pub fn on_demand(asset_id: &str) -> FetchScope {
        FetchScope {
            asset: Some(asset_id.to_string()),
            include_unknown: true,
            wait: std::time::Duration::from_secs(300),
            budget: crate::wake_memo::WalkBudget::new(std::time::Duration::from_secs(600), 64 * 1024 * 1024),
        }
    }
}

/// Whether a carrier's asset is one this wallet has a reason to trust before walking its line:
/// a pinned v1 key named in its memo, a passed cached registry audit listing the asset, or the
/// local test manifest (test builds). A stranger's note naming an asset nobody vouches for is
/// not walked unless the user asks (review 2026-10-09, Knotline A).
fn asset_is_known(asset_id: &str, c: &crate::zmap::CarrierRef) -> bool {
    if genesis_from_local_manifest(asset_id).is_some() {
        return true;
    }
    if let Some(rec) = crate::zmap::parse_memo(&c.memo) {
        if let Some(ik) = rec.ik.as_deref() {
            if crate::issuance_v1::PINNED_V1.iter().any(|(_, k, _)| k.eq_ignore_ascii_case(ik)) {
                return true;
            }
        }
    }
    crate::collection_audit::audited_collection_listing(asset_id).map(|a| a.passed).unwrap_or(false)
}

/// The unattended pass, in a thread nobody waits for, at most once a minute.
pub fn fetch_missing_consignments_in_background(db_path: String) {
    static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    {
        let mut last = LAST.lock().unwrap();
        if last.map(|t| t.elapsed() < std::time::Duration::from_secs(60)).unwrap_or(false) {
            return;
        }
        *last = Some(std::time::Instant::now());
    }
    std::thread::spawn(move || match fetch_missing_consignments_scoped(&db_path, FetchScope::background()) {
        Ok(r) if r.fetched > 0 || !r.failed.is_empty() => println!("[wake] consignments: {r:?}"),
        Err(e) => eprintln!("[wake] consignment fetch skipped: {e}"),
        _ => {}
    });
}

pub fn fetch_missing_consignments(db_path: &str) -> Result<FetchReport> {
    fetch_missing_consignments_scoped(db_path, FetchScope::background())
}

/// The fetch pass under a [`FetchScope`].
pub fn fetch_missing_consignments_scoped(db_path: &str, scope: FetchScope) -> Result<FetchReport> {
    let started = std::time::Instant::now();
    let wait = scope.wait;
    let conn = Connection::open(db_path)?;
    let holdings = crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn)?);
    let mut report = FetchReport::default();
    for h in &holdings {
        if scope.asset.as_deref().map(|a| !a.eq_ignore_ascii_case(&h.asset_id)).unwrap_or(false) {
            continue;
        }
        for c in &h.carriers {
            let Some(hash) = c.consignment_hash.as_deref() else { continue };
            // A lading this wallet made for a send to itself is re-read from its own line, so
            // the next transfer chains instead of starting over (review 2026-10-09, Knotline H).
            let held = crate::zmap::consignment_by_hash(&conn, hash)?;
            let self_sent = held.as_ref().map(|x| x.source.as_deref() == Some("sent")).unwrap_or(false);
            if held.is_some() && !self_sent {
                report.already_held += 1;
                continue;
            }
            if !scope.include_unknown && !asset_is_known(&h.asset_id, c) {
                report.not_known.push(format!("{}: {}", h.name, walk_key(c)));
                continue;
            }
            // A line that failed to rebuild is not tried again at once; the delay doubles and
            // survives a restart (audit 2026-10-08, Knotline B; review 2026-10-09, Knotline A).
            let key = walk_key(c);
            if let Some((_, _, left)) = crate::zmap::walk_failure(&conn, &c.txid, c.output_index)? {
                if left > 0 {
                    continue;
                }
            }
            let mut guard = WalkGuard::start(&key);
            while guard.is_none() && started.elapsed() < wait {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if crate::zmap::consignment_by_hash(&conn, hash)?.is_some() {
                    break;
                }
                guard = WalkGuard::start(&key);
            }
            if !self_sent && crate::zmap::consignment_by_hash(&conn, hash)?.is_some() {
                report.already_held += 1;
                continue;
            }
            let Some(_walking) = guard else {
                report.in_progress.push(key);
                continue;
            };
            // Knotline: a key memo to the carrier's receiver opens the newest knot, and each
            // knot leads to the one before it. A failed walk does not stop the other routes
            // (review 2026-10-09, Knotline E).
            match crate::wake_memo::lading_from_knotline(&conn, &c.txid_bytes, Some(c.note_id), hash, Some(&scope.budget)) {
                Ok(Some((bytes, walked, start_key))) => {
                    let stored = if self_sent {
                        Ok(hash.to_string())
                    } else {
                        accept_lading(&conn, &h.asset_id, c, &bytes, "knotline")
                    };
                    match stored {
                        Ok(hh) => {
                            let _ = crate::zmap::mark_consignment_knotline(&conn, &hh, &start_key, &c.txid_bytes, walked);
                            let _ = crate::zmap::clear_walk_failure(&conn, &c.txid, c.output_index);
                            println!("[wake] lading for {} rebuilt from its Knotline: {walked} knot(s) followed back", h.name);
                            report.fetched += 1;
                            continue;
                        }
                        Err(e) => {
                            let _ = crate::zmap::record_walk_failure(&conn, &c.txid, c.output_index, &e.to_string());
                            report.failed.push(format!("{}: {e}", h.name));
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("[wake] Knotline for {}: {e}", h.name);
                    report.failed.push(format!("{}: Knotline: {e}", h.name));
                    let _ = crate::zmap::record_walk_failure(&conn, &c.txid, c.output_index, &e.to_string());
                }
            }
            if self_sent {
                continue;
            }
            // First choice (prototype): the record may be in the carrier's own transaction.
            match crate::wake_memo::record_in_transaction(&conn, &c.txid_bytes, hash) {
                Ok(Some(bytes)) => {
                    match accept_lading(&conn, &h.asset_id, c, &bytes, "memo") {
                        Ok(_) => {
                            println!("[wake] lading for {} read from the transfer's own memos", h.name);
                            report.fetched += 1;
                        }
                        Err(e) => report.failed.push(format!("{}: {e}", h.name)),
                    }
                    continue;
                }
                Ok(None) => {}
                Err(e) => eprintln!("[wake] could not look for the record in the transfer: {e}"),
            }
            let sealed = match dropbox_get(hash) {
                Ok(Some(b)) => b,
                Ok(None) => { report.not_in_dropbox += 1; continue; }
                Err(e) => { report.failed.push(format!("{}: {e}", h.name)); continue; }
            };
            let result = accept_sealed(&conn, &h.asset_id, c, &sealed);
            match result {
                Ok(()) => report.fetched += 1,
                Err(e) => report.failed.push(format!("{}: {e}", h.name)),
            }
        }
    }
    Ok(report)
}

/// Open one sealed lading for carrier `c` of `asset_id` and store it, or say why not. It must
/// open with this wallet's keys and hash to the value the carrier's memo commits to.
fn accept_sealed(conn: &Connection, asset_id: &str, c: &crate::zmap::CarrierRef, sealed: &[u8]) -> Result<()> {
    let Some(hash) = c.consignment_hash.as_deref() else {
        return Err(anyhow!("this carrier's memo commits to no lading"));
    };
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(anyhow!("more than {MAX_SEALED_BYTES} bytes; refused"));
    }
    let note = carrier_note(conn, &c.txid_bytes, c.output_index as u32)?;
    let sealed = zmap_wake::seal::Sealed::parse(sealed)?;
    let bytes = zmap_wake::seal::open(&note.fvk, &sealed)?;
    if hex::encode(lading_hash(&bytes)) != hash {
        return Err(anyhow!("the delivered lading does not hash to the memo's consignment_hash"));
    }
    accept_lading(conn, asset_id, c, &bytes, "file")?;
    Ok(())
}

/// Store a lading that arrived for carrier `c`, by any route, after the checks that need no
/// oracle (`verify_local`: hash, canonical form, every proof, the chain rule, this note's ρ).
/// A lading that fails is recorded against the note as rejected and is **not** stored: it is
/// evidence about whoever sent that copy, never "the lading for" a carrier (review 2026-10-09,
/// regression Finding 1). Returns the stored hash.
fn accept_lading(conn: &Connection, asset_id: &str, c: &crate::zmap::CarrierRef, bytes: &[u8], source: &str) -> Result<String> {
    let sha = lading_hash(bytes);
    if let Some((reason, _, prev)) = crate::zmap::rejected_lading_for_note(conn, c.note_id)? {
        if prev.eq_ignore_ascii_case(&hex::encode(sha)) {
            return Err(anyhow!("this lading was already refused for this copy ({reason})"));
        }
    }
    let note = carrier_note(conn, &c.txid_bytes, c.output_index as u32)?;
    let expected = c
        .consignment_hash
        .as_deref()
        .and_then(|hh| hex::decode(hh).ok())
        .and_then(|v| <[u8; 32]>::try_from(v).ok());
    if let Err(f) = zmap_wake::verify_local(bytes, expected, &note.note.rho()) {
        let reason = format!("{f:?}");
        let _ = crate::zmap::record_rejected_lading(conn, c.note_id, &sha, source, &reason);
        return Err(anyhow!("a lading arrived by {source} and failed before it was stored: {reason}"));
    }
    let hh = crate::zmap::store_consignment(conn, asset_id, None, Some(c.note_id), bytes, None)?;
    let _ = crate::zmap::mark_consignment_source(conn, &hh, source);
    Ok(hh)
}

// ── delivery that can be seen, retried and done by hand (0.7.1) ───────────────────────

/// One lading this wallet sent, for the UI.
#[derive(Clone, Debug, Serialize)]
pub struct Outgoing {
    pub asset_id: String,
    pub consignment_hash: String,
    pub txid: String,
    pub recipient: String,
    pub delivered: bool,
    /// True when the lading travelled inside the transfer itself (nothing was delivered anywhere).
    pub carried: bool,
    pub delivered_at: Option<String>,
    pub note: Option<String>,
    pub created_at: String,
}

/// Every lading this wallet made for a send, newest first.
pub fn outgoing(db_path: &str) -> Result<Vec<Outgoing>> {
    let conn = Connection::open(db_path)?;
    Ok(crate::zmap::outgoing_consignments(&conn)?
        .into_iter()
        .map(|o| Outgoing {
            asset_id: o.asset_id,
            consignment_hash: o.sha256,
            txid: o.txid,
            recipient: o.recipient,
            delivered: o.delivered_at.is_some(),
            carried: o.delivery_note.as_deref() == Some(crate::zmap::CARRIED_IN_TRANSFER),
            delivered_at: o.delivered_at,
            note: o.delivery_note,
            created_at: o.created_at,
        })
        .collect())
}

/// How long the unattended pass keeps trying to deliver a record.
pub const AUTO_RETRY_DAYS: i64 = 30;

/// The unattended delivery pass, at most once per [`AUTO_RETRY_EVERY`], and never waited for:
/// an unreachable drop-box must not hold up whatever triggered it.
pub fn redeliver_in_background(db_path: String) {
    const AUTO_RETRY_EVERY: std::time::Duration = std::time::Duration::from_secs(600);
    static LAST: once_cell::sync::Lazy<std::sync::Mutex<Option<std::time::Instant>>> =
        once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));
    {
        let mut last = LAST.lock().unwrap();
        if last.map(|t| t.elapsed() < AUTO_RETRY_EVERY).unwrap_or(false) {
            return;
        }
        *last = Some(std::time::Instant::now());
    }
    std::thread::spawn(move || match redeliver(&db_path, None) {
        Ok(r) if r.delivered > 0 => println!("[wake] {} waiting lading(s) delivered", r.delivered),
        _ => {}
    });
}

/// What a delivery pass did.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DeliveryReport {
    pub delivered: usize,
    pub failed: Vec<String>,
}

/// Deliver ladings that have not reached a drop-box: all of them, or the one named. Naming one
/// delivers it again even if it was delivered before (a drop-box keeps the first copy).
pub fn redeliver(db_path: &str, only: Option<&str>) -> Result<DeliveryReport> {
    let conn = Connection::open(db_path)?;
    let mut report = DeliveryReport::default();
    for o in crate::zmap::outgoing_consignments(&conn)? {
        match only {
            Some(h) if !h.eq_ignore_ascii_case(&o.sha256) => continue,
            // The unattended pass leaves alone what was delivered and what is older than
            // AUTO_RETRY_DAYS: a record nobody collected in that time is asked for by hand.
            None if o.delivered_at.is_some() || o.age_days > AUTO_RETRY_DAYS => continue,
            _ => {}
        }
        let outcome = seal_for(&o.recipient, &o.json).and_then(|sealed| dropbox_put(&o.sha256, &sealed));
        match &outcome {
            Ok(()) => report.delivered += 1,
            Err(e) => report.failed.push(format!("{}…: {e}", &o.sha256[..16.min(o.sha256.len())])),
        }
        let why = outcome.as_ref().err().map(|e| e.to_string());
        let _ = crate::zmap::mark_consignment_delivery(&conn, &o.sha256, match &why { None => Ok(()), Some(w) => Err(w.as_str()) });
    }
    Ok(report)
}

/// The lading `hash_hex`, sealed to its recipient, as a file's bytes and a file name. Only the
/// recipient's keys open it, so the file can travel by any channel.
pub fn export_sealed(db_path: &str, hash_hex: &str) -> Result<(String, Vec<u8>)> {
    let conn = Connection::open(db_path)?;
    let o = crate::zmap::outgoing_consignments(&conn)?
        .into_iter()
        .find(|o| o.sha256.eq_ignore_ascii_case(hash_hex))
        .ok_or_else(|| anyhow!("this wallet holds no sent lading {hash_hex}"))?;
    let sealed = seal_for(&o.recipient, &o.json)?;
    Ok((format!("lineage-{}.wake.json", &o.sha256[..16]), sealed))
}

/// What importing a lineage file did.
#[derive(Clone, Debug, Serialize)]
pub struct Imported {
    pub asset_id: String,
    pub name: String,
    pub consignment_hash: String,
    pub hops: usize,
}

/// Take a sealed lading handed over as a file. It is tried against every held carrier whose
/// memo commits to a lading this wallet does not hold yet; the same rules as a drop-box fetch
/// apply, so a file that is not for this wallet, or not the committed lading, is refused.
pub fn import_sealed(db_path: &str, sealed: &[u8]) -> Result<Imported> {
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(anyhow!("that file is larger than {MAX_SEALED_BYTES} bytes; not a lineage file this wallet accepts"));
    }
    zmap_wake::seal::Sealed::parse(sealed).map_err(|e| anyhow!("that is not a lineage file: {e}"))?;
    let conn = Connection::open(db_path)?;
    let holdings = crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn)?);
    let mut waiting = 0;
    for h in &holdings {
        for c in &h.carriers {
            let Some(hash) = c.consignment_hash.as_deref() else { continue };
            if crate::zmap::consignment_by_hash(&conn, hash)?.is_some() {
                continue;
            }
            waiting += 1;
            if accept_sealed(&conn, &h.asset_id, c, sealed).is_ok() {
                let hops = crate::zmap::consignment_by_hash(&conn, hash)?
                    .and_then(|k| Lading::parse(&k.json).ok())
                    .map(|l| l.hops.len())
                    .unwrap_or(0);
                return Ok(Imported { asset_id: h.asset_id.clone(), name: h.name.clone(), consignment_hash: hash.to_string(), hops });
            }
        }
    }
    Err(if waiting == 0 {
        anyhow!("no unit in this wallet is waiting for a lineage record")
    } else {
        anyhow!("that file does not belong to any unit here that is waiting for its lineage record: it is sealed to another wallet, or it is not the record the sender committed to")
    })
}

/// What sending `asset_id` now would carry and cost. Collects a waiting lading first, as the
/// send itself does, so the estimate and the send agree.
pub async fn asset_send_estimate(asset_id: String) -> Result<crate::wake_memo::SendEstimate> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    // The manifest's genesis, so the estimate ranks the copies as the send will.
    let genesis = genesis_outpoint(&asset_id).await.map(|(t, i, _)| (t, i));
    tokio::task::spawn_blocking(move || {
        let _ = fetch_missing_consignments_scoped(&db_path, FetchScope::for_send(&asset_id));
        let conn = Connection::open(&db_path)?;
        crate::wake_memo::send_estimate(&conn, &asset_id, genesis.as_ref())
    })
    .await
    .map_err(|e| anyhow!("did not finish: {e}"))?
}

/// Async wrappers for the UI.
pub async fn lineage_outgoing() -> Result<Vec<Outgoing>> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    tokio::task::spawn_blocking(move || outgoing(&db_path)).await.map_err(|e| anyhow!("did not finish: {e}"))?
}

pub async fn lineage_redeliver(only: Option<String>) -> Result<DeliveryReport> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    tokio::task::spawn_blocking(move || redeliver(&db_path, only.as_deref())).await.map_err(|e| anyhow!("did not finish: {e}"))?
}

/// Write the sealed lading into the user's Downloads folder (their home if there is none) and
/// return the path.
pub async fn lineage_export(hash_hex: String) -> Result<String> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    tokio::task::spawn_blocking(move || -> Result<String> {
        let (name, bytes) = export_sealed(&db_path, &hash_hex)?;
        let home = PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("no home folder"))?);
        let dir = Some(home.join("Downloads")).filter(|d| d.is_dir()).unwrap_or(home);
        let path = dir.join(name);
        std::fs::write(&path, bytes)?;
        Ok(path.to_string_lossy().into_owned())
    })
    .await
    .map_err(|e| anyhow!("did not finish: {e}"))?
}

pub async fn lineage_import(sealed: Vec<u8>) -> Result<Imported> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    tokio::task::spawn_blocking(move || import_sealed(&db_path, &sealed)).await.map_err(|e| anyhow!("did not finish: {e}"))?
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
        /// The node that answered, in words, so the screen can show which loopback address
        /// was trusted (review 2026-10-09, regression Finding 8).
        asked: String,
    },
    /// Everything `Verified` checks held, but the chain's answers (tree roots, the genesis
    /// output) came from a server and not from a node on this machine: the wallet's provider, or
    /// a node elsewhere. The proofs themselves were checked here. This is the same trust a light
    /// wallet places in its provider for its balance; it is **not** "verified by your own node"
    /// and the UI must not show it as such (WAKE-v1 §8.1).
    ProviderChecked {
        hops: usize,
        min_anchor_depth: u32,
        genesis_txid: String,
        genesis_action_index: u32,
        genesis_source: GenesisSource,
        consignment_hash: String,
        /// Who answered, in words.
        asked: String,
    },
    /// The proofs and chain rule held, but something outside them could not be confirmed: an
    /// anchor is not yet deep enough, no trusted manifest confirms the genesis output, or
    /// nothing could be asked about the chain at all. **Not** a verdict against the asset.
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

/// Verify the lading held for `asset_id`: every unspent carrier of it is checked against the
/// lading its own memo commits to, and the best result is the asset's state. Until 2026-10-08
/// one carrier (the smallest txid) was checked against the newest lading stored for the asset,
/// so an unsolicited copy of a unit, sent by anyone who knew the address, could make the
/// genuine unit show Broken and refuse to send (audit, ZMAP B / Zecboat C / ZMAP I).
pub fn verify_holding(db_path: &str, asset_id: &str, genesis: Option<&(String, u32, GenesisSource)>) -> Result<WakeState> {
    let conn = Connection::open(db_path)?;
    let holdings = crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn)?);
    let Some(h) = holdings.iter().find(|h| h.asset_id == asset_id) else {
        return Ok(WakeState::NoWake { detail: "this wallet holds no carrier of that asset".into() });
    };
    if h.carriers.is_empty() {
        return Ok(WakeState::NoWake { detail: "no unspent carrier".into() });
    }
    let mut carriers: Vec<&crate::zmap::CarrierRef> = h.carriers.iter().collect();
    carriers.sort_by_key(|c| (c.txid.clone(), c.output_index));
    let mut best: Option<WakeState> = None;
    for c in carriers {
        let state = verify_carrier(&conn, asset_id, c, genesis)?;
        if best.as_ref().map(|b| wake_rank(&state) > wake_rank(b)).unwrap_or(true) {
            best = Some(state);
        }
    }
    Ok(best.unwrap_or(WakeState::NoWake { detail: "no unspent carrier".into() }))
}

/// Order of preference when an asset has several carriers: a proven one over an unproven one,
/// an unproven one over one that came with nothing, and that over a broken one. Until
/// 2026-10-09 Broken ranked above NoWake, so a copy someone else sent with a failed lading
/// spoke for the asset over a genuine unit that came with no lading (review, regression
/// suggestion 12). The same order decides which carrier a send spends.
pub fn wake_rank(s: &WakeState) -> u8 {
    match s {
        WakeState::Verified { .. } => 5,
        WakeState::ProviderChecked { .. } => 4,
        WakeState::Unverified { .. } => 3,
        WakeState::NoWake { .. } => 2,
        WakeState::Broken { .. } => 1,
    }
}

/// One carrier's lineage state, for the per-copy view and for choosing which copy to spend.
#[derive(Clone, Debug, Serialize)]
pub struct CarrierState {
    pub txid: String,
    pub output_index: u32,
    pub state: WakeState,
}

/// Every unspent carrier of `asset_id` with its own lineage state, in txid order. The asset's
/// badge is the best of these; this is what lets the screen say "2 copies: one checks out, one
/// came with a broken lineage" instead of hiding the second under the first (review
/// 2026-10-09, regression Finding 11).
pub fn holding_carrier_states(db_path: &str, asset_id: &str, genesis: Option<&(String, u32, GenesisSource)>) -> Result<Vec<CarrierState>> {
    let conn = Connection::open(db_path)?;
    let holdings = crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn)?);
    let Some(h) = holdings.iter().find(|h| h.asset_id == asset_id) else { return Ok(Vec::new()) };
    let mut carriers: Vec<&crate::zmap::CarrierRef> = h.carriers.iter().collect();
    carriers.sort_by_key(|c| (c.txid.clone(), c.output_index));
    carriers
        .into_iter()
        .map(|c| {
            Ok(CarrierState {
                txid: c.txid.clone(),
                output_index: c.output_index as u32,
                state: verify_carrier(&conn, asset_id, c, genesis)?,
            })
        })
        .collect()
}

/// The rank of one carrier for the send planner. No oracle is asked, so the choice is the same
/// on every call and a retry after a crash lands on the same note. With the manifest's genesis
/// in hand, the order is: the carrier that IS the genesis output (a unit at its first holder,
/// whose proof is made at send time); a held lading that passes the oracle-free checks and
/// descends from that genesis; a held lading that passes them when no manifest names a genesis;
/// a carrier with no lading; a carrier whose lading fails, descends from another genesis, or
/// was rejected. Until 2026-10-09 the rank was taken from `verify_carrier` with no genesis, so
/// a copy with a self-consistent lading of its own outranked the genuine first-holder unit
/// (review, regression over 12-13, Issue A).
pub fn carrier_send_rank(conn: &Connection, asset_id: &str, c: &crate::zmap::CarrierRef, genesis: Option<&(String, u32)>) -> u8 {
    if !is_ironwood(c) {
        return 2;
    }
    let Ok(note) = carrier_note(conn, &c.txid_bytes, c.output_index as u32) else { return 0 };
    let outpoint_is_genesis = genesis
        .map(|(t, i)| t.eq_ignore_ascii_case(&hex::encode(note.txid_display)) && *i == note.action_index)
        .unwrap_or(false);
    let rho = note.note.rho().to_bytes();
    let lading = crate::zmap::consignment_for_carrier(conn, asset_id, c.consignment_hash.as_deref(), &rho, Some(c.note_id))
        .ok()
        .flatten();
    let rejected = crate::zmap::rejected_lading_for_note(conn, c.note_id).ok().flatten().is_some();
    send_rank(outpoint_is_genesis, lading.as_ref().map(|l| l.json.as_slice()), &note.note.rho(), genesis, rejected)
}

#[cfg(test)]
mod send_rank_tests {
    use super::send_rank;

    /// The copy variants the regression review listed (2026-10-09, Issue A), ranked without an
    /// oracle: the published Wake Test #001 lading (real proofs) stands for "a valid lading".
    #[test]
    fn copies_are_ranked_by_genesis_and_local_checks_only() {
        let vector: &[u8] = include_bytes!("../../zmap-wake/docs/test_vector/wake_test_001_lading.json");
        let rho_bytes = zmap_wake::oracle::decode_hex_32("c208b5304d072f05e40142cce0026e6faa4961b83b7ae81ac255013aad404a39").unwrap();
        let rho: orchard::note::Rho = Option::from(orchard::note::Rho::from_bytes(&rho_bytes)).unwrap();
        let genesis = ("14b8a35a93fec522b597115e18e5100885c30964f222a998cd8325df9118f362".to_string(), 2u32);
        let other = ("ab".repeat(32), 0u32);
        // The genuine unit at its first holder: its outpoint is the genesis output.
        assert_eq!(send_rank(true, None, &rho, Some(&genesis), false), 6);
        // A held lading with real proofs descending from the manifest's genesis.
        assert_eq!(send_rank(false, Some(vector), &rho, Some(&genesis), false), 5);
        // The same lading when no manifest names a genesis: better than nothing, below a match.
        assert_eq!(send_rank(false, Some(vector), &rho, None, false), 3);
        // A copy that brought nothing ranks below the genuine first-holder unit.
        assert_eq!(send_rank(false, None, &rho, Some(&genesis), false), 2);
        // A copy whose valid lading descends from another genesis, a garbage lading, a lading
        // for another note, and a rejected copy: all last.
        assert_eq!(send_rank(false, Some(vector), &rho, Some(&other), false), 1);
        let garbage = vector.iter().map(|b| if *b == b'A' { b'B' } else { *b }).collect::<Vec<u8>>();
        assert_eq!(send_rank(false, Some(&garbage), &rho, Some(&genesis), false), 1);
        let other_rho: orchard::note::Rho = Option::from(orchard::note::Rho::from_bytes(&[1u8; 32])).unwrap();
        assert_eq!(send_rank(false, Some(vector), &other_rho, Some(&genesis), false), 1);
        assert_eq!(send_rank(false, None, &rho, Some(&genesis), true), 1);
    }
}

/// The pure part of [`carrier_send_rank`], so the copy variants can be tested without a wallet.
pub fn send_rank(outpoint_is_genesis: bool, lading: Option<&[u8]>, rho: &orchard::note::Rho, genesis: Option<&(String, u32)>, rejected: bool) -> u8 {
    if outpoint_is_genesis {
        return 6;
    }
    match lading {
        None => {
            if rejected {
                1
            } else {
                2
            }
        }
        Some(bytes) => match zmap_wake::verify_local(bytes, None, rho) {
            Err(_) => 1,
            Ok((l, _)) => match genesis {
                Some((t, i)) if t.eq_ignore_ascii_case(&l.genesis.txid) && *i == l.genesis.action_index => 5,
                Some(_) => 1,
                None => 3,
            },
        },
    }
}

fn is_ironwood(c: &crate::zmap::CarrierRef) -> bool {
    use zcash_protocol::{PoolType, ShieldedProtocol};
    matches!(crate::zmap::pool_type(c.pool), Some(PoolType::Shielded(ShieldedProtocol::Ironwood)))
}

/// One carrier against the lading its memo commits to.
fn verify_carrier(
    conn: &Connection,
    asset_id: &str,
    carrier: &crate::zmap::CarrierRef,
    genesis: Option<&(String, u32, GenesisSource)>,
) -> Result<WakeState> {
    if !is_ironwood(carrier) {
        return Ok(WakeState::NoWake {
            detail: "an Orchard-pool unit (received before NU6.3): Wake covers Ironwood notes only, so it has no lineage proof and moves unproven".into(),
        });
    }
    let note = carrier_note(conn, &carrier.txid_bytes, carrier.output_index as u32)?;
    let rho = note.note.rho().to_bytes();
    let Some(consignment) =
        crate::zmap::consignment_for_carrier(conn, asset_id, carrier.consignment_hash.as_deref(), &rho, Some(carrier.note_id))?
    else {
        // A lading that arrived with this copy and failed before it was stored makes THIS copy
        // Broken; another copy of the same asset is judged on its own (review 2026-10-09).
        if let Some((reason, source, _)) = crate::zmap::rejected_lading_for_note(conn, carrier.note_id)? {
            return Ok(WakeState::Broken {
                failure: reason.clone(),
                detail: format!("a lading arrived with this copy (by {source}) and failed its checks before it was stored: {reason}"),
            });
        }
        return Ok(WakeState::NoWake {
            detail: match &carrier.consignment_hash {
                Some(hh) => match crate::zmap::rejected_lading_for_note(conn, carrier.note_id)?.map(|_| ()).or(None) {
                    _ => match crate::zmap::walk_failure(conn, &carrier.txid, carrier.output_index)? {
                        Some((err, n, left)) if left > 0 => format!(
                            "the memo commits to lading {}… and collecting it failed ({n} time(s), last: {err}); next try in {} min, or ask for it now",
                            &hh[..16],
                            (left / 60).max(1)
                        ),
                        _ => format!("the memo commits to lading {}… but it has not been fetched; ask for it, or it is collected in the background when its collection is one this wallet knows", &hh[..16]),
                    },
                },
                None => "no lineage travelled with this unit (a unit straight from its mint, or sent by a wallet before 0.7.0); its first proof is made when it is sent".into(),
            },
        });
    };

    // `parse_memo` keeps a consignment_hash only when it is 64 hex characters; anything else
    // reads as a memo without one, and such a carrier gets no lading but its own (above).
    let expected = carrier
        .consignment_hash
        .as_deref()
        .and_then(|hh| hex::decode(hh).ok())
        .and_then(|v| <[u8; 32]>::try_from(v).ok());
    let oracle = chain();
    let lading = Lading::parse(&consignment.json).map_err(|e| anyhow!("stored lading unreadable: {e}"))?;
    // The genesis proof is anchored at the block the genesis output was mined in, so the genesis
    // transaction can be fetched under the cover of its block.
    if let Some(first) = lading.hops.first() {
        oracle.hint_height(&lading.genesis.txid, first.anchor_height);
    }

    match verify_chain(&consignment.json, expected, &note.note.rho(), &oracle, MIN_DEPTH) {
        Ok(v) => {
            let g_ok = genesis.map(|(t, i, _)| t.eq_ignore_ascii_case(&lading.genesis.txid) && *i == lading.genesis.action_index);
            match g_ok {
                Some(true) if v.trust == OracleTrust::FullNode => {
                    let _ = crate::zmap::mark_consignment_verified(conn, &consignment.sha256, Some(oracle.tip_height().unwrap_or(0)));
                    Ok(WakeState::Verified {
                        hops: v.hops,
                        min_anchor_depth: v.min_anchor_depth,
                        genesis_txid: lading.genesis.txid.clone(),
                        genesis_action_index: lading.genesis.action_index,
                        genesis_source: genesis.map(|g| g.2.clone()).unwrap_or(GenesisSource::PinnedManifest),
                        consignment_hash: consignment.sha256.clone(),
                        asked: oracle.described(),
                    })
                }
                // The same checks, answered by a server. Not recorded as verified: that mark is
                // kept for a verdict this machine reached against its own node.
                Some(true) => Ok(WakeState::ProviderChecked {
                    hops: v.hops,
                    min_anchor_depth: v.min_anchor_depth,
                    genesis_txid: lading.genesis.txid.clone(),
                    genesis_action_index: lading.genesis.action_index,
                    genesis_source: genesis.map(|g| g.2.clone()).unwrap_or(GenesisSource::PinnedManifest),
                    consignment_hash: consignment.sha256.clone(),
                    asked: oracle.described(),
                }),
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
                        "the chain of {} proof(s) verified against {}, but no trusted manifest could confirm that {}… output {} is this asset's genesis",
                        v.hops,
                        oracle.described(),
                        &lading.genesis.txid[..16],
                        lading.genesis.action_index
                    ),
                    consignment_hash: Some(consignment.sha256.clone()),
                }),
            }
        }
        Err(e) if classify(&e) => {
            let _ = crate::zmap::mark_consignment_verified(conn, &consignment.sha256, None);
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

        // 0.7.1, in this test because the choice is process-wide: Settings outranks the
        // environment, `off` means no drop-box at all, and clearing it gives the environment back.
        let other = std::env::temp_dir().join(format!("wake-dropbox-chosen-{}", std::process::id()));
        set_dropbox_choice(&format!("file://{}/", other.display())).unwrap();
        assert_eq!(dropbox_base(), format!("file://{}", other.display()));
        assert_eq!(dropbox_get(&h).unwrap(), None, "the chosen folder is empty");
        set_dropbox_choice("off").unwrap();
        assert!(!dropbox_enabled());
        assert!(dropbox_put(&h, b"x").unwrap_err().to_string().contains("no drop-box is in use"));
        assert_eq!(dropbox_get(&h).unwrap(), None);
        assert!(set_dropbox_choice("ftp://example").is_err());
        assert_eq!(dropbox_choice(), "off", "a refused value changes nothing");
        set_dropbox_choice("").unwrap();
        assert_eq!(dropbox_base(), format!("file://{}", dir.display()));
        assert_eq!(dropbox_get(&h).unwrap().as_deref(), Some(&b"sealed-1"[..]));

        std::env::remove_var("ZECBOAT_DROPBOX");
        // Nothing named anywhere: no drop-box, and no fallback to a web address.
        assert!(!dropbox_enabled());
        assert_eq!(dropbox_base(), "");
        assert!(dropbox_put(&h, b"x").is_err());
        assert_eq!(dropbox_get(&h).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn an_oversized_file_is_not_a_lineage_file() {
        let big = vec![b' '; MAX_SEALED_BYTES + 1];
        let e = import_sealed("/nonexistent/wallet.db", &big).unwrap_err().to_string();
        assert!(e.contains("larger than"), "{e}");
        let e = import_sealed("/nonexistent/wallet.db", b"{}").unwrap_err().to_string();
        assert!(e.contains("not a lineage file"), "{e}");
    }

    #[test]
    fn seal_for_needs_a_unified_address_with_orchard() {
        assert!(seal_for("t1abc", b"x").is_err());
    }
}
