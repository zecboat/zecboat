//! A1b (v0.7.0): the issuance badge for collections minted under ZMAP identity v1.
//!
//! Written independently of the mint (`~/zecboat_mint_wake/src/identity.rs`) from the rule
//! itself, so the wallet is a second opinion rather than the same code agreeing with itself:
//!
//! ```text
//! asset_id = BLAKE2b-256(personal "ZMAP-AssetID-v1", 0x01 ‖ ik ‖ desc)
//! ik       = BIP-340 x-only public key on secp256k1
//! manifest = schema "zecboat-proof-of-issuance/2", signed BIP-340 under ik over the raw bytes
//! ```
//!
//! The badge for a v1 collection states what it checked:
//!
//!  1. the manifest's BIP-340 signature verifies under the ik PINNED in this wallet;
//!  3. the manifest is for mainnet;
//!  4. this asset is listed in it;
//!  6'. the asset id recomputes from the pinned ik and the manifest's description, and the
//!      holder's own carrier memo carries that same description and names that same ik;
//!  5'. the genesis output the manifest names is on chain with the commitment it states,
//!      asked of the chain source this wallet chose (its own node, else its provider).
//!
//! What it does NOT check, and says so: that this unit descends from that genesis output
//! (that is the lineage badge, Wake), and the collection's close and count (that is `audit`).

use serde_json::Value;

use crate::issuance::BadgeState;

pub const PERSONAL: &[u8; 15] = b"ZMAP-AssetID-v1";
pub const VERSION: u8 = 1;

/// Collections under identity v1 pinned in this build: (label, ik hex, manifest location
/// relative to the registry base). A pinned key is the only thing that lets a collection's
/// green badge mean "the issuer this wallet knows": the Registry is open and self-signed, and
/// a name plus a short key fragment is forgeable (review 2026-10-09, session 4, Issue A: a
/// 32-bit fragment ground in under two hours). A collection found only in the Registry is
/// shown as registered, never green. The owner adds a line per collection they vouch for.
pub const PINNED_V1: &[(&str, &str, &str)] = &[
    ("Lagos Post Card", "e9be4cf91390aba0740ce108a0c2f390d1610ef5c77ede09b445e888fd79b590", "issuance/lpc_issuance_manifest.json"),
    ("Happy Birthday Zcash 10", "1ba0bd2f1a1891d616ce912b5e02c38069a9ec87d6b33769bdd8a00741ce1fa0", "issuance/hbd10_issuance_manifest.json"),
    ("Barcelona Post Card 2026", "d289030848144bc321be1030051f90dbf170f0c6752ab8dbf6ed029658d1a820", "issuance/bcn26_issuance_manifest.json"),
];

/// The Zecboat Registry (created 2026-09-27, `~/zecboat_registry/ZECBOAT_REGISTRY.md`): the one
/// account every identity-v1 collection registers with. From this viewing key and birthday alone,
/// anyone can list every registered collection on chain and audit each (`registry-scan --audit`).
/// Pinned so a wallet never has to look the registry up: that lookup is the thing it replaces.
pub const REGISTRY_ADDRESS: &str = "u1qdh76ny27usxr760e92lel2rapd3ckmcw8khyznf8jh637twhw2l4v7vtxtt7hd9ddrw6h8vzaygt8wujzpse32dthwpyt9shmpwln5fpg8n9t6ea4eftf08tpag6whh96vy38gzy279u8wy2wc6j4e9s77yzvaupnqjwr00t5fk6uyr";
pub const REGISTRY_UFVK: &str = "uview198rw4fq5lwhus2snzqsm32jlskaxezfm6aqpjndvnczxmhzcwwsen3du3ptupps8jg2skqpdpcdjtc0ht4utzuynl88e2lcg5zpwnqlut5euux9hla0h6h2m0ky2gwnnygghlw28lq7sx2lf362gsdd5rjsvy725zrpnqpueu7xsyna8wfdqk0umg230x96a4jfem4fqfrqazd4vdvquhh204hhev6lqwpsrwm8js4t5x9puc93vf0tf6hdf7fhz92vkwcafr3fs5nntdxzwve522cqn4amdnqhkukzwjep2k3z6jk6sj4f57zlwnzz54578uszkekka629f4clyccxhegm64u49ktc7ea5ts6vzwlpvv4r9s56ynnyw7fsgzt6n0kgyuaf70";
pub const REGISTRY_BIRTHDAY: u32 = 3498338;

/// One v1 pin.
#[derive(Debug, Clone)]
pub struct Pin {
    pub label: String,
    pub ik: [u8; 32],
    /// `file:///…` or a path under the registry base.
    pub source: String,
    /// True for pins that came from the environment, not from this build.
    pub test_only: bool,
}

/// The pins: compiled ones, plus `ZECBOAT_PINNED_V1` for testing a throwaway collection:
/// `label|ik_hex|source;label|ik_hex|source`. A test pin is always reported as such, and is
/// read only by a build with `--features test-overrides` (`crate::test_override`).
pub fn pins() -> Vec<Pin> {
    let mut v: Vec<Pin> = PINNED_V1
        .iter()
        .filter_map(|(l, k, s)| Some(Pin { label: l.to_string(), ik: hex32(k)?, source: s.to_string(), test_only: false }))
        .collect();
    if let Some(env) = crate::test_override("ZECBOAT_PINNED_V1") {
        for item in env.split(';').filter(|s| !s.trim().is_empty()) {
            let parts: Vec<&str> = item.splitn(3, '|').collect();
            if let [l, k, s] = parts[..] {
                if let Some(ik) = hex32(k.trim()) {
                    v.push(Pin { label: l.trim().to_string(), ik, source: s.trim().to_string(), test_only: true });
                }
            }
        }
    }
    v
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.try_into().ok()
}

pub fn derive_asset_id(ik: &[u8; 32], desc: &str) -> String {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(PERSONAL)
        .to_state()
        .update(&[VERSION])
        .update(ik)
        .update(desc.as_bytes())
        .finalize();
    hex::encode(h.as_bytes())
}

pub fn verify_bip340(ik: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    use k256::schnorr::signature::Verifier;
    // Length first: k256 0.13.4 PANICS ("mid > len") on a signature shorter than 64 bytes
    // instead of returning an error. A truncated .sig from a server must be a refusal, not a
    // crash of the badge. Found by `bip340_rejects_garbage`.
    if sig.len() != 64 {
        return false;
    }
    let Ok(vk) = k256::schnorr::VerifyingKey::from_bytes(ik) else { return false };
    let Ok(sig) = k256::schnorr::Signature::try_from(sig) else { return false };
    vk.verify(msg, &sig).is_ok()
}

async fn fetch(source: &str, suffix: &str) -> std::result::Result<Vec<u8>, String> {
    if let Some(path) = source.strip_prefix("file://") {
        let p = if suffix == ".sig" { path.replace(".json", ".sig") } else { path.to_string() };
        return std::fs::read(&p).map_err(|e| format!("{p}: {e}"));
    }
    // No other source: a manifest comes from the chain or from the build, never from the website.
    Err(format!("{source}: manifests are not fetched over the network"))
}

/// Every carrier memo this wallet holds for `asset_id`, as JSON. All of them, not the first:
/// a copy anyone can send used to be the one memo read, and framed the genuine unit as
/// "Not issued by" (review 2026-10-09, session 4, Issue B).
fn holder_memos(asset_id: &str) -> Vec<Value> {
    let Ok(db) = crate::paths::as_string::wallet_db_path() else { return Vec::new() };
    let Ok(conn) = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) else { return Vec::new() };
    let Ok(rows) = crate::zmap::read_carrier_rows(&conn) else { return Vec::new() };
    let holdings = crate::zmap::holdings_from_rows(rows);
    holdings
        .iter()
        .filter(|h| h.asset_id.eq_ignore_ascii_case(asset_id))
        .flat_map(|h| h.carriers.iter())
        .filter_map(|c| {
            let end = c.memo.iter().position(|&b| b == 0).unwrap_or(c.memo.len());
            serde_json::from_slice(&c.memo[..end]).ok()
        })
        .collect()
}

/// The first memo for `asset_id`, kept for the registry path's "is it registered" lookup.
fn holder_memo(asset_id: &str) -> Option<Value> {
    holder_memos(asset_id).into_iter().next()
}

/// The signed manifests of the pinned collections, built into the wallet: the seed of a fresh
/// install's knowledge, before its first registry scan. The chain copy (a passed audit's
/// etched manifest) is preferred whenever the wallet holds one. **Nothing here is fetched from
/// zecboat.com**: from 2026-10-09 (hardening 13) to the same evening (hardening 16) the pinned
/// path asked the website first and failed when it failed, which is the drop-box mistake the
/// owner had ruled out; the website is not part of verifying a unit.
pub struct Seed {
    pub label: &'static str,
    pub ik: &'static str,
    pub manifest: &'static [u8],
    pub signature: &'static [u8],
}

pub const SEEDS: &[Seed] = &[
    Seed { label: "Lagos Post Card", ik: "e9be4cf91390aba0740ce108a0c2f390d1610ef5c77ede09b445e888fd79b590", manifest: include_bytes!("../pinned/lpc_issuance_manifest.json"), signature: include_bytes!("../pinned/lpc_issuance_manifest.sig") },
    Seed { label: "Happy Birthday Zcash 10", ik: "1ba0bd2f1a1891d616ce912b5e02c38069a9ec87d6b33769bdd8a00741ce1fa0", manifest: include_bytes!("../pinned/hbd10_issuance_manifest.json"), signature: include_bytes!("../pinned/hbd10_issuance_manifest.sig") },
    Seed { label: "Barcelona Post Card 2026", ik: "d289030848144bc321be1030051f90dbf170f0c6752ab8dbf6ed029658d1a820", manifest: include_bytes!("../pinned/bcn26_issuance_manifest.json"), signature: include_bytes!("../pinned/bcn26_issuance_manifest.sig") },
];

/// The ik of the pinned collection whose manifest (chain copy, or built-in seed) lists
/// `asset_id`, with no network. This is what "an asset this wallet knows" means for the
/// automatic Knotline walk (review 2026-10-09, regression over 12-15, Issue A: a memo naming a
/// pinned key is not a reason; being listed under it is).
pub fn pinned_listing_offline(asset_id: &str) -> Option<[u8; 32]> {
    if let Some(a) = crate::collection_audit::audited_collection_listing(asset_id) {
        if let Some(ik) = hex32(&a.ik) {
            // The chain copy's signature is checked here as everywhere else it is read (gate
            // third pass, Finding 6).
            let signed = match (hex::decode(a.manifest_hex.as_deref().unwrap_or("")), hex::decode(a.signature_hex.as_deref().unwrap_or(""))) {
                (Ok(body), Ok(sig)) => verify_bip340(&ik, &body, &sig),
                _ => false,
            };
            if signed && PINNED_V1.iter().any(|(_, k, _)| k.eq_ignore_ascii_case(&a.ik)) {
                return Some(ik);
            }
        }
    }
    for seed in SEEDS {
        let v: Value = serde_json::from_slice(seed.manifest).ok()?;
        if v["assets"].as_array().map(|a| a.iter().any(|x| x["asset_id"].as_str().map(|s| s.eq_ignore_ascii_case(asset_id)).unwrap_or(false))).unwrap_or(false) {
            return hex32(seed.ik);
        }
    }
    None
}

/// The genesis output a manifest this wallet holds states for one asset, with the commitment
/// and the block it states, read with no network: the chain copy of a passed audit (a pinned
/// collection's, or any collection's found in the Zecboat Registry, under the key the audit
/// verified), else a built-in seed; the signature is checked either way (review 2026-10-09,
/// gate second pass, Issues A and C; third pass, Findings 1 and 2). What the send planner
/// needs beside the outpoint: the commitment binds a held lading's first proof to this
/// genesis (W1 done offline, since the manifest is signed), and the block is the only hint a
/// provider is given for the W1 fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedGenesis {
    /// Display-order hex, lower case.
    pub txid: String,
    pub action_index: u32,
    pub cmx: [u8; 32],
    pub height: u32,
    /// True when read from the chain copy rather than the built-in seed.
    pub via_chain_copy: bool,
    /// True when the collection's key is pinned in this build; false for a registry
    /// collection trusted through its passed audit.
    pub pinned: bool,
}

pub fn pinned_genesis_offline(asset_id: &str) -> Option<PinnedGenesis> {
    let find = |v: &Value| -> Option<Value> {
        v["assets"].as_array()?.iter().find(|x| x["asset_id"].as_str().map(|s| s.eq_ignore_ascii_case(asset_id)).unwrap_or(false)).cloned()
    };
    let read = |asset: &Value, via_chain_copy: bool, pinned: bool| -> Option<PinnedGenesis> {
        let iss = &asset["issuance"];
        let txid = iss["txid"].as_str()?.to_ascii_lowercase();
        if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let action_index = u32::try_from(iss["action_index"].as_u64()?).ok()?;
        let cmx = hex32(iss["cmx"].as_str()?)?;
        let height = u32::try_from(iss["height"].as_u64()?).ok()?;
        Some(PinnedGenesis { txid, action_index, cmx, height, via_chain_copy, pinned })
    };
    // A passed audit's chain copy: the key is the one the audit verified (pinned, or the
    // collection's registered key); its signature over the etched bytes is checked again here.
    if let Some(a) = crate::collection_audit::audited_collection_listing(asset_id).filter(|a| a.passed) {
        if let Some(ik) = hex32(&a.ik) {
            let pinned = pins().into_iter().any(|p| p.ik == ik);
            if let (Ok(body), Ok(sig)) = (hex::decode(a.manifest_hex.as_deref().unwrap_or("")), hex::decode(a.signature_hex.as_deref().unwrap_or(""))) {
                if verify_bip340(&ik, &body, &sig) {
                    if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                        if v["schema"] == "zecboat-proof-of-issuance/2" {
                            if let Some(g) = find(&v).and_then(|asset| read(&asset, true, pinned)) {
                                return Some(g);
                            }
                        }
                    }
                }
            }
        }
    }
    for seed in SEEDS {
        let Some(ik) = hex32(seed.ik) else { continue };
        let Ok(v) = serde_json::from_slice::<Value>(seed.manifest) else { continue };
        let Some(asset) = find(&v) else { continue };
        if !verify_bip340(&ik, seed.manifest, seed.signature) {
            continue;
        }
        return read(&asset, false, true);
    }
    None
}

/// The issuance viewing keys of the pinned collections, from the built-in manifests: an
/// account that must never send units (TRUST_MODEL row 13), checked with no network.
pub fn pinned_issuance_ufvks() -> Vec<String> {
    SEEDS
        .iter()
        .filter_map(|s| serde_json::from_slice::<Value>(s.manifest).ok())
        .filter_map(|v| v["identity"]["issuance_ufvk"].as_str().map(|u| u.trim().to_string()))
        .collect()
}

/// The v1 badge, if any held manifest or audited collection lists `asset_id`. `None` when
/// none knows the asset (the caller then says "unknown", which is not a verdict).
///
/// Sources, in order, none of them the website: the chain copy of a pinned collection's
/// manifest (a passed audit, verified under the registered key, which must be the pinned one);
/// the built-in seed; a test pin's local file (test builds only). A source that is missing is
/// skipped, never a verdict.
pub async fn verify(asset_id: &str) -> Option<BadgeState> {
    // 1. The chain copy, when the wallet has audited the collection and its key is pinned.
    if let Some(a) = crate::collection_audit::audited_collection_listing(asset_id) {
        if let Some(pin) = pins().into_iter().find(|p| hex::encode(p.ik).eq_ignore_ascii_case(&a.ik)) {
            if let (Ok(body), Ok(sig)) = (hex::decode(a.manifest_hex.as_deref().unwrap_or("")), hex::decode(a.signature_hex.as_deref().unwrap_or(""))) {
                if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                    if let Some(asset) = v["assets"].as_array().and_then(|x| x.iter().find(|x| x["asset_id"].as_str().map(|s| s.eq_ignore_ascii_case(asset_id)).unwrap_or(false))).cloned() {
                        let mut state = check(&pin, &body, &v, &sig, &asset, asset_id, None).await;
                        if let BadgeState::Verified { checks, .. } = &mut state {
                            checks.push(format!("manifest read from the chain (the collection's close, audited to block {})", a.audited_to));
                        }
                        return Some(state);
                    }
                }
            }
        }
    }
    // 2. The built-in seed of a pinned collection.
    for seed in SEEDS {
        let Some(ik) = hex32(seed.ik) else { continue };
        let Ok(v) = serde_json::from_slice::<Value>(seed.manifest) else { continue };
        let Some(asset) = v["assets"].as_array().and_then(|a| a.iter().find(|x| x["asset_id"].as_str().map(|s| s.eq_ignore_ascii_case(asset_id)).unwrap_or(false))).cloned() else {
            continue;
        };
        let pin = Pin { label: seed.label.to_string(), ik, source: "built-in".into(), test_only: false };
        let mut state = check(&pin, seed.manifest, &v, seed.signature, &asset, asset_id, None).await;
        if let BadgeState::Verified { checks, .. } = &mut state {
            checks.push("manifest from the copy built into this wallet; a registry Check replaces it with the chain's".into());
        }
        return Some(state);
    }
    // 3. Test pins with local files (test builds only).
    for pin in pins().into_iter().filter(|p| p.test_only && p.source.starts_with("file://")) {
        let (Ok(body), Ok(sig)) = (fetch(&pin.source, "").await, fetch(&pin.source, ".sig").await) else { continue };
        let Ok(v) = serde_json::from_slice::<Value>(&body) else { continue };
        let Some(asset) = v["assets"].as_array().and_then(|a| a.iter().find(|x| x["asset_id"].as_str().map(|s| s.eq_ignore_ascii_case(asset_id)).unwrap_or(false))).cloned() else {
            continue;
        };
        return Some(check(&pin, &body, &v, &sig, &asset, asset_id, None).await);
    }
    // A3b phase 4: no pin lists the asset. A collection found in the pinned Zecboat Registry and
    // audited in full (17/17, cached with the manifest and signature rebuilt from the chain) is
    // checked by exactly the same rules, with the registered key in place of a pinned one. The
    // trust root is the registry's key, pinned above; zecboat.com is not consulted.
    let Some(a) = crate::collection_audit::audited_collection_listing(asset_id) else {
        // Registered, but not (or not since phase 4) checked: say so in grey. Falling through
        // would give "not listed", the forgery verdict, for a collection that is merely
        // unchecked.
        let memo_ik = holder_memo(asset_id).and_then(|m| m["ik"].as_str().map(str::to_ascii_lowercase));
        let registered = memo_ik.and_then(|ik| {
            crate::collections::registry_view().ok()?.registrations.into_iter().find(|r| r.valid && r.ik.eq_ignore_ascii_case(&ik))
        });
        return registered.map(|r| BadgeState::CouldNotCheck {
            detail: format!("{} is in the Zecboat Registry but not checked yet: open Collections and press Check", r.name),
        });
    };
    let (Some(ik), Ok(body), Ok(sig)) = (
        hex32(&a.ik),
        hex::decode(a.manifest_hex.as_deref().unwrap_or("")),
        hex::decode(a.signature_hex.as_deref().unwrap_or("")),
    ) else {
        return Some(BadgeState::CouldNotCheck { detail: format!("{}: the cached audit is incomplete; check the collection again", a.name) });
    };
    let v: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return Some(BadgeState::CouldNotCheck { detail: format!("{}: etched manifest is not JSON: {e}", a.name) }),
    };
    let asset = v["assets"].as_array().and_then(|x| x.iter().find(|x| x["asset_id"].as_str().map(|s| s.eq_ignore_ascii_case(asset_id)).unwrap_or(false))).cloned()?;
    let pin = Pin { label: a.name.clone(), ik, source: "zecboat-registry".into(), test_only: false };
    let mut state = check(&pin, &body, &v, &sig, &asset, asset_id, Some(a.audited_to)).await;
    // A registration whose name reads like a collection this wallet knows, under another key,
    // is the impostor the open Registry cannot stop (review 2026-10-09, session 4, Issue A).
    if let BadgeState::Verified { caveat, .. } = &mut state {
        let mine = crate::collections::name_skeleton(&a.name);
        // Against the pinned collections' names.
        let known = PINNED_V1
            .iter()
            .map(|(l, k, _)| (*l, *k))
            .find(|(l, k)| crate::collections::name_skeleton(l) == mine && !k.eq_ignore_ascii_case(&a.ik));
        if let Some((l, _)) = known {
            *caveat = format!(
                "LOOK-ALIKE NAME: this registration is called \"{}\" but its key is not the one this wallet knows for \"{l}\". \
                 Compare the full key with one the issuer published elsewhere. {caveat}",
                a.name
            );
        }
    }
    Some(state)
}

/// The v1 checks, over a manifest and signature from either origin: a pinned collection's
/// published files, or (phase 4) the copy etched on chain and rebuilt by a passed audit.
async fn check(pin: &Pin, body: &[u8], v: &Value, sig: &[u8], asset: &Value, asset_id: &str, registry_at: Option<u32>) -> BadgeState {
    // CHECK 1: BIP-340 under the ik (pinned, or registered and audited), over the raw bytes.
    if v["schema"] != "zecboat-proof-of-issuance/2" || !verify_bip340(&pin.ik, body, sig) {
        return BadgeState::SignatureFailed {
            detail: format!("the manifest for {} is not signed by its pinned key (BIP-340)", pin.label),
        };
    }
    if v["identity"]["ik"].as_str() != Some(&hex::encode(pin.ik)) {
        return BadgeState::SignatureFailed { detail: "the manifest names a different ik than the one pinned".into() };
    }
    // CHECK 3
    if v["network"] != "main" {
        return BadgeState::SignatureFailed { detail: format!("manifest is for network {:?}", v["network"]) };
    }
    // CHECK 6': id from ik + description; holder's memo agrees.
    let desc = asset["asset_desc"].as_str().unwrap_or("");
    if derive_asset_id(&pin.ik, desc) != asset_id.to_ascii_lowercase() {
        return BadgeState::NotListed { issuer: pin.label.clone(), detail: "the listed id does not derive from the pinned ik and its description".into() };
    }
    let mut checks = vec![
        match registry_at {
            None => format!("1 manifest signature (BIP-340) against the ik pinned for {}", pin.label),
            Some(h) => format!(
                "1 found in the Zecboat Registry and audited 17/17 to block {h}; the manifest etched on chain is signed (BIP-340) by the registered ik"
            ),
        },
        "3 network is mainnet".into(),
        "4 this design is listed in the manifest".into(),
        if registry_at.is_some() {
            "6' asset id recomputed from the registered ik and the description etched on chain".into()
        } else {
            "6' asset id recomputed from the pinned ik and the published description".into()
        },
    ];
    // Every copy this wallet holds is read; one that carries the manifest's description (and
    // this ik, when it names one) is enough. A copy that does not is someone else's memo, and
    // is judged on its own in the per-copy list; it never speaks for the genuine unit.
    let memos = holder_memos(asset_id);
    if memos.is_empty() {
        checks.push("6' (no carrier of this asset in this wallet to compare)".into());
    } else {
        let agrees = |m: &Value| {
            m["desc"].as_str() == Some(desc)
                && m["ik"].as_str().map(|mik| mik.eq_ignore_ascii_case(&hex::encode(pin.ik))).unwrap_or(true)
        };
        let n = memos.iter().filter(|m| agrees(m)).count();
        if n == 0 {
            return BadgeState::NotListed {
                issuer: pin.label.clone(),
                detail: "no carrier of this asset in this wallet carries the manifest's description and issuer key".into(),
            };
        }
        if n == memos.len() {
            checks.push("6' your carrier's memo carries the same description (and ik, when it names one)".into());
        } else {
            checks.push(format!("6' {n} of {} copies in this wallet carry the manifest's description; the others are somebody's copies and are judged on their own", memos.len()));
        }
    }
    // CHECK 5': the genesis output is on chain with the stated commitment.
    let iss = &asset["issuance"];
    let (txid, idx, cmx) = (iss["txid"].as_str().unwrap_or(""), iss["action_index"].as_u64().unwrap_or(u64::MAX), iss["cmx"].as_str().unwrap_or(""));
    let height = iss["height"].as_u64().unwrap_or(0) as u32;
    // Asked of the wallet's own node when one answers, of its provider otherwise (0.7.1). The
    // source is made and dropped inside the blocking section: the provider path runs its own
    // short-lived runtime.
    let (on_chain, asked, own_node) = tokio::task::block_in_place(|| {
        let chain = crate::wake::chain();
        use zmap_wake::oracle::{ChainOracle, OracleTrust};
        // The manifest states the block; a provider then is not told which transaction of it.
        if height > 0 {
            chain.hint_height(txid, height);
        }
        (chain.ironwood_actions(txid), chain.described(), chain.trust() == OracleTrust::FullNode)
    });
    match on_chain {
        Ok(Some((_, actions))) if actions.get(idx as usize).map(|a| hex::encode(a.cmx) == cmx).unwrap_or(false) => {
            checks.push(format!("5' genesis output {}… #{} is on chain with the stated commitment, as reported by {asked}", &txid[..16.min(txid.len())], idx));
        }
        Ok(Some(_)) => {
            return BadgeState::SignatureFailed { detail: format!("the genesis commitment the manifest states is not at that output on chain, as reported by {asked}") };
        }
        Ok(None) => return BadgeState::CouldNotCheck { detail: format!("{asked} does not know the genesis transaction {txid}") },
        Err(e) => return BadgeState::CouldNotCheck { detail: format!("could not ask {asked} for the genesis output: {e}") },
    }
    let mut caveat = "Issuance only: that THIS unit descends from that genesis output is the lineage badge's \
                      question, and the collection's close and count are `audit`'s."
        .to_string();
    if pin.test_only {
        caveat = format!("TEST PIN from ZECBOAT_PINNED_V1, not built into this wallet. {caveat}");
    }
    if !own_node {
        caveat = format!("That the genesis output is on chain was reported by {asked}, not checked by a node on this machine. {caveat}");
    }
    if let Some(h) = registry_at {
        caveat = format!(
            "Trusted through the Zecboat Registry (the one key pinned in this wallet) and an audit to block {h}; \
             check the collection again to confirm nothing was issued since. {caveat}"
        );
        // F10: say so when that audit is old (judged by the registry scan, no network).
        if let Some(tip) = crate::collection_audit::registry_scanned_tip() {
            let age = tip.saturating_sub(h);
            if age > crate::collection_audit::AUDIT_STALE_BLOCKS {
                caveat = format!("RE-CHECK DUE: that audit is {age} blocks old. {caveat}");
            }
        }
    }
    BadgeState::Verified {
        issuer: pin.label.clone(),
        pinned: registry_at.is_none(),
        issuer_key: Some(hex::encode(pin.ik)),
        issuance_txid: txid.to_string(),
        issuance_height: height,
        issuance_action_index: idx as u32,
        checks,
        caveat,
        found_in_registry_at: registry_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_registry_key_is_a_mainnet_ufvk_matching_its_address() {
        use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};
        let ufvk = UnifiedFullViewingKey::decode(&zcash_protocol::consensus::MainNetwork, REGISTRY_UFVK).expect("mainnet UFVK");
        let (ua, _) = ufvk.default_address(UnifiedAddressRequest::ALLOW_ALL).unwrap();
        assert_eq!(ua.encode(&zcash_protocol::consensus::MainNetwork), REGISTRY_ADDRESS);
        assert!(REGISTRY_BIRTHDAY > 3_498_000);
    }

    /// The mint's pinned vector, recomputed here by independent code: secret 3 → BIP-340
    /// vector 0 key; this description → this id (printed by the mint's `pinned_vector` test).
    #[test]
    fn agrees_with_the_mint_on_live_wake_test_2() {
        let ik = hex32("7e0a1a7333d80469be1273ff78953fede09f3d136526cb90e06408e9e698e7f7").unwrap();
        let desc = "zmap-desc-v1|Wake Test 2|1|Wake Test 2 #001|WK2|b1240d820bb725b9fdc17862f604eda1a0c6a0da1644fd51daed208bd134d789";
        assert_eq!(derive_asset_id(&ik, desc), "ca54948c3ff3eac68191b4a411dedf451f1bd61204f2db11fd4b17b687e8ff2f");
    }

    #[test]
    fn the_built_in_manifests_verify_under_their_pinned_keys_and_list_their_units() {
        for seed in SEEDS {
            let (label, k, _) = PINNED_V1.iter().find(|(_, k, _)| k.eq_ignore_ascii_case(seed.ik)).expect("every seed has a pin");
            assert_eq!(*label, seed.label);
            let ik = hex32(k).unwrap();
            assert!(verify_bip340(&ik, seed.manifest, seed.signature), "{label}: built-in manifest does not verify under its pinned key");
            let v: Value = serde_json::from_slice(seed.manifest).unwrap();
            assert_eq!(v["schema"], "zecboat-proof-of-issuance/2");
            assert_eq!(v["identity"]["ik"].as_str().map(str::to_ascii_lowercase).as_deref(), Some(k.to_ascii_lowercase().as_str()));
            let assets = v["assets"].as_array().unwrap();
            assert_eq!(assets.len(), 10, "{label}");
            for a in assets {
                let id = a["asset_id"].as_str().unwrap();
                assert_eq!(derive_asset_id(&ik, a["asset_desc"].as_str().unwrap()), id.to_ascii_lowercase());
                assert_eq!(pinned_listing_offline(id), Some(ik), "{label}: {id} is listed offline");
                let g = pinned_genesis_offline(id).expect("the built-in manifest states the genesis");
                assert_eq!(g.txid, a["issuance"]["txid"].as_str().unwrap().to_ascii_lowercase());
                assert_eq!(hex::encode(g.cmx), a["issuance"]["cmx"].as_str().unwrap().to_ascii_lowercase());
                assert!(g.height > 0 && !g.via_chain_copy && g.pinned, "{label}");
            }
        }
        assert!(pinned_listing_offline(&"0".repeat(64)).is_none());
        assert_eq!(pinned_issuance_ufvks().len(), SEEDS.len());
    }

    #[test]
    fn env_pins_are_marked_test_only() {
        std::env::set_var("ZECBOAT_PINNED_V1", "WT2|7e0a1a7333d80469be1273ff78953fede09f3d136526cb90e06408e9e698e7f7|file:///x.json; bad|zz|y");
        let p = pins();
        std::env::remove_var("ZECBOAT_PINNED_V1");
        // The compiled pins (never test-only) plus the one well-formed env pin (test-only).
        assert_eq!(p.len(), PINNED_V1.len() + 1);
        assert!(p[..PINNED_V1.len()].iter().all(|x| !x.test_only));
        assert!(p[PINNED_V1.len()].test_only);
        assert!(PINNED_V1.iter().all(|(_, k, s)| hex32(k).is_some() && s.ends_with(".json")), "every compiled pin has a 32-byte key and a manifest path");
    }

    #[test]
    fn bip340_rejects_garbage() {
        let ik = hex32("7e0a1a7333d80469be1273ff78953fede09f3d136526cb90e06408e9e698e7f7").unwrap();
        assert!(!verify_bip340(&ik, b"x", &[0u8; 64]));
        assert!(!verify_bip340(&ik, b"x", &[0u8; 10]));
    }
}
