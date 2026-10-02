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
//!      asked of the node this wallet uses (`ZECBOAT_ZEBRAD_RPC`).
//!
//! What it does NOT check, and says so: that this unit descends from that genesis output
//! (that is the lineage badge, Wake), and the collection's close and count (that is `audit`).

use serde_json::Value;

use crate::issuance::BadgeState;

pub const PERSONAL: &[u8; 15] = b"ZMAP-AssetID-v1";
pub const VERSION: u8 = 1;

/// Collections under identity v1 pinned in this build: (label, ik hex, manifest location
/// relative to the registry base). Empty until the first real collection is minted; the owner
/// adds a line per collection, as for `PINNED_ISSUERS`.
pub const PINNED_V1: &[(&str, &str, &str)] = &[];

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
/// `label|ik_hex|source;label|ik_hex|source`. A test pin is always reported as such.
pub fn pins() -> Vec<Pin> {
    let mut v: Vec<Pin> = PINNED_V1
        .iter()
        .filter_map(|(l, k, s)| Some(Pin { label: l.to_string(), ik: hex32(k)?, source: s.to_string(), test_only: false }))
        .collect();
    if let Ok(env) = std::env::var("ZECBOAT_PINNED_V1") {
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
    let url = format!("{}/{}{}", crate::rpc::registry_base(), source.trim_start_matches('/'), suffix);
    let res = reqwest::get(&url).await.map_err(|e| format!("{url}: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("{url}: HTTP {}", res.status()));
    }
    res.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("{url}: {e}"))
}

/// The holder's own carrier memo for `asset_id`, as JSON, if this wallet holds one.
fn holder_memo(asset_id: &str) -> Option<Value> {
    let db = crate::paths::as_string::wallet_db_path().ok()?;
    let conn = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    let rows = crate::zmap::read_carrier_rows(&conn).ok()?;
    let holdings = crate::zmap::holdings_from_rows(rows);
    let h = holdings.iter().find(|h| h.asset_id.eq_ignore_ascii_case(asset_id))?;
    let memo = &h.carriers.first()?.memo;
    let end = memo.iter().position(|&b| b == 0).unwrap_or(memo.len());
    serde_json::from_slice(&memo[..end]).ok()
}

/// The v1 badge, if any v1 pin lists `asset_id`. `None` when no v1 pin knows the asset (the
/// caller then falls back to the pre-Wake badge).
pub async fn verify(asset_id: &str) -> Option<BadgeState> {
    for pin in pins() {
        let body = match fetch(&pin.source, "").await {
            Ok(b) => b,
            Err(e) => return Some(BadgeState::CouldNotCheck { detail: format!("{}: {e}", pin.label) }),
        };
        let v: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => return Some(BadgeState::CouldNotCheck { detail: format!("{}: manifest is not JSON: {e}", pin.label) }),
        };
        let Some(asset) = v["assets"].as_array().and_then(|a| a.iter().find(|x| x["asset_id"].as_str().map(|s| s.eq_ignore_ascii_case(asset_id)).unwrap_or(false))).cloned() else {
            continue; // not this collection; try the next pin
        };
        let sig = match fetch(&pin.source, ".sig").await {
            Ok(s) => s,
            Err(e) => return Some(BadgeState::CouldNotCheck { detail: format!("{}: signature: {e}", pin.label) }),
        };
        return Some(check(&pin, &body, &v, &sig, &asset, asset_id, None).await);
    }
    // A3b phase 4: no pin lists the asset. A collection found in the pinned Zecboat Registry and
    // audited in full (17/17, cached with the manifest and signature rebuilt from the chain) is
    // checked by exactly the same rules, with the registered key in place of a pinned one. The
    // trust root is the registry's key, pinned above; zecboat.com is not consulted.
    let Some(a) = crate::collection_audit::audited_collection_listing(asset_id) else {
        // Registered, but not (or not since phase 4) checked: say so in grey. Falling through
        // would reach the pre-v1 badge, whose answer for an unknown asset is "not issued by",
        // the forgery verdict, for a collection that is merely unchecked.
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
    Some(check(&pin, &body, &v, &sig, &asset, asset_id, Some(a.audited_to)).await)
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
    match holder_memo(asset_id) {
        Some(m) => {
            if m["desc"].as_str() != Some(desc) {
                return BadgeState::NotListed { issuer: pin.label.clone(), detail: "your carrier's memo carries a different description than the manifest".into() };
            }
            if let Some(mik) = m["ik"].as_str() {
                if !mik.eq_ignore_ascii_case(&hex::encode(pin.ik)) {
                    return BadgeState::NotListed { issuer: pin.label.clone(), detail: "your carrier's memo names a different issuer key".into() };
                }
            }
            checks.push("6' your carrier's memo carries the same description (and ik, when it names one)".into());
        }
        None => checks.push("6' (no carrier of this asset in this wallet to compare)".into()),
    }
    // CHECK 5': the genesis output is on chain with the stated commitment.
    let iss = &asset["issuance"];
    let (txid, idx, cmx) = (iss["txid"].as_str().unwrap_or(""), iss["action_index"].as_u64().unwrap_or(u64::MAX), iss["cmx"].as_str().unwrap_or(""));
    let height = iss["height"].as_u64().unwrap_or(0) as u32;
    let oracle = crate::wake::oracle();
    let on_chain = tokio::task::block_in_place(|| oracle.ironwood_actions(txid));
    match on_chain {
        Ok(Some((_, actions))) if actions.get(idx as usize).map(|a| hex::encode(a.cmx) == cmx).unwrap_or(false) => {
            checks.push(format!("5' genesis output {}… #{} is on chain with the stated commitment", &txid[..16.min(txid.len())], idx));
        }
        Ok(Some(_)) => {
            return BadgeState::SignatureFailed { detail: "the genesis commitment the manifest states is not at that output on chain".into() };
        }
        Ok(None) => return BadgeState::CouldNotCheck { detail: format!("the node does not know the genesis transaction {txid}") },
        Err(e) => return BadgeState::CouldNotCheck { detail: format!("could not ask the node for the genesis output: {e}") },
    }
    let mut caveat = "Issuance only: that THIS unit descends from that genesis output is the lineage badge's \
                      question, and the collection's close and count are `audit`'s."
        .to_string();
    if pin.test_only {
        caveat = format!("TEST PIN from ZECBOAT_PINNED_V1, not built into this wallet. {caveat}");
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
    fn env_pins_are_marked_test_only() {
        std::env::set_var("ZECBOAT_PINNED_V1", "WT2|7e0a1a7333d80469be1273ff78953fede09f3d136526cb90e06408e9e698e7f7|file:///x.json; bad|zz|y");
        let p = pins();
        std::env::remove_var("ZECBOAT_PINNED_V1");
        assert_eq!(p.len(), 1);
        assert!(p[0].test_only);
    }

    #[test]
    fn bip340_rejects_garbage() {
        let ik = hex32("7e0a1a7333d80469be1273ff78953fede09f3d136526cb90e06408e9e698e7f7").unwrap();
        assert!(!verify_bip340(&ik, b"x", &[0u8; 64]));
        assert!(!verify_bip340(&ik, b"x", &[0u8; 10]));
    }
}
