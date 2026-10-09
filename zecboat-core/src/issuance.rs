//! Issuance verification — the "Design Verified" badge.
//!
//! Answers one question: **did the issuer this asset names actually create this design?**
//!
//! ## Why this exists, and why the existing check is not enough
//!
//! `rpc::verify_asset_image` checks that the artwork hashes to the value committed in the
//! memo. That is ZMAP-v0.3 §9 check 6, and it is real — but on its own it endorses forgeries.
//! `ZsaGallery.svelte` already says so in a comment: *"a forger can copy a memo and point it at
//! the same artwork, and this check passes for them too."*
//!
//! §12.1 is explicit about the trap:
//!
//! > Implementations MUST NOT report a note as genuine on the strength of checks 1–4 and 6
//! > alone. A verifier collapsing them into one "verified" badge will endorse forgeries.
//!
//! So this module runs **five of the six checks**, and check 5 — the disclosure — is the one
//! that makes the rest mean anything.
//!
//! | # | Check | Here |
//! |---|---|---|
//! | 1 | issuer key — ed25519 over the manifest | `verify_manifest` |
//! | 2 | freshness — generation >= highest seen | **NOT DONE** — needs a local generation log |
//! | 3 | network matches the chain queried | `verify_manifest` |
//! | 4 | `asset_id` listed in `assets[]` | `verify_manifest` |
//! | 5 | disclosure recovers the output | `verify_disclosure` |
//! | 6 | artwork hash | already in `rpc::verify_asset_image` |
//!
//! **Check 2 is absent and the badge must not imply otherwise.** Without a generation log a
//! rolled-back manifest is undetectable. `Verified` therefore means "checks 1, 3, 4, 5 and 6
//! passed", not "verified" in the unqualified sense the spec warns about.
//!
//! ## Two properties that are not optional
//!
//! **The issuer key is PINNED in this binary.** Fetching the key from beside the manifest —
//! which is what `zmap-verify` still does — proves only that the server agrees with itself.
//! `CLAUDE.md` calls pinning "the open work"; this is it, for the wallet.
//!
//! **The signature covers RAW BYTES.** Never parse-then-reserialise before verifying. The
//! published examples verify over raw bytes and *fail* over re-serialised JSON, and
//! canonicalisation would force every verifier to reimplement the same normalisation.

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Issuer keys, pinned. One per range — §7.1 persists the highest generation *per issuer key*,
/// so two ranges sharing a key produce order-dependent false rollback rejections.
///
/// A key here is a claim this binary makes about who Zecboat is. Adding one is a release
/// decision, not a configuration change, which is the entire point of pinning.
/// `(range, issuer key, manifest path under the registry base)`.
///
/// ONE KEY PER COLLECTION, AND ONE MANIFEST PATH PER KEY. The path is pinned beside the key
/// on purpose: the wallet then knows exactly where each collection's manifest lives without
/// trusting anything in a memo, and a manifest fetched from a collection's path is verified
/// against THAT collection's key only — location and key are bound together.
///
/// Before 2026-09-25 this table had two keys and the badge fetched one fixed path,
/// `/issuance/issuance_manifest.json`. That single path is Happy Birthday's, so a Barcelona
/// asset could never be listed no matter what was published — the badge was
/// single-collection by construction, and it surfaced the day the first Barcelona card
/// landed in a wallet. §7.1 (one generation sequence per issuer key) is also why the two
/// cannot share a manifest: two collections under one key collide on rollback detection.
///
/// The path is a FILE PREFIX under `/issuance/`, because that is the convention the server
/// actually uses and has since 2026-09-15 — verified by listing `/var/www/webwallet/public/
/// issuance/` on 2026-09-25: `issuance_manifest.*` (Happy Birthday, unprefixed, the legacy
/// root), `barcelona_issuance_manifest.*`, `nomad_issuance_manifest.*`. The first version of
/// this table invented a per-collection DIRECTORY, `issuance/barcelona_post_card/…`, and
/// probed only that path — which is how "Barcelona has no manifest" got written into
/// CLAUDE.md while a generation-2 manifest had been live for ten days. Read what is served
/// before designing where it should be.
const PINNED_ISSUERS: &[(&str, &str, &str)] = &[
    (
        "Happy Birthday Zcash",
        "98508d73ce15d3f2cdc3506b3a53da0f4bece0c51116e296057de2ea922ab0db",
        "issuance/issuance_manifest",
    ),
    (
        "Barcelona Post Card",
        "ecc9f9a3b148f4066a09bb46a713c6dbac39571665a7783f9fd15d4ee8bf31c4",
        "issuance/barcelona_issuance_manifest",
    ),
];

/// The pinned keys, for the About panel.
///
/// Published deliberately: the badge claims to verify "against a key pinned in this wallet",
/// and a claim a user cannot inspect is a claim they have to take on trust. These are public
/// keys — showing them costs nothing and makes the badge checkable.
pub fn pinned_issuers() -> Vec<serde_json::Value> {
    PINNED_ISSUERS
        .iter()
        .map(|(label, key, path)| serde_json::json!({ "range": label, "key": key, "manifest": path }))
        .collect()
}

/// What the badge is allowed to say. Four states, never one tick.
///
/// The three failure states are distinct on purpose. Collapsing "could not reach the registry"
/// into "not genuine" defames a holder; collapsing it into "verified" endorses a forgery. The
/// same discipline §9 demands of a verifier — report *which* check failed.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BadgeState {
    /// Checks 1, 3, 4 and 5 passed against a pinned key. **Not check 2.**
    Verified {
        issuer: String,
        /// True when the key the checks were made against is pinned in this build (or a test
        /// pin); false for a key taken from the Registry after a passed audit. Said explicitly,
        /// so the screen does not infer it from a number (review 2026-10-09, Issue L.5).
        pinned: bool,
        /// The issuance key (`ik`, hex) the checks were made against, so the badge can show
        /// its fingerprint beside the name: a look-alike name under another key must not read
        /// as the same issuer (audit 2026-10-08, ZMAP C).
        issuer_key: Option<String>,
        issuance_txid: String,
        issuance_height: u32,
        /// The Action index of the issuance output: with `issuance_txid`, the asset's genesis
        /// output for Wake (chapter 8). Additive; the badge UI ignores it.
        issuance_action_index: u32,
        checks: Vec<String>,
        caveat: String,
        /// A3b phase 4: set when the trust came from the pinned Zecboat Registry plus a passed
        /// audit (the block the audit ran to), not from a key pinned for this collection.
        found_in_registry_at: Option<u32>,
    },
    /// The manifest verified, but this `asset_id` is not in it. This is the forgery answer.
    NotListed { issuer: String, detail: String },
    /// The manifest was fetched and its signature did not verify under any pinned key.
    SignatureFailed { detail: String },
    /// We could not complete the check. **This is not a verdict about the asset.**
    CouldNotCheck { detail: String },
}

#[derive(Debug, Deserialize)]
struct Manifest {
    generation: u64,
    network: String,
    issuer: ManifestIssuer,
    assets: Vec<ManifestAsset>,
}

#[derive(Debug, Deserialize)]
struct ManifestIssuer {
    name: String,
    // The signed schema keeps `collection`. The UI says "range" -- see
    // ~/zecboat_positioning/. Renaming the field would break the signature for a synonym.
    collection: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManifestAsset {
    asset_id: String,
    name: Option<String>,
    issuance: Option<Issuance>,
}

/// A signed issuance manifest is tens of kilobytes; a megabyte is far above any real one.
pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize, Clone)]
struct Issuance {
    txid: String,
    height: u32,
    action_index: usize,
    ock: String,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Checks 1, 3 and 4 against the pinned keys.
///
/// Takes the manifest as **bytes**, not as a parsed value, because check 1 verifies the
/// signature over exactly what was served. Parsing happens afterwards and only to read fields.
fn verify_manifest(
    body: &[u8],
    sig: &[u8],
    asset_id: &str,
    issuer_label: &str,
    key_hex: &str,
) -> std::result::Result<(String, Issuance, u64), BadgeState> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let sig: [u8; 64] = sig.try_into().map_err(|_| BadgeState::SignatureFailed {
        detail: format!(
            "the signature is {} bytes; an ed25519 signature is 64. It is served raw, not hex.",
            sig.len()
        ),
    })?;
    let signature = Signature::from_bytes(&sig);

    // CHECK 1 -- against the ONE key pinned for the path this manifest was fetched from.
    // It used to try every pinned key, which let a manifest at collection A's path pass
    // if signed by collection B's key. Binding path to key closes that.
    let raw = hex32(key_hex).ok_or_else(|| BadgeState::CouldNotCheck {
        detail: format!("the pinned key for {issuer_label} is malformed in this build"),
    })?;
    let vk = VerifyingKey::from_bytes(&raw).map_err(|e| BadgeState::CouldNotCheck {
        detail: format!("the pinned key for {issuer_label} is not a valid ed25519 key: {e}"),
    })?;
    if vk.verify(body, &signature).is_err() {
        return Err(BadgeState::SignatureFailed {
            detail: format!(
                "the manifest at {issuer_label}'s path is not signed by {issuer_label}'s pinned \
                 key. Either it is not ours, or it was tampered with in transit."
            ),
        });
    }

    let manifest: Manifest =
        serde_json::from_slice(body).map_err(|e| BadgeState::CouldNotCheck {
            detail: format!("the signature verified but the manifest did not parse: {e}"),
        })?;

    // CHECK 3 -- network. A mainnet wallet must not accept a testnet manifest.
    if manifest.network != "main" {
        return Err(BadgeState::SignatureFailed {
            detail: format!(
                "this manifest is for the '{}' network; this wallet is on mainnet",
                manifest.network
            ),
        });
    }

    // CHECK 4 -- is this asset in it?
    let asset = manifest
        .assets
        .iter()
        .find(|a| a.asset_id.eq_ignore_ascii_case(asset_id))
        .ok_or_else(|| BadgeState::NotListed {
            issuer: manifest.issuer.name.clone(),
            detail: format!(
                "the manifest signed by {} lists {} designs and this asset is not among them",
                issuer_label,
                manifest.assets.len()
            ),
        })?;

    let issuance = asset.issuance.clone().ok_or_else(|| BadgeState::CouldNotCheck {
        detail: format!(
            "'{}' is listed but carries no issuance disclosure, so check 5 cannot run. \
             Checks 1, 3 and 4 passed.",
            asset.name.clone().unwrap_or_else(|| asset_id.to_string())
        ),
    })?;

    let _ = manifest.issuer.collection;
    Ok((manifest.issuer.name, issuance, manifest.generation))
}

/// CHECK 5 — the disclosure. The only check that ties *this design* to *that issuer*.
///
/// Fetches the issuance transaction from the node the wallet is already using and recovers the
/// output the manifest points at, using the published OCK. An OCK is self-authenticating: a
/// forged one simply fails to recover. Nothing here trusts the registry.
async fn verify_disclosure(issuance: &Issuance, asset_id: &str) -> std::result::Result<(), BadgeState> {
    use std::io::Cursor;
    use orchard::note_encryption::IronwoodDomain;
    use zcash_note_encryption::{try_output_recovery_with_ock, OutgoingCipherKey};
    use zcash_primitives::transaction::Transaction;
    use zcash_protocol::consensus::BranchId;

    const NU63_BRANCH_ID: u32 = 0x37a5_165b;

    let mut txid = hex32(&issuance.txid).ok_or_else(|| BadgeState::CouldNotCheck {
        detail: "the manifest's issuance txid is not 64 hex characters".into(),
    })?;
    txid.reverse(); // display order -> internal order

    let ock_bytes = hex32(&issuance.ock).ok_or_else(|| BadgeState::CouldNotCheck {
        detail: "the manifest's disclosure OCK is not 64 hex characters".into(),
    })?;

    // Through the chain source in force (own node, or provider under the cover of the
    // manifest's block), as the v1 check already does. Until 2026-10-09 this asked the provider
    // by id whatever the setting, so a "my own node only" user still told the provider which
    // issuance transaction they were looking at (review, regression Finding 7).
    let raw_data = tokio::task::block_in_place(|| {
        let chain = crate::wake::chain();
        if issuance.height > 0 {
            chain.hint_height(&issuance.txid, issuance.height);
        }
        let described = chain.described();
        match chain.raw_transaction(&txid) {
            Ok(Some((_, data))) => Ok(data),
            Ok(None) => Err(BadgeState::CouldNotCheck {
                detail: format!("{described} does not know the issuance transaction"),
            }),
            Err(e) => Err(BadgeState::CouldNotCheck {
                detail: format!("could not fetch the issuance transaction from {described}: {e}"),
            }),
        }
    })?;

    let branch = BranchId::try_from(NU63_BRANCH_ID).map_err(|_| BadgeState::CouldNotCheck {
        detail: "internal: NU6.3 branch id rejected".into(),
    })?;
    let tx = Transaction::read(Cursor::new(&raw_data), branch).map_err(|e| {
        BadgeState::CouldNotCheck {
            detail: format!("the issuance transaction did not parse: {e}"),
        }
    })?;
    // The server's word is checked against the id asked for (audit 2026-10-08, Zecboat J):
    // a different transaction is "could not check", not a verdict either way.
    if tx.txid().as_ref() != &txid[..] {
        return Err(BadgeState::CouldNotCheck {
            detail: "the server answered with a different transaction than the issuance transaction asked for".into(),
        });
    }

    // Every ZMAP mint since NU6.3 is Ironwood -- HBD's own mint has 11 Ironwood actions and
    // 0 Orchard. Reading an Orchard-only producer and concluding otherwise is a documented
    // mistake; do not repeat it here.
    let bundle = tx.ironwood_bundle().ok_or_else(|| BadgeState::CouldNotCheck {
        detail: "the issuance transaction has no Ironwood bundle".into(),
    })?;
    let action = bundle
        .actions()
        .get(issuance.action_index)
        .ok_or_else(|| BadgeState::SignatureFailed {
            detail: format!(
                "the manifest points at action {} but the transaction has {}",
                issuance.action_index,
                bundle.actions().len()
            ),
        })?;

    let domain = IronwoodDomain::for_action(action);
    let ock = OutgoingCipherKey(ock_bytes);
    // Signature matches ironwood_shield/src/disclose_verify.rs, which produced the published
    // HBD disclosures. Four arguments: the action carries its own cv_net.
    let recovered =
        try_output_recovery_with_ock(&domain, &ock, action, &action.encrypted_note().out_ciphertext);

    let Some((_note, _addr, memo)) = recovered else {
        // A forged OCK fails here. So does a genuine one pointed at the wrong action.
        return Err(BadgeState::SignatureFailed {
            detail: "the disclosure in the manifest does not open that output. The asset is \
                     listed and the manifest is signed, but the issuer has not shown it created \
                     this design."
                .into(),
        });
    };

    // The recovered memo must actually name this asset. Without this the check proves only
    // that *some* output was opened -- not that it is the one claimed.
    let text = String::from_utf8_lossy(&memo);
    if !text.to_lowercase().contains(&asset_id.to_lowercase()) {
        return Err(BadgeState::SignatureFailed {
            detail: "the disclosure opened an output, but its memo does not name this asset id"
                .into(),
        });
    }

    Ok(())
}

/// Run checks 1, 3, 4 and 5 for one asset and return what the badge may say.
///
/// Never returns `Err`: every outcome is a `BadgeState`, because "could not check" is a result
/// the UI must render distinctly rather than an error to swallow.
pub async fn verify_issuance(asset_id: String) -> Result<BadgeState> {
    if asset_id.len() != 64 || !asset_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(BadgeState::CouldNotCheck {
            detail: "not a valid ZMAP asset id (expected 64 hex characters)".into(),
        });
    }

    // A1b: a collection minted under identity v1 is checked by its own rules first.
    if let Some(state) = crate::issuance_v1::verify(&asset_id).await {
        return Ok(state);
    }

    let base = crate::rpc::registry_base();

    // Manifests and signatures through the one bounded registry client (review 2026-10-09,
    // regression Finding 10).
    let fetch = |url: String| async move {
        crate::rpc::registry_fetch(&url, MAX_MANIFEST_BYTES).await.map(|(_, b)| b).map_err(|e| e.to_string())
    };

    // Every pinned collection, at its own path, against its own key. The first manifest
    // that verifies AND lists this asset wins; the others are consulted only if none does,
    // and then the outcome is ranked: a tampered pinned manifest outranks an unreachable one,
    // which outranks "simply not listed" — because those call for different responses.
    let mut found: Option<(String, Issuance, u64)> = None;
    let mut not_listed: Vec<String> = Vec::new();
    let mut unreachable: Vec<String> = Vec::new();
    let mut tampered: Vec<String> = Vec::new();

    for (label, key_hex, path) in PINNED_ISSUERS {
        let body = match fetch(format!("{base}/{path}.json")).await {
            Ok(b) => b,
            Err(e) => { unreachable.push(format!("{label} ({e})")); continue; }
        };
        let sig = match fetch(format!("{base}/{path}.sig")).await {
            Ok(b) => b,
            Err(e) => { unreachable.push(format!("{label} ({e})")); continue; }
        };
        match verify_manifest(&body, &sig, &asset_id, label, key_hex) {
            Ok(v) => { found = Some(v); break; }
            Err(BadgeState::NotListed { detail, .. }) => not_listed.push(detail),
            Err(BadgeState::SignatureFailed { detail }) => tampered.push(detail),
            Err(other) => return Ok(other),
        }
    }

    let (issuer, issuance, _generation) = match found {
        Some(v) => v,
        None if !tampered.is_empty() => {
            return Ok(BadgeState::SignatureFailed { detail: tampered.join("; ") })
        }
        None if !unreachable.is_empty() => {
            return Ok(BadgeState::CouldNotCheck {
                detail: format!(
                    "not listed in any manifest that could be reached, and {} could not be: {}",
                    unreachable.len(),
                    unreachable.join("; ")
                ),
            })
        }
        None => {
            return Ok(BadgeState::NotListed {
                issuer: "no pinned issuer".into(),
                detail: not_listed.join("; "),
            })
        }
    };

    if let Err(state) = verify_disclosure(&issuance, &asset_id).await {
        return Ok(state);
    }

    Ok(BadgeState::Verified {
        issuer,
        pinned: true,
        // The legacy (v0.3 disclosure) path checks a pinned ed25519 key, not an `ik`.
        issuer_key: None,
        issuance_txid: issuance.txid,
        issuance_height: issuance.height,
        issuance_action_index: issuance.action_index as u32,
        checks: vec![
            "1 issuer signature, against a key pinned in this wallet".into(),
            "3 network is mainnet".into(),
            "4 this design is listed in the manifest".into(),
            "5 the issuer's disclosure opens the issuance output".into(),
        ],
        caveat: "Check 2 (freshness) is not implemented: this wallet keeps no generation log, \
                 so a rolled-back manifest would not be detected. Supply is not checked and \
                 cannot be — see ZMAP-v0.3 §13."
            .into(),
        found_in_registry_at: None,
    })
}

/// The genesis output of `asset_id` according to a pinned, verified manifest:
/// `(txid in display order, action_index)`. `None` when no pinned manifest lists it or none
/// could be verified. Wake chapter 8 uses this to decide whether a carrier is a first-holder
/// note (genesis proof) and to confirm a delivered lading's genesis against the issuer.
pub async fn genesis_outpoint(asset_id: &str) -> Option<(String, u32, bool)> {
    match verify_issuance(asset_id.to_string()).await {
        Ok(BadgeState::Verified { issuance_txid, issuance_action_index, found_in_registry_at, .. }) => {
            Some((issuance_txid.to_ascii_lowercase(), issuance_action_index, found_in_registry_at.is_some()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex32_is_strict() {
        assert!(hex32("00").is_none(), "short input must not parse");
        assert!(hex32(&"z".repeat(64)).is_none(), "non-hex must not parse");
        assert_eq!(hex32(&"ab".repeat(32)).unwrap()[0], 0xab);
    }

    /// A manifest served at collection A's path must be signed by collection A's key.
    ///
    /// Before per-collection paths, check 1 tried EVERY pinned key, so a manifest at one
    /// collection's location signed by another collection's key would pass. Binding the path
    /// to the key closes that: a valid signature from the wrong pinned key is a failure.
    #[test]
    fn a_manifest_signed_by_the_wrong_collections_key_is_refused() {
        use ed25519_dalek::{Signer, SigningKey};
        let body = br#"{"network":"main","generation":1,"issuer":{"name":"x"},"assets":[]}"#;

        // A genuine signature — just not from the key pinned for this path.
        let other = SigningKey::from_bytes(&[7u8; 32]);
        let sig = other.sign(body).to_bytes();

        let (label, key, _) = PINNED_ISSUERS[0];
        match verify_manifest(body, &sig, &"a".repeat(64), label, key) {
            Err(BadgeState::SignatureFailed { detail }) => {
                assert!(detail.contains(label), "the refusal must name the collection: {detail}")
            }
            other => panic!("a correctly-formed signature from the WRONG key was accepted: {other:?}"),
        }

        // And the same signature IS accepted when the pinned key is the one that made it:
        // check 1 passes, and it proceeds to fail at check 4 (not listed) instead.
        let hex = hex::encode(other.verifying_key().to_bytes());
        match verify_manifest(body, &sig, &"a".repeat(64), "test", &hex) {
            Err(BadgeState::NotListed { .. }) => {}
            other => panic!("expected check 1 to pass and check 4 to fail, got {other:?}"),
        }
    }

    #[test]
    fn a_wrong_length_signature_is_a_failure_not_a_panic() {
        let (label, key, _) = PINNED_ISSUERS[0];
        let s = verify_manifest(b"{}", &[0u8; 63], &"a".repeat(64), label, key).unwrap_err();
        match s {
            BadgeState::SignatureFailed { detail } => assert!(detail.contains("64")),
            other => panic!("expected SignatureFailed, got {other:?}"),
        }
    }

    /// The pinned keys are claims this binary makes. If one is malformed the badge silently
    /// stops verifying that range, which is worse than failing loudly.
    #[test]
    fn every_pinned_key_is_well_formed() {
        for (label, key, path) in PINNED_ISSUERS {
            assert!(!path.is_empty() && !path.starts_with('/') && !path.ends_with('/'),
                "{label}: manifest path must be a bare relative path, got {path:?}");
            let raw = hex32(key).unwrap_or_else(|| panic!("{label}: key is not 64 hex chars"));
            ed25519_dalek::VerifyingKey::from_bytes(&raw)
                .unwrap_or_else(|e| panic!("{label}: not a valid ed25519 key: {e}"));
        }
    }
}
