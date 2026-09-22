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
const PINNED_ISSUERS: &[(&str, &str)] = &[
    (
        "Happy Birthday Zcash",
        "98508d73ce15d3f2cdc3506b3a53da0f4bece0c51116e296057de2ea922ab0db",
    ),
    (
        "Barcelona Post Card",
        "ecc9f9a3b148f4066a09bb46a713c6dbac39571665a7783f9fd15d4ee8bf31c4",
    ),
];

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
        issuance_txid: String,
        issuance_height: u32,
        checks: Vec<String>,
        caveat: String,
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
) -> std::result::Result<(String, Issuance, u64), BadgeState> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let sig: [u8; 64] = sig.try_into().map_err(|_| BadgeState::SignatureFailed {
        detail: format!(
            "the signature is {} bytes; an ed25519 signature is 64. It is served raw, not hex.",
            sig.len()
        ),
    })?;
    let signature = Signature::from_bytes(&sig);

    // CHECK 1 -- against every pinned key, because one wallet holds assets from several ranges.
    let mut matched: Option<&str> = None;
    for (label, key_hex) in PINNED_ISSUERS {
        let Some(raw) = hex32(key_hex) else { continue };
        let Ok(vk) = VerifyingKey::from_bytes(&raw) else {
            continue;
        };
        if vk.verify(body, &signature).is_ok() {
            matched = Some(label);
            break;
        }
    }
    let issuer_label = matched.ok_or_else(|| BadgeState::SignatureFailed {
        detail:
            "the manifest is not signed by any issuer key pinned in this wallet. Either it is \
             not ours, or it was tampered with in transit."
                .to_string(),
    })?;

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

    let endpoint = crate::rpc::grpc_endpoint();
    let mut client = crate::rpc::lightwallet::compact_tx_streamer_client::CompactTxStreamerClient::connect(
        endpoint.clone(),
    )
    .await
    .map_err(|e| BadgeState::CouldNotCheck {
        detail: format!("could not reach the node at {endpoint} to fetch the issuance transaction: {e}"),
    })?;

    let raw = client
        .get_transaction(tonic::Request::new(crate::rpc::lightwallet::TxFilter {
            block: None,
            index: 0,
            hash: txid.to_vec(),
        }))
        .await
        .map_err(|e| BadgeState::CouldNotCheck {
            detail: format!("the node could not return the issuance transaction: {e}"),
        })?
        .into_inner();

    let branch = BranchId::try_from(NU63_BRANCH_ID).map_err(|_| BadgeState::CouldNotCheck {
        detail: "internal: NU6.3 branch id rejected".into(),
    })?;
    let tx = Transaction::read(Cursor::new(&raw.data), branch).map_err(|e| {
        BadgeState::CouldNotCheck {
            detail: format!("the issuance transaction did not parse: {e}"),
        }
    })?;

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

    let base = crate::rpc::registry_base();
    let client = reqwest::Client::new();

    let fetch = |url: String| {
        let c = client.clone();
        async move {
            let res = c.get(&url).send().await.map_err(|e| format!("{url}: {e}"))?;
            if !res.status().is_success() {
                return Err(format!("{url}: HTTP {}", res.status()));
            }
            res.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("{url}: {e}"))
        }
    };

    let body = match fetch(format!("{base}/issuance/issuance_manifest.json")).await {
        Ok(b) => b,
        Err(e) => return Ok(BadgeState::CouldNotCheck { detail: e }),
    };
    let sig = match fetch(format!("{base}/issuance/issuance_manifest.sig")).await {
        Ok(b) => b,
        Err(e) => return Ok(BadgeState::CouldNotCheck { detail: e }),
    };

    let (issuer, issuance, _generation) = match verify_manifest(&body, &sig, &asset_id) {
        Ok(v) => v,
        Err(state) => return Ok(state),
    };

    if let Err(state) = verify_disclosure(&issuance, &asset_id).await {
        return Ok(state);
    }

    Ok(BadgeState::Verified {
        issuer,
        issuance_txid: issuance.txid,
        issuance_height: issuance.height,
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
    })
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

    #[test]
    fn a_wrong_length_signature_is_a_failure_not_a_panic() {
        let s = verify_manifest(b"{}", &[0u8; 63], &"a".repeat(64)).unwrap_err();
        match s {
            BadgeState::SignatureFailed { detail } => assert!(detail.contains("64")),
            other => panic!("expected SignatureFailed, got {other:?}"),
        }
    }

    /// The pinned keys are claims this binary makes. If one is malformed the badge silently
    /// stops verifying that range, which is worse than failing loudly.
    #[test]
    fn every_pinned_key_is_well_formed() {
        for (label, key) in PINNED_ISSUERS {
            let raw = hex32(key).unwrap_or_else(|| panic!("{label}: key is not 64 hex chars"));
            ed25519_dalek::VerifyingKey::from_bytes(&raw)
                .unwrap_or_else(|e| panic!("{label}: not a valid ed25519 key: {e}"));
        }
    }
}
