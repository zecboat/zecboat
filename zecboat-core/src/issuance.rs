//! Issuance verification — the "Design Verified" badge.
//!
//! Answers one question: **did the issuer this asset names actually create this design?**
//! The checks are `issuance_v1`'s (identity v1: a BIP-340 `ik`, a signed proof-of-issuance
//! manifest held by this wallet, the genesis output on chain with the stated commitment),
//! against the three collections pinned in this build or a collection audited from the
//! Zecboat Registry. Nothing is fetched from zecboat.com.
//!
//! Until 2026-10-09 this module also carried the pre-v1 path (ed25519 keys, a disclosure
//! opening the issuance output) for the two collections minted before identity v1. Nobody
//! holds a unit of those, 0.7.1 is not built for them, and keeping them cost a second genesis
//! path that the send planner could not bind offline (gate third pass, Findings 1 and 2).
//! Their units now read as a collection this wallet does not know.
//!
//! **Check 2 (freshness) is absent and the badge must not imply otherwise.** Without a
//! generation log a rolled-back manifest is undetectable.

use anyhow::Result;
use serde::Serialize;

/// The pinned keys, for the About panel.
///
/// Published deliberately: the badge claims to verify "against a key pinned in this wallet",
/// and a claim a user cannot inspect is a claim they have to take on trust. These are public
/// keys — showing them costs nothing and makes the badge checkable.
pub fn pinned_issuers() -> Vec<serde_json::Value> {
    crate::issuance_v1::PINNED_V1
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
    /// No manifest this wallet holds says anything about this asset: not a verdict. Said in
    /// grey, apart from `NotListed`, which is evidence (gate fourth pass, L-3).
    Unknown { detail: String },
    /// The manifest was fetched and its signature did not verify under any pinned key.
    SignatureFailed { detail: String },
    /// We could not complete the check. **This is not a verdict about the asset.**
    CouldNotCheck { detail: String },
}

/// The badge for one asset: identity v1 against the pinned collections and the audited
/// registry collections. An asset none of them lists is unknown, which is not a verdict; the
/// forgery answer (`NotListed`) is for an asset whose own collection's verified manifest does
/// not list it.
pub async fn verify_issuance(asset_id: String) -> Result<BadgeState> {
    if asset_id.len() != 64 || !asset_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(BadgeState::CouldNotCheck {
            detail: "not a valid ZMAP asset id (expected 64 hex characters)".into(),
        });
    }
    if let Some(state) = crate::issuance_v1::verify(&asset_id).await {
        return Ok(state);
    }
    // A memo naming a key this wallet knows was answered above, as the forgery answer, before
    // any "registered but not checked" (gate fifth pass, Finding 1; sixth pass, Finding 1).
    let known = crate::issuance_v1::PINNED_V1.iter().map(|(l, _, _)| *l).collect::<Vec<_>>().join(", ");
    Ok(BadgeState::Unknown {
        detail: format!("a collection this wallet does not know: not listed in any manifest it holds ({known}) nor in a collection audited from the Zecboat Registry"),
    })
}
