//! Knotline v1 and the canonical lading, pinned under the wallet's own dependency set
//! (audit 2026-10-08, WAKE F-10).
//!
//! `zmap_wake::knotline::tests::v1_format_is_frozen` pins the same values, but it is
//! compiled with zmap-wake's lock file. A wallet ships with zecboat-core's. The canonical
//! lading is serde_json output, so the serialiser that matters is the one resolved here:
//! if it ever writes different bytes, a recipient rebuilding a lading from knots computes a
//! different hash and shows a sound unit as unproven. Same expected values as the library
//! test; never edit them, add a version.

use base64::Engine;
use sha2::{Digest, Sha256};
use zmap_wake::knotline::{knot_keys, pack_knot, Knot};
use zmap_wake::lading::{Lading, ProofEntry};

fn hx(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

fn hop() -> ProofEntry {
    ProofEntry {
        kind: "wake-v1".to_string(),
        circuit: "hop".to_string(),
        instance: ["01".repeat(32), "02".repeat(32), "03".repeat(32)],
        anchor_height: 3_508_581,
        proof: base64::engine::general_purpose::STANDARD.encode(vec![7u8; 4960]),
    }
}

#[test]
fn canonical_lading_bytes_are_frozen_under_the_wallets_serde_json() {
    let h = hop();
    let mut l = Lading::new(&"ab".repeat(32), 3);
    l.hops.push(ProofEntry { circuit: "genesis".to_string(), ..h.clone() });
    l.hops.push(h);
    let bytes = l.to_bytes();
    assert_eq!(
        (bytes.len(), hx(&Sha256::digest(&bytes)).as_str()),
        (14132, "66c4b7ab20cf0525b062b8ae9c80828f5e818c54c1d98c62af2e82e4fe3c9472")
    );
    assert_eq!(Lading::parse(&bytes).unwrap().to_bytes(), bytes, "parse then serialise is the identity");
}

#[test]
fn knot_address_and_layouts_are_frozen() {
    let (_, addr) = knot_keys(&[0x11; 32]);
    assert_eq!(
        hx(&addr.to_raw_address_bytes()),
        "35c679162ac1cf05fe3a21d14b48a0f6617bd35ed509e6b685df34acc6edd70fb9f26b9a8e3eff4ada4abf"
    );
    let h = hop();
    let later = pack_knot(&Knot { prev: Some(([0x22; 32], [0x33; 32])), genesis: None, hops: vec![h.clone()] }).unwrap();
    let first = pack_knot(&Knot {
        prev: None,
        genesis: Some(("ab".repeat(32), 3)),
        hops: vec![ProofEntry { circuit: "genesis".to_string(), ..h }],
    })
    .unwrap();
    assert_eq!((later.len(), hx(&Sha256::digest(&later)).as_str()), (5131, "1e949f7508ddfaba4f351b07bf4a48c2aa86bcdbc3b61ac03f88670c65dc81eb"));
    assert_eq!((first.len(), hx(&Sha256::digest(&first)).as_str()), (5103, "dcf4b5e68906d40b45493134c3c00cf8c14c93cd9c69402de0a3c061463bf3fd"));
}
