//! Every lading in `$WAKE_LADINGS_DIR` (real mainnet ladings exported from a wallet copy,
//! never checked in: a lading must not be published) verifies proof-by-proof under this
//! build's pinned keys. Written 2026-10-02 for the NU7 crate bump (halo2 0.3 → 0.4, orchard
//! 0.15.3 → 0.16): a proof made under the old stack must still verify under the new one, or
//! by WAKE-v1 §7.4/§12 this is `wake-v2` and every lading on mainnet is orphaned.
//! Skips (with a message) when the directory is not set, so CI without fixtures stays green.

use base64::Engine;
use zmap_wake::lading::Lading;
use zmap_wake::oracle::decode_hex_32;
use zmap_wake::circuit::Kind;
use zmap_wake::prove::WakeProof;
use zmap_wake::verify::{decode_instance, verify_wake_proof};

#[test]
fn stored_mainnet_ladings_verify_under_this_build() {
    let Some(dir) = std::env::var_os("WAKE_LADINGS_DIR") else {
        eprintln!("WAKE_LADINGS_DIR not set; skipping");
        return;
    };
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .json ladings in {dir:?}");
    let mut proofs = 0;
    for f in &files {
        let bytes = std::fs::read(f).unwrap();
        let lading = Lading::parse(&bytes).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        for (j, entry) in lading.hops.iter().enumerate() {
            assert_eq!(entry.kind, "wake-v1", "{}: hop {j} kind", f.display());
            let kind = match entry.circuit.as_str() {
                "genesis" => Kind::Genesis,
                "hop" => Kind::Hop,
                other => panic!("{}: hop {j} circuit {other}", f.display()),
            };
            let mut rows = [[0u8; 32]; 3];
            for (i, h) in entry.instance.iter().enumerate() {
                rows[i] = decode_hex_32(h).unwrap();
            }
            let instance = decode_instance(&rows).unwrap();
            let proof = base64::engine::general_purpose::STANDARD.decode(&entry.proof).unwrap();
            let p = WakeProof { kind, instance, proof };
            verify_wake_proof(&p).unwrap_or_else(|e| {
                panic!("{}: hop {j} ({}) at anchor_height {} FAILED under this build: {e:?}",
                    f.display(), entry.circuit, entry.anchor_height)
            });
            proofs += 1;
        }
        eprintln!("ok {} ({} proof(s))", f.file_name().unwrap().to_string_lossy(), lading.hops.len());
    }
    eprintln!("{} lading(s), {proofs} proof(s) verified", files.len());
    assert!(proofs > 0);
}
