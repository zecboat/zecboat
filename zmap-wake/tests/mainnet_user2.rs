//! Chapter 7: a real hop on Zcash mainnet, from a COPY of user2's wallet.
//!
//! Ignored by default. Run by hand, never against a live wallet:
//!
//! ```sh
//! WAKE_WALLET_COPY=$WAKE_COPIES_DIR/user2_wallet.db \
//! WAKE_TXID=3ba90bd4a6b90aeeff33e77db530a7a0586803e24b4a09666c1c2e2480ec07f1 \
//! cargo test --test mainnet_user2 -- --ignored --nocapture
//! ```
//!
//! `WAKE_ZEBRAD` defaults to `http://127.0.0.1:8232`.
//!
//! What it establishes, in order:
//!
//! 1. the wallet's stored nullifier for the note received in `WAKE_TXID` is
//!    reproduced byte for byte from the note fields and the viewing key
//!    (chapter 3's last line);
//! 2. that note's ρ equals the nullifier revealed in the same Action of the same
//!    transaction, read from the node (the consensus fact, on this machine);
//! 3. the note's authentication path, rebuilt at the transaction's block from
//!    the wallet's shards, leads to the root the node reports for that block;
//! 4. `WAKE_HOP` proves and verifies with `nf_prev` = that on-chain nullifier.
//!
//! The proof and its instance are written beside the wallet copy as JSON, for
//! chapter 6's lading format and chapter 10's test vector. They are not published.

use std::env;
use std::path::PathBuf;
use std::time::Instant;

use ff::PrimeField;
use zcash_protocol::consensus::Network;
use zmap_wake::circuit::{ANCHOR, LINK, NF};
use zmap_wake::lading::ProofEntry;
use zmap_wake::oracle::{hex, reversed, ZebradOracle};
use zmap_wake::wallet_notes::{received_notes_in_tx, witness_at};
use zmap_wake::wallet_path::open_wallet_copy;
use zmap_wake::{prove_hop, verify_hop};

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

#[test]
#[ignore = "needs a wallet COPY and a synced zebrad; see the module doc"]
fn real_hop_from_user2_wallet_copy() {
    let wallet_path = PathBuf::from(
        env::var("WAKE_WALLET_COPY").expect("set WAKE_WALLET_COPY to a wallet.db COPY"),
    );
    let txid_hex = env_or(
        "WAKE_TXID",
        "3ba90bd4a6b90aeeff33e77db530a7a0586803e24b4a09666c1c2e2480ec07f1",
    );
    let node = ZebradOracle::new(env_or("WAKE_ZEBRAD", "http://127.0.0.1:8232"));

    // ---- the wallet copy -------------------------------------------------------------
    let txid_display = zmap_wake::oracle::decode_hex_32(&txid_hex).unwrap();
    let notes = received_notes_in_tx(&wallet_path, Network::MainNetwork, &txid_display)
        .expect("received notes");
    assert!(!notes.is_empty(), "no Ironwood notes received in that transaction");
    let mined_height = notes[0].mined_height;
    println!("tx {txid_hex} mined at {mined_height}");
    for n in &notes {
        println!(
            "note {} action {} value {} change {} version {:?} position {:?}",
            n.row_id, n.action_index, n.value, n.is_change, n.note.version(), n.position
        );
    }
    // The carrier: 10,000 zat and not change. Fall back to the first non-change note.
    let row = notes
        .iter()
        .find(|n| n.value == 10_000 && !n.is_change)
        .or_else(|| notes.iter().find(|n| !n.is_change))
        .expect("no non-change note");
    let note = row.note;
    let fvk = row.fvk.clone();
    let rho = note.rho();

    // 1. The wallet's stored nullifier, byte for byte, from the library and from Wake's own derivation.
    let stored_nf: [u8; 32] = row
        .stored_nf
        .expect("note has no stored nf; is the wallet synced past it?");
    assert_eq!(note.nullifier(&fvk).to_bytes(), stored_nf, "library nf != stored nf");
    println!("1. stored nf reproduced: {}", hex(&stored_nf));

    // 2. rho == the nullifier in the same Action, from the node.
    let (node_height, actions) = node
        .ironwood_actions(&txid_hex)
        .expect("getrawtransaction")
        .expect("transaction is mined");
    assert_eq!(node_height, mined_height, "wallet and node disagree on the height");
    let act = &actions[row.action_index as usize];
    let rho_bytes = rho.to_bytes();
    let order = if act.nullifier == rho_bytes {
        "as-is"
    } else if reversed(act.nullifier) == rho_bytes {
        "reversed"
    } else {
        panic!(
            "rho {} is not the Action {} nullifier {} in either byte order",
            hex(&rho_bytes),
            row.action_index,
            hex(&act.nullifier)
        );
    };
    let nf_prev = rho_bytes;
    println!(
        "2. rho == nullifier of Action {} (node encodes it {order}): {}",
        row.action_index,
        hex(&nf_prev)
    );
    let cmx_bytes = orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes();
    assert!(
        act.cmx == cmx_bytes || reversed(act.cmx) == cmx_bytes,
        "the note's cmx is not the Action's cmx"
    );

    // 3. The path at the transaction's block, from the wallet's shards, reaches the node's root.
    let db = open_wallet_copy(&wallet_path, Network::MainNetwork).expect("open wallet copy");
    let ts = node
        .ironwood_tree_state(mined_height)
        .expect("z_gettreestate");
    let witness = witness_at(&db, row, &ts).expect("witness at the mined height");
    let anchor = witness.anchor().expect("anchor");
    assert_eq!(anchor, ts.root, "witness anchor != node root at {mined_height}");
    assert_eq!(witness.nullifier().unwrap().to_repr(), stored_nf, "Wake nf != stored nf");
    println!("3. path at {mined_height} reaches the node's root {}", hex(&anchor.to_bytes()));
    let cmx_order = if act.cmx == cmx_bytes { "as-is" } else { "reversed" };
    println!("   node encodes cmx {cmx_order}");

    // 4. Prove and verify the hop.
    let t = Instant::now();
    zmap_wake::keys::warm();
    println!("   keys ready in {:.1?}", t.elapsed());
    let t = Instant::now();
    let proof = prove_hop(&witness).expect("prove");
    let prove_time = t.elapsed();
    let t = Instant::now();
    verify_hop(&proof.proof, &proof.instance).expect("verify");
    let verify_time = t.elapsed();
    assert_eq!(proof.instance[LINK].to_repr(), nf_prev);
    assert_eq!(proof.instance[NF].to_repr(), stored_nf);
    assert_eq!(proof.instance[ANCHOR].to_repr(), anchor.to_bytes());
    println!(
        "4. WAKE_HOP proved in {prove_time:.2?}, verified in {verify_time:.2?}, {} bytes",
        proof.proof.len()
    );

    // Tip depth, for W2.
    let tip = node.tip_height().unwrap_or(0);
    println!("   anchor depth below tip: {}", tip.saturating_sub(mined_height));

    // Record beside the wallet copy as a lading entry (chapter 6 format, with the
    // anchor height the oracle needs). Not a full lading: no genesis proof yet. Not published.
    let entry = ProofEntry::from_proof(&proof, mined_height);
    let out = serde_json::json!({
        "note": "one WAKE_HOP for user2's note; wallet copies are not published",
        "txid": txid_hex,
        "action_index": row.action_index,
        "entry": entry,
        "prove_secs": prove_time.as_secs_f64(),
        "verify_secs": verify_time.as_secs_f64(),
    });
    let out_path = wallet_path.with_file_name("user2_hop_proof.json");
    std::fs::write(&out_path, serde_json::to_string_pretty(&out).unwrap()).expect("write proof");
    println!("   written {}", out_path.display());
    // And the entry round-trips through the lading decoder.
    assert_eq!(entry.to_proof().unwrap(), proof);
}
