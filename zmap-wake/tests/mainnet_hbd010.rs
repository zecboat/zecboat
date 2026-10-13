//! Chapter 7: the first complete real chain. Happy Birthday #010 on Zcash mainnet.
//!
//! ```text
//! mint   bed008bf… h3,447,455  Action 10  ->  holder note    (genesis)         nf_0
//! S1     253b97c7… h3,450,761  Action 1   ->  user2 note     rho = nf_0        nf_1
//! S2     929c1846… h3,487,666  Action 1   ->  holder note    rho = nf_1        (the note in hand)
//! ```
//!
//! Both transfers predate §5.5, so each pairing was a coin flip; both landed.
//!
//! Ignored by default. Needs COPIES of the holder's and user2's wallets and a synced zebrad:
//!
//! ```sh
//! WAKE_HOLDER_COPY=$WAKE_COPIES_DIR/holder_wallet.db \
//! WAKE_USER2_COPY=$WAKE_COPIES_DIR/user2_wallet.db \
//! cargo test --test mainnet_hbd010 -- --ignored --nocapture
//! ```
//!
//! What it establishes: the genesis proof is made by the mint output's **first
//! holder** (the first holder's wallet here), not by the issuer; the hop proof by user2; the lading
//! verifies under `verify_chain` against a full node with `MIN_DEPTH`; and every
//! W-check would have named its failure. The lading is written beside the wallet
//! copies and is not published.

use std::env;
use std::path::PathBuf;
use std::time::Instant;

use ff::PrimeField;
use zcash_protocol::consensus::Network;
use zmap_wake::lading::{lading_hash, Lading, ProofEntry};
use zmap_wake::oracle::{decode_hex_32, hex, ChainOracle, OracleTrust, ZebradOracle, MIN_DEPTH};
use zmap_wake::verify::{verify_chain, WakeFailure};
use zmap_wake::wallet_notes::{received_notes_in_tx, spent_in, witness_at};
use zmap_wake::wallet_path::open_wallet_copy;
use zmap_wake::{prove_genesis, prove_hop};

const MINT: &str = "bed008bf1024151746d5c581c0791694504f094b0cf5bf84d3818ad4f9f2ba36";
const MINT_ACTION: u32 = 10;
const S1: &str = "253b97c76f04b58a9f3163eaa3c6d370e52adf2e21a71307cfda73e4a53142bb";
const S1_ACTION: u32 = 1;
const S2: &str = "929c1846ab374e3f68562a63a87e16e9881d1037440f6b11717b8e5ac00c258f";
const S2_ACTION: u32 = 1;

fn env_path(name: &str, default: &str) -> PathBuf {
    PathBuf::from(env::var(name).unwrap_or_else(|_| {
        format!("{}/{default}", env::var("WAKE_COPIES_DIR").unwrap_or_else(|_| ".".into()))
    }))
}

#[test]
#[ignore = "needs wallet COPIES of the holder and user2 and a synced zebrad; see the module doc"]
fn hbd_010_full_chain_verifies_on_mainnet() {
    let holder = env_path("WAKE_HOLDER_COPY", "holder_wallet.db");
    let user2 = env_path("WAKE_USER2_COPY", "user2_wallet.db");
    let node = ZebradOracle::new(
        env::var("WAKE_ZEBRAD").unwrap_or_else(|_| "http://127.0.0.1:8232".into()),
    );
    let net = Network::MainNetwork;

    // ---- the three notes ------------------------------------------------------------
    let g = received_notes_in_tx(&holder, net, &decode_hex_32(MINT).unwrap())
        .expect("holder notes in the mint tx")
        .into_iter()
        .find(|n| n.action_index == MINT_ACTION)
        .expect("the holder has the #010 mint output");
    let u = received_notes_in_tx(&user2, net, &decode_hex_32(S1).unwrap())
        .expect("user2 notes in S1")
        .into_iter()
        .find(|n| n.action_index == S1_ACTION)
        .expect("user2 received #010 in S1");
    let h = received_notes_in_tx(&holder, net, &decode_hex_32(S2).unwrap())
        .expect("holder notes in S2")
        .into_iter()
        .find(|n| n.action_index == S2_ACTION)
        .expect("the holder received #010 back in S2");
    for (label, n) in [("genesis", &g), ("hop 1", &u), ("in hand", &h)] {
        println!(
            "{label}: h {} action {} value {} position {:?}",
            n.mined_height, n.action_index, n.value, n.position
        );
        assert_eq!(n.value, 10_000, "{label} is not a 10,000-zat carrier");
    }

    // The chain, as consensus already recorded it.
    let nf_0 = g.note.nullifier(&g.fvk).to_bytes();
    let nf_1 = u.note.nullifier(&u.fvk).to_bytes();
    assert_eq!(u.note.rho().to_bytes(), nf_0, "user2's rho is not the holder's genesis nf");
    assert_eq!(h.note.rho().to_bytes(), nf_1, "the holder's note-in-hand rho is not user2's nf");
    println!("consensus links hold: rho_1 == nf_0, rho_2 == nf_1");
    let spent = spent_in(&holder, h.row_id).expect("spends");
    println!("note in hand spent in: {:?}", spent.iter().map(|(t, hh)| (hex(t), *hh)).collect::<Vec<_>>());

    // ---- proofs -----------------------------------------------------------------------
    let cap_db = open_wallet_copy(&holder, net).expect("open holder copy");
    let u2_db = open_wallet_copy(&user2, net).expect("open user2 copy");
    zmap_wake::keys::warm();

    let t = Instant::now();
    let ts_g = node.ironwood_tree_state(g.mined_height).expect("tree state at the mint");
    let wg = witness_at(&cap_db, &g, &ts_g).expect("genesis witness (path from the holder's shards)");
    let pg = prove_genesis(&wg).expect("genesis proof");
    println!("genesis proved in {:.2?}", t.elapsed());

    let t = Instant::now();
    let ts_u = node.ironwood_tree_state(u.mined_height).expect("tree state at S1");
    let wu = witness_at(&u2_db, &u, &ts_u).expect("hop witness (path from user2's shards)");
    let pu = prove_hop(&wu).expect("hop proof");
    println!("hop 1 proved in {:.2?}", t.elapsed());
    assert_eq!(pu.instance[1].to_repr(), nf_0);
    assert_eq!(pu.instance[2].to_repr(), nf_1);

    // ---- the lading -------------------------------------------------------------------
    let mut lading = Lading::new(MINT, MINT_ACTION);
    lading.hops.push(ProofEntry::from_proof(&pg, g.mined_height));
    lading.hops.push(ProofEntry::from_proof(&pu, u.mined_height));
    let bytes = lading.to_bytes();
    let hash = lading_hash(&bytes);

    // ---- verify against the full node ------------------------------------------------
    let t = Instant::now();
    let v = verify_chain(&bytes, Some(hash), &h.note.rho(), &node, MIN_DEPTH).expect("chain verifies");
    println!("verify_chain in {:.2?}: {v:?}", t.elapsed());
    assert_eq!(v.hops, 2);
    assert_eq!(v.trust, OracleTrust::FullNode);
    assert_eq!(v.genesis_cmx, g.cmx().to_bytes());
    assert_eq!(v.final_nf, nf_1);
    assert!(v.min_anchor_depth >= MIN_DEPTH);

    // The same lading against the wrong note in hand, and the genesis cmx from the node.
    assert_eq!(
        verify_chain(&bytes, Some(hash), &g.note.rho(), &node, MIN_DEPTH),
        Err(WakeFailure::RhoMismatch)
    );
    let on_chain = node
        .cmx_at(&decode_hex_32(MINT).unwrap(), MINT_ACTION)
        .unwrap()
        .unwrap();
    assert_eq!(on_chain, g.cmx());

    // ---- record, not publish ----------------------------------------------------------
    let out = holder.with_file_name("hbd010_lading.json");
    std::fs::write(&out, &bytes).expect("write lading");
    let rec = serde_json::json!({
        "asset": "Happy Birthday #010",
        "asset_id": "60fe2d16fbea1e540c4e7fcf0b5e9e57c4b483ef2699da622118fa4daed284ef",
        "lading_sha256": hex(&hash),
        "note_in_hand": { "txid": S2, "action_index": S2_ACTION, "rho": hex(&h.note.rho().to_bytes()) },
        "verified": { "hops": v.hops, "min_anchor_depth": v.min_anchor_depth, "trust": format!("{:?}", v.trust) },
    });
    std::fs::write(
        holder.with_file_name("hbd010_lading_record.json"),
        serde_json::to_string_pretty(&rec).unwrap(),
    )
    .unwrap();
    println!("lading written to {} ({} bytes, sha256 {})", out.display(), bytes.len(), hex(&hash));
}
