//! A memo someone sent you must be readable.
//!
//! `get_transactions` read its per-output detail `FROM sent_notes` alone — the outputs this
//! wallet CREATED. A received transaction matches zero rows there, so its memo was never
//! shown. **Zecboat could display a memo you sent and never one sent to you**, which is
//! backwards: the memo that matters is the one addressed to you.
//!
//! Measured on `~/user2` 2026-09-23 before the fix: five transactions, five received memos,
//! two with `sent_notes` rows. The wallet held five memos and could display at most two.
//!
//! The gap was half-noticed. The pool label carried the comment *"Receives have no
//! sent_notes rows, so the pool is not knowable from this side"* — right about the symptom,
//! wrong about the conclusion. It is knowable; it is in the other table, and so is the memo.
//!
//! **On the fixture.** These tests insert a `transactions` row and a received-note row
//! directly. That is test scaffolding for a SQL query, not a wallet being told it owns
//! money it does not: no balance is asserted, no key material is invented, and nothing here
//! runs against a real wallet. Scanning a chain inside a unit test is not available, and a
//! test that only re-ran the same SQL string would be testing a copy of the thing under
//! test.

use std::path::PathBuf;
use std::sync::Mutex;

static ENV: Mutex<()> = Mutex::new(());
const BIRTHDAY: u32 = 3_400_000;

/// The real memo captain sent user2, 360 bytes including padding.
const SENT_TO_ME: &str = "https://zecboat.com\nZcash Desktop Wallet Application for debian.";

struct Sandbox {
    home: PathBuf,
    real_home: Option<String>,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let real_home = std::env::var("HOME").ok();
        let home = std::env::temp_dir().join(format!("zb-memotest-{}-{}", std::process::id(), tag));
        if let Some(rh) = &real_home {
            assert!(
                !rh.is_empty() && !home.starts_with(rh),
                "scratch HOME must not be under the real HOME"
            );
        }
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        *zecboat_core::rpc::PROVIDER_URL.lock().unwrap() = "http://127.0.0.1:1".to_string();
        Sandbox { home, real_home }
    }
    fn db(&self) -> PathBuf {
        self.home.join(".AppVault/data/wallet.db")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        match &self.real_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        *zecboat_core::rpc::WALLET_PASSWORD.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// A 512-byte memo, text then NUL padding, as a real one arrives.
fn memo_bytes(text: &str) -> Vec<u8> {
    let mut m = text.as_bytes().to_vec();
    m.resize(512, 0);
    m
}

/// Insert one received Ironwood note carrying `memo` into a transaction we did not send.
/// Returns the txid, display order (big-endian hex).
fn plant_incoming(db: &PathBuf, value: i64, memo: &[u8], height: i64) -> String {
    let conn = rusqlite::Connection::open(db).unwrap();
    let txid_raw: Vec<u8> = (0..32).map(|i| (i * 7 + 3) as u8).collect();

    // `min_observed_height` is NOT NULL with no default — the height at which the wallet
    // first saw this transaction. For a mined one that is the mined height.
    conn.execute(
        // `block` is a foreign key into `blocks`, which a scratch wallet has no rows in.
        // Left NULL: `mined_height` is what the views and the UI actually read.
        "INSERT INTO transactions
           (txid, mined_height, block, tx_index, expiry_height, min_observed_height)
         VALUES (?1, ?2, NULL, 0, ?3, ?2)",
        rusqlite::params![txid_raw, height, height + 40],
    )
    .unwrap();
    let id_tx: i64 = conn
        .query_row("SELECT id_tx FROM transactions WHERE txid = ?1", [&txid_raw], |r| r.get(0))
        .unwrap();
    let account_id: i64 = conn
        .query_row("SELECT id FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();

    conn.execute(
        "INSERT INTO ironwood_received_notes
           (transaction_id, action_index, account_id, diversifier, value, rho, rseed,
            nf, is_change, memo, commitment_tree_position, recipient_key_scope, note_version)
         VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, 1, 0, 2)",
        rusqlite::params![
            id_tx,
            account_id,
            vec![1u8; 11],
            value,
            vec![2u8; 32],
            vec![3u8; 32],
            vec![4u8; 32],
            memo,
        ],
    )
    .unwrap();

    txid_raw.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

/// The failing case: a plain message sent TO this wallet.
#[tokio::test]
async fn a_memo_sent_to_me_is_readable() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("incoming");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet");

    let txid = plant_incoming(&sb.db(), 20_000, &memo_bytes(SENT_TO_ME), 3_492_146);

    let txs = zecboat_core::get_transactions().await.expect("transactions");
    let tx = txs
        .iter()
        .find(|t| t["id"].as_str() == Some(txid.as_str()))
        .unwrap_or_else(|| panic!("the received transaction is not listed at all: {txs:#?}"));

    let memo = tx["memo"].as_str();
    assert!(
        memo.is_some(),
        "no memo on a transaction that carries one — this is the defect: {tx:#?}"
    );
    assert!(
        memo.unwrap().contains("zecboat.com"),
        "memo present but not the one that was sent: {:?}",
        memo
    );

    // The pool was reported as unknowable for receives for the same reason. It is not.
    assert_eq!(
        tx["pool"].as_str(),
        Some("ironwood"),
        "a received note knows its own pool: {tx:#?}"
    );
}

/// An empty memo is 0xF6 by convention and must read as "no memo", not as a stray byte.
#[tokio::test]
async fn an_empty_memo_reads_as_none_not_as_junk() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("nomemo");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet");

    let mut empty = vec![0xF6u8];
    empty.resize(512, 0);
    let txid = plant_incoming(&sb.db(), 50_000, &empty, 3_492_200);

    let txs = zecboat_core::get_transactions().await.expect("transactions");
    let tx = txs.iter().find(|t| t["id"].as_str() == Some(txid.as_str())).expect("listed");
    assert!(
        tx["memo"].is_null(),
        "0xF6 means no memo and must not surface as text: {:?}",
        tx["memo"]
    );
}

/// A received ZMAP carrier must be recognised from the receiving side too — exactly
/// 10,000 zat AND a memo naming an asset. Value alone is an ordinary payment; memo alone
/// is any note with JSON in it.
#[tokio::test]
async fn a_received_carrier_is_recognised_as_an_asset() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("carrier");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet");

    // Exactly 64 hex characters. parse_memo checks the length (zmap.rs:223) and an
    // off-by-one here rejects the memo silently — which is how this test first failed.
    let asset = "60fe2d16fbea1e540c4e7fcf0b5e9e57c4b483ef2699da622118fa4da0000000";
    assert_eq!(asset.len(), 64, "fixture asset_id must be 64 hex characters");
    let memo = format!(
        r#"{{"asset_id":"{asset}","name":"Test Card","collection":"Test"}}"#
    );
    let txid = plant_incoming(
        &sb.db(),
        zecboat_core::zmap::CARRIER_ZAT as i64,
        &memo_bytes(&memo),
        3_492_300,
    );

    let txs = zecboat_core::get_transactions().await.expect("transactions");
    let tx = txs.iter().find(|t| t["id"].as_str() == Some(txid.as_str())).expect("listed");
    let assets = tx["assets"].as_array().expect("assets array");
    assert_eq!(
        assets.len(),
        1,
        "a received 10,000 zat note with an asset memo is a carrier: {tx:#?}"
    );
}
