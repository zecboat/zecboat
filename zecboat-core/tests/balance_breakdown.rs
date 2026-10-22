//! A5 — the balance gap is itemised, not unexplained.
//!
//! A real wallet showed one number on the card and a smaller one available to send, with
//! nothing between them saying where the rest was. Every zatoshi the wallet knows about
//! belongs in exactly one named bucket, and the card names them.
//!
//! SAFETY: every wallet path is `$HOME/.AppVault/data/...`; tests point HOME at a
//! throwaway directory. The diagnostic below opens a database COPY named by an env var,
//! read-only, and prints; it never writes.

use std::path::PathBuf;
use std::sync::Mutex;

const BIRTHDAY: u32 = 3_400_000;
const ORPHAN_ZAT: i64 = 4_985_000;

static ENV: Mutex<()> = Mutex::new(());

/// A throwaway HOME (same shape as tests/key_derivation.rs).
struct Sandbox { home: PathBuf, real_home: Option<String> }
impl Sandbox {
    fn new(tag: &str) -> Self {
        let real_home = std::env::var("HOME").ok();
        let home = std::env::temp_dir().join(format!("zb-balance-{}-{}", std::process::id(), tag));
        if let Some(rh) = &real_home {
            assert!(!rh.is_empty() && !home.starts_with(rh), "scratch HOME must not be under the real HOME");
        }
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        *zecboat_core::rpc::PROVIDER_URL.lock().unwrap() = "http://127.0.0.1:1".to_string();
        Sandbox { home, real_home }
    }
    fn wallet_db(&self) -> PathBuf { self.home.join(".AppVault/data/wallet.db") }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        match &self.real_home { Some(h) => std::env::set_var("HOME", h), None => std::env::remove_var("HOME") }
        *zecboat_core::rpc::WALLET_PASSWORD.lock().unwrap() = None;
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// A fresh wallet holding exactly one note: a received Orchard note with NO commitment
/// tree position — the shape the pre-Ironwood → Ironwood migration left in a real wallet
/// (a duplicate record of an Ironwood note, filed under Orchard, that no scan can ever
/// place in the tree). Unspent by every table, so it is "money" to a naive sum, and
/// unspendable to note selection, which requires a position to build a witness.
async fn wallet_with_one_unpositioned_note(tag: &str) -> Sandbox {
    let sb = Sandbox::new(tag);
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY)).await.expect("create");
    let conn = rusqlite::Connection::open(sb.wallet_db()).unwrap();
    conn.execute(
        "INSERT INTO transactions (txid, min_observed_height) VALUES (?1, ?2)",
        rusqlite::params![vec![0x5au8; 32], BIRTHDAY],
    ).unwrap();
    let tx_id = conn.last_insert_rowid();
    let account_id: i64 = conn.query_row("SELECT id FROM accounts LIMIT 1", [], |r| r.get(0)).unwrap();
    conn.execute(
        "INSERT INTO orchard_received_notes
           (transaction_id, action_index, account_id, diversifier, value, rho, rseed, nf, is_change,
            memo, commitment_tree_position, recipient_key_scope, witness_stabilized, note_version)
         VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6, NULL, 0, NULL, NULL, 0, 0, 2)",
        rusqlite::params![tx_id, account_id, vec![1u8; 11], ORPHAN_ZAT, vec![2u8; 32], vec![3u8; 32]],
    ).unwrap();
    sb
}

/// 0.7.2 (seen on a mainnet wallet, 2026-10-14): the duplicate record above, but in a transaction that IS mined,
/// at a height the wallet has already scanned, and with no nullifier: the scanner never found
/// this note, so no rescan will place it. It must leave every bucket, not move to another one.
async fn wallet_with_one_phantom_row_in_a_scanned_block(tag: &str) -> Sandbox {
    let sb = Sandbox::new(tag);
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY)).await.expect("create");
    let conn = rusqlite::Connection::open(sb.wallet_db()).unwrap();
    let height = BIRTHDAY + 10;
    conn.execute(
        // sapling_tree is the legacy serialized CommitmentTree the summary still reads:
        // an empty one is left None, right None, no parents = three zero bytes.
        "INSERT INTO blocks (height, hash, time, sapling_tree, sapling_commitment_tree_size, orchard_commitment_tree_size, ironwood_commitment_tree_size)
         VALUES (?1, ?2, 0, ?3, 0, 0, 0)",
        rusqlite::params![height, vec![0x11u8; 32], vec![0u8; 3]],
    ).unwrap();
    conn.execute(
        "INSERT INTO transactions (txid, min_observed_height, block, mined_height) VALUES (?1, ?2, ?3, ?3)",
        rusqlite::params![vec![0x5bu8; 32], BIRTHDAY, height],
    ).unwrap();
    let tx_id = conn.last_insert_rowid();
    let account_id: i64 = conn.query_row("SELECT id FROM accounts LIMIT 1", [], |r| r.get(0)).unwrap();
    conn.execute(
        "INSERT INTO orchard_received_notes
           (transaction_id, action_index, account_id, diversifier, value, rho, rseed, nf, is_change,
            memo, commitment_tree_position, recipient_key_scope, witness_stabilized, note_version)
         VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, NULL, 1, NULL, NULL, 1, 0, 2)",
        rusqlite::params![tx_id, account_id, vec![1u8; 11], ORPHAN_ZAT, vec![2u8; 32], vec![3u8; 32]],
    ).unwrap();
    sb
}

#[tokio::test]
async fn a_phantom_row_in_a_scanned_block_is_in_no_bucket_and_asks_for_no_rescan() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let _sb = wallet_with_one_phantom_row_in_a_scanned_block("phantom").await;
    let b = zecboat_core::get_balance_breakdown().await.expect("breakdown");
    assert_eq!(b.unpositioned_zat, 0, "a row no scan can place must not ask for a rescan");
    assert_eq!(b.unpositioned_notes, 0);
    assert_eq!(b.unpositioned_from_height, None);
    assert_eq!(b.awaiting_scan_zat, 0, "and it must not reappear as awaiting scan");
    assert_eq!(b.spendable_zat, 0);
    assert_eq!(
        b.spendable_zat + b.locked_zat + b.pending_change_zat + b.awaiting_scan_zat + b.unpositioned_zat + b.uneconomic_zat,
        b.shielded_total_zat,
        "the buckets must still add up to the total"
    );
    assert_eq!(b.shielded_total_zat, 0, "the phantom's value is not in the total either");
}

/// The send screen's "available" figure comes from fee_readiness, which summed every
/// unspent output. A note with no tree position cannot be selected for any transaction,
/// so counting it tells the user they can pay a fee they cannot pay.
#[tokio::test]
async fn fee_readiness_does_not_count_a_note_with_no_tree_position() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let _sb = wallet_with_one_unpositioned_note("fee").await;
    let r = zecboat_core::fee_readiness().await.expect("fee_readiness");
    let spendable = r["spendable_zat"].as_u64().expect("spendable_zat");
    assert_eq!(
        spendable, 0,
        "fee_readiness counted {spendable} zat that note selection can never spend (no tree position)"
    );
    assert_eq!(r["can_pay_fee"].as_bool(), Some(false));
}

/// Print what the backend's summary says about an existing wallet database, per pool and
/// per bucket. For diagnosing a live gap: copy the wallet.db somewhere, then
///
///   ZECBOAT_DIAG_DB=/path/to/copy/wallet.db cargo test --test balance_breakdown print_summary -- --ignored --nocapture
///
/// Ignored because it needs a database to look at; it asserts nothing.
#[test]
#[ignore]
fn print_summary_for_db_in_env() {
    use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
    use zcash_client_backend::data_api::WalletRead;
    use zcash_client_sqlite::WalletDb;
    use zcash_client_sqlite::util::SystemClock;
    use zcash_protocol::consensus::MainNetwork;
    use zmap_wake::rng::OsRng;

    let Ok(db) = std::env::var("ZECBOAT_DIAG_DB") else {
        eprintln!("ZECBOAT_DIAG_DB not set; nothing to print");
        return;
    };
    let db = PathBuf::from(db);
    let wallet_db = WalletDb::for_path(&db, MainNetwork, SystemClock, OsRng).expect("open");
    let summary = wallet_db
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .expect("summary")
        .expect("wallet has a summary");
    eprintln!("chain tip {:?}, fully scanned {:?}", summary.chain_tip_height(), summary.fully_scanned_height());
    for (uuid, b) in summary.account_balances() {
        eprintln!("account {uuid:?}");
        for (name, p) in [("sapling", b.sapling_balance()), ("orchard", b.orchard_balance()), ("ironwood", b.ironwood_balance())] {
            eprintln!(
                "  {name:9} spendable={:>10} locked={:>8} pending_change={:>8} pending_spendability={:>10} uneconomic={:>6} total={:>10}",
                u64::from(p.spendable_value()), u64::from(p.locked_value()), u64::from(p.change_pending_confirmation()),
                u64::from(p.value_pending_spendability()), u64::from(p.uneconomic_value()), u64::from(p.total())
            );
        }
        eprintln!("  unshielded={}  account total={}", u64::from(b.unshielded_balance().total()), u64::from(b.total()));
    }
}

/// The card's headline excludes the note, and the breakdown names it — in the bucket that
/// says "rescan", not the backend's "pending spendability", which reads as "wait".
#[tokio::test]
async fn an_unpositioned_note_is_named_as_needing_a_rescan_and_kept_out_of_spendable() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let _sb = wallet_with_one_unpositioned_note("breakdown").await;
    let b = zecboat_core::get_balance_breakdown().await.expect("breakdown");
    assert_eq!(b.spendable_zat, 0, "an unpositioned note must never be spendable");
    assert_eq!(b.unpositioned_zat, ORPHAN_ZAT as u64);
    assert_eq!(b.unpositioned_notes, 1);
    assert_eq!(b.awaiting_scan_zat, 0, "a note no scan can place must not be filed under 'awaiting scan'");
    assert_eq!(
        b.spendable_zat + b.locked_zat + b.pending_change_zat + b.awaiting_scan_zat + b.unpositioned_zat + b.uneconomic_zat,
        b.shielded_total_zat,
        "every zatoshi in exactly one bucket"
    );
    let headline = zecboat_core::get_balance().await.expect("get_balance");
    assert_eq!(headline, 0.0, "the card's number must be the spendable bucket");
}

/// A wallet with nothing in it reports nothing in every bucket — the rows on the card are
/// hidden by the UI when zero, so the backend must not invent a bucket for an empty wallet.
#[tokio::test]
async fn an_empty_wallet_has_nothing_in_any_bucket() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let _sb = Sandbox::new("empty");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY)).await.expect("create");
    let b = zecboat_core::get_balance_breakdown().await.expect("breakdown");
    assert_eq!((b.spendable_zat, b.locked_zat, b.pending_change_zat, b.awaiting_scan_zat, b.unpositioned_zat, b.uneconomic_zat, b.transparent_zat, b.shielded_total_zat), (0, 0, 0, 0, 0, 0, 0, 0));
    assert_eq!(b.unpositioned_from_height, None);
}
