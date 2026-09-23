//! Backup and restore: the two operations a user reaches for when something has
//! already gone wrong.
//!
//! Both were defective in ways that only show up at the worst moment, which is why they
//! are tested rather than eyeballed:
//!
//! - `backup_wallet` copied `wallet.db` alone. The seed inside it is encrypted to an
//!   X25519 key that lives only in `encryption-identity.txt`, and that file is **rotated**
//!   by `initialize_new_wallet` and `recover_wallet_from_seed`. So the backup could
//!   restore a wallet that displays a balance and cannot spend it.
//!
//! - `restore_backup` was a bare `std::fs::copy` onto the live database, with no
//!   `preserve_replaced_file`. It destroyed the current wallet with no copy kept — from a
//!   button labelled "restore".
//!
//! Neither failure produces an error at the time. Both surface later, as "my money is
//! gone", which is the same shape as the derivation bugs `key_derivation.rs` covers.

use std::path::PathBuf;
use std::sync::Mutex;

/// `HOME` is process-global and cargo runs tests on parallel threads. Every test that
/// touches it holds this. Same rule as `key_derivation.rs`.
static ENV: Mutex<()> = Mutex::new(());

/// Explicit, so `initialize_new_wallet` never asks a node for the chain tip.
const BIRTHDAY: u32 = 3_400_000;

/// A throwaway `HOME`, restored on drop. Refuses to run if the scratch directory is
/// anywhere under the real home: every wallet path derives from `HOME`, so this
/// assertion is the only thing standing between the test and a real wallet.
struct Sandbox {
    home: PathBuf,
    real_home: Option<String>,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let real_home = std::env::var("HOME").ok();
        let home =
            std::env::temp_dir().join(format!("zb-backuptest-{}-{}", std::process::id(), tag));
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

    fn data(&self) -> PathBuf {
        self.home.join(".AppVault/data")
    }
    fn db(&self) -> PathBuf {
        self.data().join("wallet.db")
    }
    fn identity(&self) -> PathBuf {
        self.data().join("encryption-identity.txt")
    }
    fn backups(&self) -> PathBuf {
        self.home.join("ZecboatBackups")
    }

    fn replaced_copies(&self) -> Vec<String> {
        std::fs::read_dir(self.data())
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.contains(".replaced-"))
                    .collect()
            })
            .unwrap_or_default()
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

/// A backup must carry BOTH halves.
///
/// `paths::identity_path`'s own doc comment has said so since it was written: "The wallet
/// will not open without this file, so it is always a pair with `wallet_db_path`. Backups
/// that carry one without the other are useless." The code disagreed with the comment.
#[tokio::test]
async fn backup_carries_both_halves_of_the_wallet() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("both-halves");

    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet should initialise");

    zecboat_core::backup_wallet().await.expect("backup should succeed");

    let names: Vec<String> = std::fs::read_dir(sb.backups())
        .expect("backup directory should exist")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();

    let db = names.iter().find(|n| n.ends_with(".db"));
    let id = names.iter().find(|n| n.ends_with(".identity.txt"));

    assert!(db.is_some(), "backup produced no database: {names:?}");
    assert!(
        id.is_some(),
        "backup produced a database with no encryption identity beside it — the half-wallet \
         this test exists to prevent: {names:?}"
    );

    // The identity in the backup must be the one that actually opens that database.
    let backed_up = std::fs::read(sb.backups().join(id.unwrap())).unwrap();
    let live = std::fs::read(sb.identity()).unwrap();
    assert_eq!(backed_up, live, "the backed-up identity is not the live one");
}

/// Without the identity there is nothing worth backing up, and saying so is better than
/// writing a file that will disappoint later.
#[tokio::test]
async fn backup_refuses_when_the_identity_is_missing() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("no-identity");

    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet should initialise");
    std::fs::remove_file(sb.identity()).unwrap();

    let r = zecboat_core::backup_wallet().await;
    assert!(r.is_err(), "backup succeeded with no encryption identity present");

    // And it must not have left a database behind that `list_backups` would advertise.
    let listed = zecboat_core::list_backups().await.unwrap_or_default();
    assert!(
        listed.is_empty(),
        "a refused backup still left something in the list: {listed:?}"
    );
}

/// Restore must not destroy the wallet it replaces.
///
/// The case that motivated this: a wallet created AFTER the backup was taken, whose 24
/// words were never written down. The old code overwrote it with a bare `fs::copy` and
/// the loss was total.
#[tokio::test]
async fn restore_preserves_the_wallet_it_replaces() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("preserve");

    // Wallet A, backed up.
    zecboat_core::initialize_new_wallet("pw-a".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet A");
    zecboat_core::backup_wallet().await.expect("backup A");
    let backup_name = zecboat_core::list_backups()
        .await
        .expect("list")
        .into_iter()
        .next()
        .expect("one backup");
    let a_identity = std::fs::read(sb.identity()).unwrap();

    // Wallet B replaces it. This is the wallet restore is about to overwrite.
    zecboat_core::initialize_new_wallet("pw-b".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet B");
    let b_db = std::fs::read(sb.db()).unwrap();
    let b_identity = std::fs::read(sb.identity()).unwrap();
    assert_ne!(a_identity, b_identity, "the two wallets should differ");

    zecboat_core::restore_backup(backup_name).await.expect("restore");

    // B must still exist somewhere.
    let kept = sb.replaced_copies();
    assert!(
        !kept.is_empty(),
        "restore kept no copy of the wallet it replaced — the data-loss path"
    );
    let kept_db_bytes: Vec<Vec<u8>> = kept
        .iter()
        .map(|n| std::fs::read(sb.data().join(n)).unwrap_or_default())
        .collect();
    assert!(
        kept_db_bytes.iter().any(|b| *b == b_db),
        "the replaced wallet database was not among the preserved copies"
    );

    // And the restored pair must be A's, not a mix of A and B.
    let now_identity = std::fs::read(sb.identity()).unwrap();
    assert_eq!(
        now_identity, a_identity,
        "restored A's database but left B's identity — the mismatch that shows a balance \
         which cannot be spent"
    );
}
