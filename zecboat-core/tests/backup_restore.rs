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

/// The stored seed must belong to one of this database's accounts.
///
/// `ext_zecboat_keystore_mnemonics.hd_seed_fingerprint` is `BLOB NOT NULL UNIQUE` and exists
/// to say WHICH seed the stored mnemonic belongs to. All three writers put `vec![0u8; 32]`
/// there, so it said the same thing about every wallet and nothing compared it to anything.
/// A database whose mnemonic and account disagree showed one wallet's balance and would sign
/// with another's key — surfacing at the first spend, not at unlock.
///
/// The check compares against `accounts.hd_seed_fingerprint`, which the backend computes
/// independently, rather than against our own column: a value we wrote ourselves could only
/// prove we are self-consistent.
///
/// **Constructing a real mismatch takes care.** The obvious fixture — A's database beside
/// B's identity — fails at `NoMatchingKeys` before the fingerprint is ever consulted, so it
/// passes while proving nothing. That version was written first and discarded. This one goes
/// through `import_wallet`, which leaves the mnemonic decryptable by the identity in place,
/// and then removes the account it belongs to.
#[tokio::test]
async fn a_stored_seed_that_matches_no_account_is_refused() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("fingerprint");

    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet A");
    zecboat_core::unlock_wallet("pw".into(), false).await.expect("unlock");

    // A published vector, so nothing here is a seed that has held funds.
    const OTHER: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
    zecboat_core::import_wallet(OTHER, Some(BIRTHDAY)).await.expect("import");

    // Import ADDS an account, so the wallet now holds two and the stored mnemonic belongs
    // to one of them. This must still work — an earlier draft compared against the first
    // account only and would have refused every wallet that had ever imported.
    zecboat_core::export_keys()
        .await
        .expect("a legitimately imported wallet must still open its own seed");

    // Make the account's fingerprint the one a DIFFERENT seed would produce. That is
    // exactly the state a mismatched restore leaves: an accounts row derived from one seed
    // beside a stored mnemonic from another.
    //
    // Deleting the account instead does NOT work, and the attempt is worth recording:
    // import_wallet REPLACES the account rather than adding one, so the wallet holds a
    // single row, and removing it leaves nothing to compare against — which the check
    // correctly treats as "no opinion" rather than as a mismatch.
    {
        let conn = rusqlite::Connection::open(sb.db()).unwrap();
        let n = conn
            .execute(
                "UPDATE accounts SET hd_seed_fingerprint = ?1",
                rusqlite::params![vec![0xABu8; 32]],
            )
            .unwrap();
        assert_eq!(n, 1, "expected exactly one account to re-point");
    }

    let msg = format!(
        "{:#}",
        zecboat_core::export_keys().await.expect_err(
            "a stored seed belonging to no account was accepted; the wallet would sign with \
             the wrong key and say nothing"
        )
    );
    assert!(
        msg.contains("does not belong to any of its accounts"),
        "refused, but for the wrong reason — the fingerprint check did not run: {msg}"
    );
}

/// Import must not silently succeed without storing the seed phrase.
///
/// `if let Ok(conn) = Connection::open(...)` swallowed a failed open: the block that writes
/// the mnemonic was skipped, the account below was still created, and `Ok(())` returned.
/// The result was a wallet holding an account and NO stored seed — unable to ever export
/// its own phrase — reported to the user as a successful import.
///
/// Also pins the birthday, which was hardcoded to 3,364,599 (Aug 2025) with a comment
/// admitting any older seed would under-report. That is the literal "zero balance, funds
/// are really there" outcome, by design. It is now a parameter defaulting to Sapling
/// activation.
#[tokio::test]
async fn import_defaults_to_sapling_activation_and_stores_the_seed() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("import-bday");

    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet");
    zecboat_core::unlock_wallet("pw".into(), false).await.expect("unlock");

    const OTHER: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
    // None = "I don't know", which must mean the safest height, not a recent one.
    zecboat_core::import_wallet(OTHER, None).await.expect("import");

    let conn = rusqlite::Connection::open(sb.db()).unwrap();

    let bday: i64 = conn
        .query_row("SELECT birthday_height FROM accounts LIMIT 1", [], |r| r.get(0))
        .unwrap();
    // 419,201, not 419,200: ChainState::empty(H) puts the chain state AT H, so the account
    // is born at the first block it must actually scan. The property being asserted is that
    // "I don't know" means Sapling activation, not a recent height.
    assert!(
        (419_200..=419_201).contains(&bday),
        "an import with no stated birthday must scan from Sapling activation, got {bday}; \
         the old hardcoded 3,364,599 silently hid every note older than August 2025"
    );

    // The seed must actually be there. The swallowed open produced a wallet where it was not.
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM ext_zecboat_keystore_mnemonics", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1, "import stored no seed phrase — the wallet could never export it");

    // And it must be the phrase that was imported, not the one that was replaced.
    let exported = zecboat_core::export_keys().await.expect("export");
    assert!(
        exported.contains("zoo zoo"),
        "the stored phrase is not the imported one: {exported}"
    );
}

/// A backup taken mid-session must contain writes still sitting in the write-ahead log.
///
/// The wallet runs in WAL mode and `WalletPool` holds connections open, so SQLite never
/// checkpoints on close. `backup_wallet` did a bare `fs::copy` of `wallet.db`, which omits
/// every committed transaction still in the log — a backup that looks fine and is missing
/// the most recent activity, which is exactly the activity worth backing up.
///
/// `preserve_replaced_file` states the hazard twice in the same file. The reasoning was
/// applied to restore and not to backup, in the same session.
///
/// Neither other backup test catches this: both run against a wallet whose log is empty.
#[tokio::test]
async fn a_backup_contains_writes_still_in_the_write_ahead_log() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("wal");

    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet");

    // A connection that stays open, with a committed write small enough that SQLite's
    // automatic checkpoint (1000 pages) never fires. This is what a running wallet looks
    // like: work committed, log not yet folded in.
    let held = rusqlite::Connection::open(sb.db()).unwrap();
    held.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    held.execute("CREATE TABLE IF NOT EXISTS zz_wal_marker (note TEXT)", []).unwrap();
    held.execute("INSERT INTO zz_wal_marker (note) VALUES ('committed before the backup')", [])
        .unwrap();

    zecboat_core::backup_wallet().await.expect("backup");

    let name = zecboat_core::list_backups().await.unwrap().into_iter().next().expect("a backup");
    let copy = rusqlite::Connection::open_with_flags(
        sb.backups().join(name),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open the backup");

    let found: i64 = copy
        .query_row("SELECT COUNT(*) FROM zz_wal_marker", [], |r| r.get(0))
        .unwrap_or(0);
    assert_eq!(
        found, 1,
        "the backup is missing a transaction that was committed before it was taken — the \
         write-ahead log was not folded in"
    );

    drop(held);
}

// ─── YubiKey stub: the third file in the pair ────────────────────────────────

/// `paths::yubikey_stub_path` says the stub "is as much a pair with identity_path as
/// that file is with wallet_db_path". Unlock decides its MODE by whether the stub exists:
/// with it, the identity is opened on the card; without it, with the password. So a
/// backup of a YubiKey wallet restored without its stub is refused by the wrong branch,
/// with a message about a damaged identity file, to a user holding the right key and PIN.
#[tokio::test]
async fn backup_carries_the_yubikey_stub_and_restore_puts_it_back() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("stub-carried");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet should initialise");
    // A stub as the plugin writes it: one identity line. Its contents are opaque here;
    // only its presence and byte-exact survival matter.
    let stub = sb.data().join("yubikey-identity.txt");
    let stub_bytes = b"# created by age-plugin-yubikey (test)\nAGE-PLUGIN-YUBIKEY-1TESTSTUB\n";
    std::fs::write(&stub, stub_bytes).unwrap();

    zecboat_core::backup_wallet().await.expect("backup should succeed");

    let names: Vec<String> = std::fs::read_dir(sb.backups())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let db_name = names.iter().find(|n| n.ends_with(".db")).expect("a .db backup").clone();
    let stub_backup = names.iter().find(|n| n.ends_with(".yubikey.txt"));
    assert!(
        stub_backup.is_some(),
        "backup of a YubiKey-mode wallet carried no stub — restore would open the identity \
         in password mode and refuse: {names:?}"
    );
    assert_eq!(
        std::fs::read(sb.backups().join(stub_backup.unwrap())).unwrap(),
        stub_bytes,
        "the backed-up stub is not byte-identical"
    );

    // Lose the stub (recover_wallet_from_seed removes it deliberately), then restore.
    std::fs::remove_file(&stub).unwrap();
    zecboat_core::restore_backup(db_name).await.expect("restore should succeed");
    assert_eq!(
        std::fs::read(&stub).ok().as_deref(),
        Some(&stub_bytes[..]),
        "restore did not put the YubiKey stub back beside the identity it unlocks"
    );
}

/// The other direction: a password-mode backup restored onto a machine that currently
/// runs a YubiKey wallet must not leave the old stub behind, or unlock tries the card on
/// a passphrase-encrypted identity. The stale stub is moved aside, not deleted.
#[tokio::test]
async fn restoring_a_password_backup_removes_a_stale_yubikey_stub() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("stub-stale");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet should initialise");
    zecboat_core::backup_wallet().await.expect("backup should succeed");
    let db_name = std::fs::read_dir(sb.backups())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.ends_with(".db"))
        .expect("a .db backup");

    let stub = sb.data().join("yubikey-identity.txt");
    std::fs::write(&stub, b"AGE-PLUGIN-YUBIKEY-1STALE\n").unwrap();

    zecboat_core::restore_backup(db_name).await.expect("restore should succeed");
    assert!(
        !stub.exists(),
        "a stale YubiKey stub survived a password-mode restore; unlock would try the card"
    );
    assert!(
        sb.replaced_copies().iter().any(|n| n.starts_with("yubikey-identity.txt.replaced-")),
        "the stale stub was deleted rather than moved aside: {:?}",
        sb.replaced_copies()
    );
}

/// `restore_backup` joins the caller's string onto the backup directory. The UI only ever
/// passes a name from `list_backups`, but the command accepts anything, and a name with a
/// path in it would install an arbitrary file as the wallet database.
#[tokio::test]
async fn restore_refuses_a_name_that_is_not_a_bare_backup_filename() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let sb = Sandbox::new("restore-name");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY))
        .await
        .expect("wallet should initialise");
    let before = std::fs::read(sb.db()).unwrap();

    for bad in ["../wallet.db", "sub/wallet_backup_1.db", "/etc/passwd", "wallet_backup_1.identity.txt", ""] {
        let err = zecboat_core::restore_backup(bad.to_string())
            .await
            .expect_err(&format!("{bad:?} must be refused"));
        assert!(
            err.to_string().contains("not a backup name"),
            "{bad:?}: refused for the wrong reason: {err}"
        );
    }
    assert_eq!(std::fs::read(sb.db()).unwrap(), before, "a refused restore touched the wallet");
    assert!(sb.replaced_copies().is_empty(), "a refused restore moved files aside");
}
