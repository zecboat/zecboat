//! Does a wallet recovered from its own seed phrase come back as the SAME wallet?
//!
//! Promoted from `examples/recovery_roundtrip.rs` (R7). The example ran by hand, never
//! under `cargo test`, and proved one thing: `initialize_new_wallet` and
//! `recover_wallet_from_seed` agree — two callers of the same derivation. These tests
//! keep that and add the three things it never touched:
//!
//!   * the STORED phrase — what Settings → Export hands back, decrypted from the
//!     ciphertext in `ext_zecboat_keystore_mnemonics`, not the string the wizard
//!     returned from memory;
//!   * `import_wallet` — the third door, which had its own parsing until F1/F6;
//!   * the SPEND path — the key a send actually signs with, from the exact function
//!     the send calls, compared with the key the wallet scans with.
//!
//! The failure this guards against is SILENT. If any door derives a different wallet
//! from the same words it does not error — it succeeds, shows a zero balance, and looks
//! exactly like the funds are gone.
//!
//! SAFETY: every wallet path is `$HOME/.AppVault/data/...`, so each test points HOME at a
//! throwaway directory and refuses to run if that is anywhere under the real one.

use std::path::{Path, PathBuf};
use std::sync::Mutex;


const BIRTHDAY: u32 = 3_400_000; // explicit, so nothing here asks a node for the tip

/// Tests in this file share process-wide state (HOME, the provider URL, the cached
/// password), so they run one at a time.
static ENV: Mutex<()> = Mutex::new(());

/// A throwaway `HOME`. Same shape as the one in `tests/key_derivation.rs` — a third copy,
/// noted rather than hidden; a `tests/common` module is the right home for it when the
/// next test file needs one.
struct Sandbox {
    home: PathBuf,
    real_home: Option<String>,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let real_home = std::env::var("HOME").ok();
        let home = std::env::temp_dir().join(format!("zb-roundtrip-{}-{}", std::process::id(), tag));
        if let Some(rh) = &real_home {
            assert!(!rh.is_empty() && !home.starts_with(rh), "scratch HOME must not be under the real HOME");
        }
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        *zecboat_core::rpc::PROVIDER_URL.lock().unwrap() = "http://127.0.0.1:1".to_string();
        Sandbox { home, real_home }
    }

    fn wallet_db(&self) -> PathBuf {
        self.home.join(".AppVault/data/wallet.db")
    }

    /// Make this sandbox the current HOME again. Tests here hold several wallets at once
    /// and move between them; every entry point reads HOME at call time.
    fn enter(&self) {
        std::env::set_var("HOME", &self.home);
        *zecboat_core::rpc::WALLET_PASSWORD.lock().unwrap() = None;
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

/// What the wallet IS: its account's UFVK and every address it has derived.
fn identity_of(db: &Path) -> (String, Vec<String>) {
    let conn = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open wallet.db");
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1, "expected exactly one account");
    let ufvk: String = conn.query_row("SELECT ufvk FROM accounts", [], |r| r.get(0)).unwrap();
    let mut st = conn.prepare("SELECT address FROM addresses ORDER BY id").unwrap();
    let addrs: Vec<String> = st.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
    assert!(!addrs.is_empty(), "the wallet derived no addresses — inconclusive, not a pass");
    (ufvk, addrs)
}

/// The phrase as Settings → Export shows it: decrypted from the stored ciphertext.
async fn exported_phrase() -> String {
    zecboat_core::export_keys(held_password()).await.expect("export_keys")
}

/// The example, kept: the words the wizard returns restore the same wallet, into a
/// different HOME, under a different password. Two callers of one derivation — a guard,
/// not a proof; the tests below are the ones that reach past it.
#[tokio::test]
async fn the_words_the_wizard_shows_restore_the_same_wallet() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let a = Sandbox::new("wizard");
    let words = zecboat_core::initialize_new_wallet("password-one".into(), false, Some(BIRTHDAY))
        .await
        .expect("create wallet");
    assert_eq!(words.split_whitespace().count(), 24);
    let created = identity_of(&a.wallet_db());

    let b = Sandbox::new("recovered");
    zecboat_core::recover_wallet_from_seed(&words, "password-two".into(), Some(BIRTHDAY))
        .await
        .expect("recover wallet");
    let recovered = identity_of(&b.wallet_db());

    assert_eq!(created, recovered, "the 24 words the wizard shows did not restore the same wallet");
}

/// Past the wizard's return value. The words a user writes down LATER come from
/// Settings → Export: decrypted from the database, under whatever password the wallet
/// has now. Those words must be the wizard's words, and must open the same wallet
/// through BOTH remaining doors.
#[tokio::test]
async fn the_stored_phrase_restores_the_same_wallet_through_every_door() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let a = Sandbox::new("origin");
    let words = zecboat_core::initialize_new_wallet("password-one".into(), false, Some(BIRTHDAY))
        .await
        .expect("create wallet");
    zecboat_core::unlock_wallet("password-one".into(), false).await.expect("unlock");
    let stored = exported_phrase().await;
    assert_eq!(stored, words, "the phrase exported from the database is not the phrase the wizard showed");
    let origin = identity_of(&a.wallet_db());

    // Door 2: recover, from the EXPORTED phrase.
    let b = Sandbox::new("recover-from-export");
    zecboat_core::recover_wallet_from_seed(&stored, "password-two".into(), Some(BIRTHDAY))
        .await
        .expect("recover");
    assert_eq!(identity_of(&b.wallet_db()), origin, "recover_wallet_from_seed opened a different wallet");

    // Door 3: import into an existing, unrelated wallet, from the EXPORTED phrase.
    let c = Sandbox::new("import-from-export");
    zecboat_core::initialize_new_wallet("password-three".into(), false, Some(BIRTHDAY))
        .await
        .expect("a wallet must exist before importing into it");
    zecboat_core::unlock_wallet("password-three".into(), false).await.expect("unlock");
    assert_ne!(identity_of(&c.wallet_db()), origin, "the throwaway wallet must differ before import");
    zecboat_core::import_wallet(&stored, Some(BIRTHDAY)).await.expect("import");
    assert_eq!(identity_of(&c.wallet_db()), origin, "import_wallet opened a different wallet");

    // And the imported wallet exports the same words again — the round trip closes.
    c.enter();
    zecboat_core::unlock_wallet("password-three".into(), false).await.expect("unlock imported");
    assert_eq!(exported_phrase().await, words, "the imported wallet exports different words");
}

/// The spend path. A send derives its signing key from the stored phrase through
/// `wallet::spending_key_from_phrase` — the one function every send calls. The key it
/// produces must be the key the wallet scans with, or a send would sign for one wallet
/// against notes found by another and fail at the chain, not in the app.
#[tokio::test]
async fn the_key_a_send_signs_with_is_the_key_the_wallet_scans_with() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let a = Sandbox::new("spend-key");
    let words = zecboat_core::initialize_new_wallet("password-one".into(), false, Some(BIRTHDAY))
        .await
        .expect("create wallet");
    zecboat_core::unlock_wallet("password-one".into(), false).await.expect("unlock");
    let (scans_with, _) = identity_of(&a.wallet_db());

    // From the wizard's words, and from the stored phrase — both go through the send's
    // own derivation, not a copy of it in this file.
    for (label, phrase) in [("wizard words", words.clone()), ("exported phrase", exported_phrase().await)] {
        let usk = zecboat_core::wallet::spending_key_from_phrase(&phrase)
            .unwrap_or_else(|e| panic!("{label}: the spend path refused the wallet's own phrase: {e}"));
        // Both as `uview1…`: the key crate's own encoding changed revision between the NU7
        // pre-release and the final crates, and the comparison is of keys, not of encodings.
        let signs_with = zecboat_core::addr::encode_uview1(&usk.to_unified_full_viewing_key());
        assert_eq!(signs_with, zecboat_core::addr::as_uview1(&scans_with), "{label}: a send would sign with a key that is not this wallet's");
    }
}

/// The passphrase the wallet was unlocked with. Taken out of the lock before the call:
/// `export_keys` locks it too, and a guard inside the call's arguments lives until the end
/// of the statement, `.await` included.
fn held_password() -> String {
    let held = zecboat_core::rpc::WALLET_PASSWORD.lock().unwrap().clone();
    held.expect("unlocked")
}
