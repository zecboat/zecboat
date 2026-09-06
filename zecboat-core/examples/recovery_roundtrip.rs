//! Does a wallet recovered from its own seed phrase come back as the SAME wallet?
//!
//! The wizard makes a user write down 24 words and warns that losing them loses
//! their funds. Nobody had ever checked those words work. The round trip was
//! called a GUI test, but the part that can lose money is
//! `recover_wallet_from_seed`, and that is testable without a GUI.
//!
//! The failure is SILENT. If recovery derives a different wallet from the same
//! seed it does not error — it succeeds, shows a zero balance, and looks exactly
//! like the funds are gone.
//!
//! SAFETY: every wallet path is `format!("{}/.AppVault/data/...", $HOME)`, so this
//! points HOME at throwaway directories and asserts they are nowhere near the real
//! one before touching anything.

use std::path::PathBuf;

fn addresses(home: &PathBuf) -> Vec<String> {
    let db = home.join(".AppVault/data/wallet.db");
    let conn = rusqlite::Connection::open_with_flags(
        &db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    ).expect("open wallet.db");
    let mut st = conn.prepare("SELECT address FROM addresses ORDER BY id").unwrap();
    let out: Vec<String> = st.query_map([], |r| r.get::<_, String>(0)).unwrap()
        .filter_map(|r| r.ok()).collect();
    out
}

#[tokio::main]
async fn main() {
    let real_home = std::env::var("HOME").unwrap_or_default();
    let scratch = PathBuf::from("/tmp").join(format!("zbseed-{}", std::process::id()));
    assert!(!scratch.starts_with(&real_home), "scratch must not be under the real HOME");

    let (a, b) = (scratch.join("created"), scratch.join("recovered"));
    for p in [&a, &b] {
        let _ = std::fs::remove_dir_all(p);
        std::fs::create_dir_all(p.join(".AppVault/data")).unwrap();
    }
    const BIRTHDAY: u32 = 3_400_000;   // explicit, so this needs no network

    println!("scratch  {}", scratch.display());
    println!();

    // 1 — create a wallet exactly as the wizard does, and take the 24 words
    std::env::set_var("HOME", &a);
    let seed = zecboat_core::initialize_new_wallet("password-one".into(), false, Some(BIRTHDAY))
        .await.expect("create wallet");
    let words = seed.split_whitespace().count();
    let before = addresses(&a);
    println!("created    {words} words, {} addresses derived", before.len());

    // 2 — recover from those words into a DIFFERENT home, with a DIFFERENT password
    std::env::set_var("HOME", &b);
    let h = zecboat_core::recover_wallet_from_seed(&seed, "password-two".into(), Some(BIRTHDAY))
        .await.expect("recover wallet");
    let after = addresses(&b);
    println!("recovered  same 24 words, different password, birthday {h}, {} addresses", after.len());

    std::env::set_var("HOME", &real_home);
    println!();

    if before.is_empty() {
        println!("INCONCLUSIVE — the created wallet derived no addresses");
        std::process::exit(2);
    }
    if before == after {
        println!("PASS — the same seed recovered the same {} addresses", before.len());
        println!("  first address: {}", &before[0][..56.min(before[0].len())]);
        let _ = std::fs::remove_dir_all(&scratch);
    } else {
        println!("**FAIL** — recovery produced a DIFFERENT wallet");
        println!("  created   {} addresses, first {}", before.len(),
                 before.first().map(|s| &s[..32.min(s.len())]).unwrap_or(""));
        println!("  recovered {} addresses, first {}", after.len(),
                 after.first().map(|s| &s[..32.min(s.len())]).unwrap_or(""));
        println!();
        println!("  The 24 words the wizard tells users to write down do not restore their wallet.");
        std::process::exit(1);
    }
}
