//! v0.7.0 B8: rescan from a height. The guards, in a sandbox with no node.
//!
//! What a rescan actually does to a synced wallet is proved on a throwaway wallet against a
//! node (testA, 2026-09-27), not here: the sandbox has no blocks to rewind. These tests pin
//! the refusals, which are where a wrong answer costs the user something.
use std::path::PathBuf;
use std::sync::Mutex;

static ENV: Mutex<()> = Mutex::new(());
const BIRTHDAY: u32 = 3_400_000;

struct Sandbox {
    home: PathBuf,
    real_home: Option<String>,
}

impl Sandbox {
    fn new(tag: &str) -> Self {
        let real_home = std::env::var("HOME").ok();
        let home = std::env::temp_dir().join(format!("zb-rescantest-{}-{}", std::process::id(), tag));
        if let Some(rh) = &real_home {
            assert!(!rh.is_empty() && !home.starts_with(rh), "scratch HOME must not be under the real HOME");
        }
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        *zecboat_core::rpc::PROVIDER_URL.lock().unwrap() = "http://127.0.0.1:1".to_string();
        Sandbox { home, real_home }
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

/// A rescan rewinds wallet state. Nothing that rewinds wallet state runs on a locked wallet.
#[tokio::test]
async fn a_locked_wallet_refuses_a_rescan() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let _sb = Sandbox::new("locked");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY)).await.expect("create");
    *zecboat_core::rpc::WALLET_PASSWORD.lock().unwrap() = None;
    let r = zecboat_core::rescan_from_height(BIRTHDAY).await;
    let e = r.expect_err("a locked wallet must refuse").to_string();
    assert!(e.contains("Unlock"), "unexpected refusal: {e}");
}

/// A wallet that has scanned nothing has nothing to rewind; say so rather than "rewound to 0".
#[tokio::test]
async fn a_wallet_with_no_scanned_blocks_has_nothing_to_rescan() {
    let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
    let _sb = Sandbox::new("unscanned");
    zecboat_core::initialize_new_wallet("pw".into(), false, Some(BIRTHDAY)).await.expect("create");
    // initialize leaves the password set; the wallet counts as unlocked.
    let e = zecboat_core::rescan_from_height(BIRTHDAY)
        .await
        .expect_err("nothing scanned")
        .to_string();
    assert!(e.contains("not scanned any blocks"), "unexpected refusal: {e}");
    // And it must not have queued anything for an engine that is not running.
    assert!(zecboat_core::rpc::RESCAN_REQUEST.lock().unwrap().is_none());
}
