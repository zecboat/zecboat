//! Every filesystem path the wallet uses, derived in one place.
//!
//! # Why this module exists
//!
//! Until 0.6.5 the wallet built its paths inline, 32 times, with this idiom:
//!
//! ```ignore
//! let home = std::env::var("HOME").unwrap_or_default();
//! let db_path = format!("{}/.AppVault/data/wallet.db", home);
//! ```
//!
//! Two problems, one of which is a live bug on Linux:
//!
//! 1. **`unwrap_or_default()` swallows a missing `HOME` into `""`**, so the path
//!    becomes `/.AppVault/data/wallet.db` — the filesystem root — and *nothing
//!    errors*. The wallet reports an empty balance, or creates a second wallet
//!    somewhere the user will never look. On Windows this is guaranteed rather
//!    than merely possible: Windows sets `USERPROFILE`, not `HOME`, so
//!    `env::var("HOME")` returns `Err` on every call.
//!
//! 2. **32 hand-copied expressions drift.** They already had two spellings of the
//!    same path and three of the same error message.
//!
//! These functions **fail** on a missing home directory rather than defaulting.
//! That is a deliberate behaviour change: refusing to open is recoverable, opening
//! the wrong database is not.
//!
//! # ⚠ `HOME` is the wallet's only isolation mechanism. Do not replace it.
//!
//! `app_data_dir()` resolves through `$HOME` on Unix **on purpose**, and must keep
//! doing so. Two live wallets on the maintainer's machine depend on it:
//!
//! ```text
//! ~/<live>/launch.sh     sets HOME=~/<live>    -> the wallet holding real funds (a folder name of your choosing)
//! ~/user2/launch-user2.sh sets HOME=~/user2    -> an independent second wallet
//! ~/zecboat_video/launch_demo_wallet.sh        -> an isolated demo wallet
//! ```
//!
//! Every "run against a copy, never the live wallet" instruction works the same
//! way. Swapping in a platform-directories crate that consults something else —
//! `XDG_DATA_HOME`, `%APPDATA%`, `~/Library/Application Support` — would make all
//! three silently open the *real* wallet while appearing to work. That is a
//! fund-losing change dressed as a tidy-up.
//!
//! Windows and macOS may diverge later; `zecboat_windows.md` §2 covers it. Unix
//! stays `$HOME`.

use anyhow::{anyhow, Result};
use std::path::PathBuf;

/// The user's home directory.
///
/// Errors rather than defaulting. See the module header: an empty string here
/// produced a silent write to the filesystem root.
pub fn home_dir() -> Result<PathBuf> {
    // Unix only, deliberately. `HOME` is what every launcher overrides to isolate
    // a wallet; a crate that consults anything else would break that silently.
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => Ok(PathBuf::from(h)),
        Ok(_) => Err(anyhow!(
            "HOME is set but empty. Refusing to guess a home directory — the wallet \
             would otherwise be created at the filesystem root."
        )),
        Err(_) => Err(anyhow!(
            "HOME is not set. The wallet derives every path from it, including which \
             wallet is opened, so there is no safe default."
        )),
    }
}

/// `$HOME/.AppVault/data` — the wallet's data directory.
pub fn app_data_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".AppVault").join("data"))
}

/// `$HOME/.AppVault/data/wallet.db`
pub fn wallet_db_path() -> Result<PathBuf> {
    Ok(app_data_dir()?.join("wallet.db"))
}

/// `$HOME/.AppVault/data/encryption-identity.txt`
///
/// The wallet will not open without this file, so it is always a pair with
/// [`wallet_db_path`]. Backups that carry one without the other are useless.
pub fn identity_path() -> Result<PathBuf> {
    Ok(app_data_dir()?.join("encryption-identity.txt"))
}

/// `$HOME/.AppVault/data/registry.db`: a view-only wallet for the Zecboat Registry (A3b).
///
/// Public data only: the registry's published viewing key, the registrations it received, and
/// the collections found through it. Deliberately a separate file from [`wallet_db_path`], so
/// reading the registry can never touch the user's own wallet. Deleting it loses nothing; the
/// next scan rebuilds it from the chain.
pub fn registry_db_path() -> Result<PathBuf> {
    Ok(app_data_dir()?.join("registry.db"))
}

/// `$HOME/.AppVault/data/yubikey-identity.txt`
///
/// Present only in a wallet that opted into YubiKey protection. Holds the plugin
/// identity stub (`AGE-PLUGIN-YUBIKEY-…`), which names a device serial and PIV slot
/// and is **not** a secret — it is useless without the key in hand.
///
/// Its presence is what puts the wallet in YubiKey mode, so it is as much a pair with
/// [`identity_path`] as that file is with [`wallet_db_path`]. A backup carrying the
/// identity without this stub will try the password path and fail confusingly.
pub fn yubikey_stub_path() -> Result<PathBuf> {
    Ok(app_data_dir()?.join("yubikey-identity.txt"))
}

/// `$HOME/ZecboatBackups`
pub fn backup_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join("ZecboatBackups"))
}

/// A named file inside [`backup_dir`].
pub fn backup_file(name: &str) -> Result<PathBuf> {
    Ok(backup_dir()?.join(name))
}

/// The same paths as `String`, for the many call sites that want one.
///
/// `to_string_lossy()` rather than `to_str().unwrap()`: a non-UTF-8 home directory
/// is exotic but should not panic a wallet.
pub mod as_string {
    use super::*;
    pub fn app_data_dir() -> Result<String> {
        Ok(super::app_data_dir()?.to_string_lossy().into_owned())
    }
    pub fn wallet_db_path() -> Result<String> {
        Ok(super::wallet_db_path()?.to_string_lossy().into_owned())
    }
    pub fn identity_path() -> Result<String> {
        Ok(super::identity_path()?.to_string_lossy().into_owned())
    }
    pub fn yubikey_stub_path() -> Result<String> {
        Ok(super::yubikey_stub_path()?.to_string_lossy().into_owned())
    }
    pub fn backup_dir() -> Result<String> {
        Ok(super::backup_dir()?.to_string_lossy().into_owned())
    }
    pub fn backup_file(name: &str) -> Result<String> {
        Ok(super::backup_file(name)?.to_string_lossy().into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `HOME` is process-global and cargo runs tests in parallel threads, so these
    /// tests were overwriting each other's environment mid-assertion — one read
    /// one fixture path while another had just set a different one. The failure
    /// looked like a path bug and was a test bug. Any test that mutates an env var
    /// must hold this lock.
    static ENV: Mutex<()> = Mutex::new(());

    /// The paths must be byte-identical to what the inlined `format!` calls
    /// produced, or an existing wallet silently becomes invisible.
    #[test]
    fn matches_the_legacy_layout() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", "/tmp/zbtest");
        assert_eq!(wallet_db_path().unwrap().to_str().unwrap(),
                   "/tmp/zbtest/.AppVault/data/wallet.db");
        assert_eq!(identity_path().unwrap().to_str().unwrap(),
                   "/tmp/zbtest/.AppVault/data/encryption-identity.txt");
        assert_eq!(app_data_dir().unwrap().to_str().unwrap(),
                   "/tmp/zbtest/.AppVault/data");
        assert_eq!(backup_dir().unwrap().to_str().unwrap(),
                   "/tmp/zbtest/ZecboatBackups");
        assert_eq!(backup_file("a.tar.gz").unwrap().to_str().unwrap(),
                   "/tmp/zbtest/ZecboatBackups/a.tar.gz");
    }

    /// HOME is the isolation mechanism: a different HOME must give a different
    /// wallet. If this test ever fails, a dedicated HOME has stopped isolating funds.
    ///
    /// The fixtures are under /tmp deliberately. `release-gate.sh` scans shipped .rs
    /// files for a `/home/<user>/` shape and cannot tell a placeholder from a real
    /// username — an earlier version of this test used "/home/someone" and the gate
    /// refused the 0.6.5 source tarball because of it.
    #[test]
    fn home_selects_the_wallet() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("HOME", "/tmp/zbtest-other");
        let a = wallet_db_path().unwrap();
        std::env::set_var("HOME", "/tmp/zbtest/live");
        let b = wallet_db_path().unwrap();
        assert_ne!(a, b, "HOME no longer selects the wallet — isolation is broken");
    }

    #[test]
    fn refuses_rather_than_defaulting() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("HOME");
        assert!(home_dir().is_err(), "a missing HOME must error, not default to \"\"");
        std::env::set_var("HOME", "");
        assert!(home_dir().is_err(), "an empty HOME must error, not build /.AppVault/...");
    }
}

// ── Private files (wallet review F-04, 2026-10-02) ──────────────────────────────────────────
// Every file the wallet writes holds secrets or linkable data: the encrypted identity, the
// database with the viewing key and every memo, the backups. They were created with the process
// umask (0644 on a stock desktop: world-readable). These helpers create them 0600 and their
// directories 0700. On non-Unix targets they fall back to the plain operations.

/// Create `dir` (and parents) readable by the owner only.
pub fn create_private_dir(dir: impl AsRef<std::path::Path>) -> std::io::Result<()> {
    let dir = dir.as_ref();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        return std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(dir)
}

/// Write `bytes` to `path`, owner-readable only (created or truncated, then chmod 0600).
pub fn write_private(path: impl AsRef<std::path::Path>, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(bytes.as_ref())?;
        f.sync_all()?;
        return std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes)
}

/// Copy `from` to `to`, then make `to` owner-readable only.
pub fn copy_private(from: impl AsRef<std::path::Path>, to: impl AsRef<std::path::Path>) -> std::io::Result<u64> {
    let n = std::fs::copy(&from, &to)?;
    #[cfg(unix)]
    std::fs::set_permissions(to.as_ref(), std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(n)
}

#[cfg(all(test, unix))]
mod private_file_tests {
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn files_and_dirs_are_owner_only() {
        let base = std::env::temp_dir().join(format!("zecboat_perm_{}", std::process::id()));
        let dir = base.join("data");
        super::create_private_dir(&dir).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        let f = dir.join("encryption-identity.txt");
        super::write_private(&f, b"secret").unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        super::write_private(&f, b"rewritten").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"rewritten");
        let c = dir.join("copy");
        super::copy_private(&f, &c).unwrap();
        assert_eq!(std::fs::metadata(&c).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&base);
    }
}
