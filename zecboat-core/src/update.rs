//! The in-wallet update check (`zecboat_admin/roadmap/update_check.md`, decided 2026-10-15;
//! built 2026-10-27 for 0.7.3).
//!
//! Signatures only, deterministic, never a dependency. The release process writes a short
//! note, `latest.json`, beside `SHA256SUMS` and signs it with the same Ed25519 release key
//! (raw signature over the file's bytes, `openssl pkeyutl -rawin`, exactly as `SHA256SUMS.sig`).
//! The wallet fetches the note and its signature through the registry's bounded https client,
//! verifies the signature under the key compiled into this build, and only then reads the
//! JSON. A newer version becomes one line in the UI with a button. Anything else, an
//! unreachable host, a bad signature, an older note, is `None` or an error the UI turns into
//! silence: the wallet never depends on the site (the rule lineage and send already follow).
//!
//! The button downloads the `.deb` named in the signed note, checks its sha256 against the
//! note, writes it under the wallet's data directory only after that check, and hands it to
//! the system installer with the user's own authentication (`pkexec apt-get install`). Nothing
//! downloaded is ever run by the wallet; the mirror is never the authority; no redirect is
//! followed; no third party is involved.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The public half of the release signing key, the key behind every `SHA256SUMS.sig` since
/// 0.7.0 and shown on the About panel. Compiled in: a compromised website cannot change it.
pub const RELEASE_PUBLIC_KEY_HEX: &str =
    "e23a2fed8f8134005ba47a3d800509678ef913d65dbe8e39d2cffc778219ed0d";

/// Where the signed note lives. The GitHub mirror is deliberately not consulted: one source,
/// one key. `ZECBOAT_UPDATE_URL` overrides it for tests (`file://` is accepted there).
pub const UPDATE_NOTE_URL: &str = "https://zecboat.com/downloads/latest.json";

/// A release note is a few hundred bytes; a signature is exactly 64.
const MAX_NOTE_BYTES: usize = 16 * 1024;
const MAX_SIG_BYTES: usize = 64;
/// The 0.7.2 `.deb` is under 30 MB. A bound, not a target.
const MAX_DEB_BYTES: usize = 256 * 1024 * 1024;

/// What the UI shows and the install step acts on. Everything here came out of the signed
/// note; `current` is this build's own version, for the sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub released: String,
    pub deb_url: String,
    pub deb_sha256: String,
    pub notes_url: String,
    pub current: String,
}

pub fn note_url() -> String {
    std::env::var("ZECBOAT_UPDATE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| UPDATE_NOTE_URL.to_string())
}

/// `major.minor.patch[-pre]`. A pre-release sorts below the release it precedes
/// (`0.7.3-beta < 0.7.3`), which is the one rule a plain tuple comparison gets wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>,
}

impl Version {
    pub fn parse(s: &str) -> Result<Version> {
        let s = s.trim().trim_start_matches('v');
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) if !p.is_empty() => (c, Some(p.to_string())),
            Some(_) => return Err(anyhow!("version {s:?}: empty pre-release tag")),
            None => (s, None),
        };
        let mut it = core.split('.');
        let mut next = |what: &str| -> Result<u64> {
            it.next()
                .ok_or_else(|| anyhow!("version {s:?}: missing {what}"))?
                .parse::<u64>()
                .map_err(|_| anyhow!("version {s:?}: {what} is not a number"))
        };
        let v = Version { major: next("major")?, minor: next("minor")?, patch: next("patch")?, pre };
        if it.next().is_some() {
            return Err(anyhow!("version {s:?}: more than three numbers"));
        }
        Ok(v)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        match (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)) {
            Equal => match (&self.pre, &other.pre) {
                (None, None) => Equal,
                (None, Some(_)) => Greater,
                (Some(_), None) => Less,
                (Some(a), Some(b)) => a.cmp(b),
            },
            o => o,
        }
    }
}

/// Verify `sig` (64 raw bytes) over `note` under the hex-encoded Ed25519 key, then parse the
/// note as JSON. Parsing happens after verification on purpose: unsigned bytes are never
/// interpreted.
pub fn verify_note(note: &[u8], sig: &[u8], key_hex: &str) -> Result<Value> {
    let key = hex::decode(key_hex.trim()).context("release key is not hex")?;
    let vk = ed25519_zebra::VerificationKey::try_from(key.as_slice())
        .map_err(|_| anyhow!("release key is not a valid Ed25519 public key"))?;
    if sig.len() != 64 {
        return Err(anyhow!("release note signature is {} bytes, not 64", sig.len()));
    }
    let sig = ed25519_zebra::Signature::from_slice(sig)
        .map_err(|_| anyhow!("release note signature is malformed"))?;
    vk.verify(&sig, note)
        .map_err(|_| anyhow!("release note signature does not verify under the pinned release key"))?;
    serde_json::from_slice(note).context("release note is not JSON")
}

/// Read the verified note. `Some` only when it names a version newer than `current` and
/// carries an https `.deb` URL with a 64-hex sha256; a same or older version is `None`, so a
/// note cannot talk a wallet into a downgrade.
pub fn newer_from_note(note: &Value, current: &str) -> Result<Option<UpdateInfo>> {
    let s = |k: &str| -> Result<String> {
        note.get(k)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("release note has no {k:?}"))
    };
    let version = s("version")?;
    let theirs = Version::parse(&version)?;
    let ours = Version::parse(current)?;
    if theirs <= ours {
        return Ok(None);
    }
    let deb_url = note
        .pointer("/urls/deb")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("release note has no urls.deb"))?
        .to_string();
    if !deb_url.starts_with("https://") {
        return Err(anyhow!("release note names a .deb that is not https"));
    }
    let deb_sha256 = note
        .pointer("/sha256/deb")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("release note has no sha256.deb"))?
        .trim()
        .to_lowercase();
    if deb_sha256.len() != 64 || hex::decode(&deb_sha256).is_err() {
        return Err(anyhow!("release note's sha256.deb is not 64 hex characters"));
    }
    Ok(Some(UpdateInfo {
        version,
        released: s("released").unwrap_or_default(),
        deb_url,
        deb_sha256,
        notes_url: s("notes_url").unwrap_or_default(),
        current: current.to_string(),
    }))
}

/// Fetch the note and its signature from `note_url` (and `note_url + ".sig"`), verify under
/// `key_hex`, compare with `current`.
pub async fn check_update_with(note_url: &str, key_hex: &str, current: &str) -> Result<Option<UpdateInfo>> {
    let (_, note) = crate::rpc::registry_fetch(note_url, MAX_NOTE_BYTES).await?;
    let (_, sig) = crate::rpc::registry_fetch(&format!("{note_url}.sig"), MAX_SIG_BYTES).await?;
    let v = verify_note(&note, &sig, key_hex)?;
    newer_from_note(&v, current)
}

/// The wallet's own check: the pinned key, the fixed URL, this build's version.
pub async fn check_update() -> Result<Option<UpdateInfo>> {
    check_update_with(&note_url(), RELEASE_PUBLIC_KEY_HEX, env!("CARGO_PKG_VERSION")).await
}

/// The downloaded package must hash to what the signed note says, byte for byte.
pub fn verify_deb(bytes: &[u8], expected_sha256_hex: &str) -> Result<()> {
    let got = hex::encode(Sha256::digest(bytes));
    if got != expected_sha256_hex.trim().to_lowercase() {
        return Err(anyhow!(
            "downloaded package does not match the signed release note (sha256 {got}, note says {expected_sha256_hex}); nothing installed"
        ));
    }
    Ok(())
}

/// `Zecboat_<version>_amd64.deb`, with the version limited to the characters a version has.
/// The name is built here, never taken from the note or the URL.
pub fn deb_file_name(version: &str) -> Result<String> {
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')) {
        return Err(anyhow!("version {version:?} is not a package version"));
    }
    Ok(format!("Zecboat_{version}_amd64.deb"))
}

/// Download the `.deb` the note names, verify it, and only then write it under the wallet's
/// data directory (`updates/`, mode 0600). Returns the file's path.
pub async fn download_update(info: &UpdateInfo) -> Result<PathBuf> {
    let (_, bytes) = crate::rpc::registry_fetch(&info.deb_url, MAX_DEB_BYTES).await?;
    verify_deb(&bytes, &info.deb_sha256)?;
    let dir = crate::paths::app_data_dir()?.join("updates");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(deb_file_name(&info.version)?);
    write_private(&path, &bytes)?;
    Ok(path)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).with_context(|| format!("cannot write {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// The one command the install step runs. `pkexec` asks the desktop for the user's own
/// authentication; `apt-get` takes a local file when the path contains a slash, which an
/// absolute path always does. The wallet runs nothing it downloaded.
pub fn install_command(deb: &Path) -> std::process::Command {
    let mut c = std::process::Command::new("pkexec");
    c.arg("apt-get").arg("install").arg("-y").arg(deb);
    c
}

/// Re-run the check (the signed note is the only authority; what the UI holds is a copy),
/// insist it still names `expected_version`, download, verify, install. The sentence that comes
/// back is for the screen.
pub async fn install_update(expected_version: &str) -> Result<String> {
    let info = check_update()
        .await?
        .ok_or_else(|| anyhow!("no newer release is signed right now; nothing installed"))?;
    if info.version != expected_version {
        return Err(anyhow!(
            "the signed release note now names {} rather than {}; check again before installing",
            info.version,
            expected_version
        ));
    }
    let path = download_update(&info).await?;
    let out = tokio::task::spawn_blocking(move || install_command(&path).output())
        .await
        .map_err(|e| anyhow!("installer task: {e}"))?
        .context("could not start pkexec; is PolicyKit installed?")?;
    if out.status.success() {
        Ok(format!("{} installed. Restart Zecboat to run it.", info.version))
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let tail: String = err.lines().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" ");
        Err(anyhow!(
            "the installer did not complete (exit {}): {}",
            out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
            if tail.is_empty() { "no message".to_string() } else { tail }
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn versions_order_the_way_releases_do() {
        assert!(v("0.7.3-beta") > v("0.7.2"));
        assert!(v("0.7.3-beta") > v("0.7.2-beta"));
        assert!(v("0.7.3") > v("0.7.3-beta"), "a release follows its pre-release");
        assert!(v("0.8.0") > v("0.7.9"));
        assert!(v("1.0.0") > v("0.99.99"));
        assert_eq!(v("0.7.3"), v("v0.7.3"));
        assert!(v("0.7.3-rc.2") > v("0.7.3-rc.1"));
        for bad in ["", "0.7", "0.7.3.1", "0.x.3", "0.7.3-"] {
            assert!(Version::parse(bad).is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn the_pinned_release_key_is_a_valid_ed25519_key() {
        let key = hex::decode(RELEASE_PUBLIC_KEY_HEX).unwrap();
        assert_eq!(key.len(), 32);
        ed25519_zebra::VerificationKey::try_from(key.as_slice()).expect("the pinned key must be a valid point");
    }

    /// A throwaway signing key for the tests. The real key never leaves the release machine.
    fn test_key() -> (ed25519_zebra::SigningKey, String) {
        let sk = ed25519_zebra::SigningKey::from([7u8; 32]);
        let vk: [u8; 32] = ed25519_zebra::VerificationKey::from(&sk).into();
        (sk, hex::encode(vk))
    }

    fn note(version: &str) -> Vec<u8> {
        serde_json::json!({
            "version": version,
            "released": "2026-11-30",
            "urls": {"deb": "https://zecboat.com/downloads/Zecboat_0.7.3_amd64.deb"},
            "sha256": {"deb": "ab".repeat(32)},
            "notes_url": "https://zecboat.com/downloads"
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn a_signed_note_is_read_only_after_its_signature_verifies() {
        let (sk, key_hex) = test_key();
        let n = note("0.7.3-beta");
        let sig = sk.sign(&n).to_bytes();
        let v = verify_note(&n, &sig, &key_hex).unwrap();
        assert_eq!(v["version"], "0.7.3-beta");

        // Tampered note: one byte, same signature.
        let mut tampered = n.clone();
        tampered[10] ^= 1;
        assert!(verify_note(&tampered, &sig, &key_hex).is_err());
        // Wrong key.
        let other: [u8; 32] = ed25519_zebra::VerificationKey::from(&ed25519_zebra::SigningKey::from([9u8; 32])).into();
        assert!(verify_note(&n, &sig, &hex::encode(other)).is_err());
        // Wrong length, malformed, and the pinned production key (the test key is not it).
        assert!(verify_note(&n, &sig[..63], &key_hex).is_err());
        assert!(verify_note(&n, &sig, RELEASE_PUBLIC_KEY_HEX).is_err());
        // Unsigned bytes are never parsed: a note that is not even JSON fails on the signature
        // first, and valid JSON with a bad signature fails the same way.
        assert!(verify_note(b"not json", &sig, &key_hex).unwrap_err().to_string().contains("signature"));
    }

    #[test]
    fn only_a_newer_version_is_an_update() {
        let newer = serde_json::from_slice::<Value>(&note("0.7.3-beta")).unwrap();
        let info = newer_from_note(&newer, "0.7.2").unwrap().expect("0.7.3-beta is newer than 0.7.2");
        assert_eq!(info.version, "0.7.3-beta");
        assert_eq!(info.deb_sha256, "ab".repeat(32));
        assert_eq!(info.current, "0.7.2");

        let same = serde_json::from_slice::<Value>(&note("0.7.2")).unwrap();
        assert_eq!(newer_from_note(&same, "0.7.2").unwrap(), None);
        let older = serde_json::from_slice::<Value>(&note("0.7.1-beta")).unwrap();
        assert_eq!(newer_from_note(&older, "0.7.2").unwrap(), None, "a note can never downgrade");
        let pre_of_ours = serde_json::from_slice::<Value>(&note("0.7.2-beta")).unwrap();
        assert_eq!(newer_from_note(&pre_of_ours, "0.7.2").unwrap(), None);

        // A newer version with a non-https .deb or a bad hash is an error, not an update.
        let mut bad = newer.clone();
        bad["urls"]["deb"] = Value::from("http://zecboat.com/x.deb");
        assert!(newer_from_note(&bad, "0.7.2").is_err());
        let mut bad = newer.clone();
        bad["sha256"]["deb"] = Value::from("abc");
        assert!(newer_from_note(&bad, "0.7.2").is_err());
        let mut bad = newer;
        bad["version"] = Value::from("soon");
        assert!(newer_from_note(&bad, "0.7.2").is_err());
    }

    #[tokio::test]
    async fn the_check_end_to_end_over_file_urls() {
        let (sk, key_hex) = test_key();
        let dir = std::env::temp_dir().join(format!("zb-update-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let n = note("0.7.3-beta");
        let p = dir.join("latest.json");
        std::fs::write(&p, &n).unwrap();
        std::fs::write(dir.join("latest.json.sig"), sk.sign(&n).to_bytes()).unwrap();
        let url = format!("file://{}", p.display());

        let info = check_update_with(&url, &key_hex, "0.7.2").await.unwrap().expect("newer");
        assert_eq!(info.version, "0.7.3-beta");
        assert_eq!(check_update_with(&url, &key_hex, "0.7.3").await.unwrap(), None);
        // The pinned production key rejects the test signature: silence, not a prompt.
        assert!(check_update_with(&url, RELEASE_PUBLIC_KEY_HEX, "0.7.2").await.is_err());
        // No signature file at all.
        std::fs::remove_file(dir.join("latest.json.sig")).unwrap();
        assert!(check_update_with(&url, &key_hex, "0.7.2").await.is_err());
        // An unreachable host over the real client is an error too, never a notice.
        assert!(check_update_with("https://127.0.0.1:1/latest.json", &key_hex, "0.7.2").await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_package_must_hash_to_the_note() {
        let bytes = b"not really a deb";
        let good = hex::encode(Sha256::digest(bytes));
        verify_deb(bytes, &good).unwrap();
        verify_deb(bytes, &good.to_uppercase()).unwrap();
        assert!(verify_deb(bytes, &"00".repeat(32)).is_err());
        assert!(verify_deb(b"not really a deb!", &good).is_err());
    }

    #[test]
    fn the_file_name_comes_from_the_version_alone() {
        assert_eq!(deb_file_name("0.7.3-beta").unwrap(), "Zecboat_0.7.3-beta_amd64.deb");
        for bad in ["", "../x", "0.7.3 beta", "0.7.3/"] {
            assert!(deb_file_name(bad).is_err(), "{bad:?}");
        }
        let c = install_command(Path::new("/home/u/.AppVault/data/updates/Zecboat_0.7.3-beta_amd64.deb"));
        assert_eq!(c.get_program(), "pkexec");
        let args: Vec<_> = c.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["apt-get", "install", "-y", "/home/u/.AppVault/data/updates/Zecboat_0.7.3-beta_amd64.deb"]);
    }
}
