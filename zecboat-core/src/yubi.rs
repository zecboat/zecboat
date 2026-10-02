//! YubiKey protection for the wallet identity file.
//!
//! # What this protects, and what it does not
//!
//! `encryption-identity.txt` holds an age X25519 identity. That identity decrypts the
//! seed phrase in `ext_zecboat_keystore_mnemonics`, so whoever can read it can rebuild
//! the wallet. Normally the file is age-encrypted under the unlock password.
//!
//! With a YubiKey the file is encrypted to a **PIV key that cannot leave the device**.
//! Decryption happens on the hardware. No copy of the identity file is useful without
//! the physical key.
//!
//! **It does NOT protect the spend.** Zcash spend authorization for Ironwood is
//! RedPallas over Pallas; no YubiKey applet implements it, and none is being pretended
//! here. Once the wallet is unlocked, signing is software, exactly as before. Claiming
//! otherwise is the specific dishonesty this module was rewritten to remove.
//!
//! # What was here before
//!
//! A mock. `is_yubikey_connected()` returned `true` unconditionally and
//! `get_yubikey_derived_key()` was `sha256(password || "Simulated_Hardware_HMAC_Secret")`
//! — a static string in the binary, no device ever contacted. A user told their wallet
//! was protected from physical access acts on that belief. The Settings panel offering
//! it was hidden on 2026-09-01 for that reason; this replaces the mechanism rather than
//! the label.
//!
//! # Where the PIN comes from
//!
//! The unlock password field. In YubiKey mode the string the user types is passed to the
//! plugin as the PIV PIN, so the box means something real again instead of being checked
//! against a file the hardware is already guarding. Retry limits are the device's, not
//! ours — three wrong PINs blocks the key, which is the point of a PIN.
//!
//! # Why the C dependency stays out of this binary
//!
//! `age-plugin-yubikey` speaks PIV over PC/SC, but age plugins are **separate
//! executables** driven over a stdio protocol. `libpcsclite` therefore lives in the
//! plugin process, not in ours. The `.deb`'s five dependencies are unchanged and 0.6.5's
//! removal of `libpcsclite1` stands. This is strictly better than the deleted `yubikey`
//! crate, which linked `pcsc-sys` directly and stopped `zecboat-core` compiling anywhere
//! `libpcsclite-dev` was absent.

use anyhow::{anyhow, bail, Result};
use std::str::FromStr;

/// The age plugin binary. Looked up on `$PATH`; `cargo install age-plugin-yubikey`.
pub const PLUGIN_NAME: &str = "yubikey";
const PLUGIN_BINARY: &str = "age-plugin-yubikey";

/// The plugin identity stub, stored beside the wallet.
///
/// This is NOT a secret. It names a key — serial number and PIV slot — and is useless
/// without the device. It is kept in the wallet directory so that `HOME` remains the
/// only thing separating one wallet from another, the same rule the rest of the app
/// follows.
pub const IDENTITY_STUB_FILE: &str = "yubikey-identity.txt";

/// Is the plugin installed?
///
/// Separate from "is a key plugged in" on purpose: the two failures need different
/// advice, and a user who has not installed the plugin should not be told to check
/// their USB port.
pub fn plugin_installed() -> bool {
    which_plugin().is_some()
}

fn which_plugin() -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(PLUGIN_BINARY))
            .find(|p| p.is_file())
    })
}

fn run_plugin(args: &[&str]) -> Result<String> {
    let bin = which_plugin().ok_or_else(|| {
        anyhow!(
            "{PLUGIN_BINARY} is not installed. Install it with:\n    \
             cargo install age-plugin-yubikey"
        )
    })?;
    let out = std::process::Command::new(&bin)
        .args(args)
        .output()
        .map_err(|e| anyhow!("could not run {PLUGIN_BINARY}: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("{PLUGIN_BINARY} {}: {}", args.join(" "), err.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Recipients (`age1yubikey1…`) for every age key on every connected YubiKey.
///
/// Empty means the plugin ran and found nothing — no device, or a device carrying no
/// age identity. That is a different answer from the plugin being absent, and callers
/// are expected to tell the user which one happened.
pub fn list_recipients() -> Result<Vec<String>> {
    Ok(run_plugin(&["--list"])
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("age1yubikey1"))
        .map(str::to_owned)
        .collect())
}

/// Identity stubs (`AGE-PLUGIN-YUBIKEY-…`) for every age key on every connected YubiKey.
pub fn list_identities() -> Result<Vec<String>> {
    Ok(run_plugin(&["--identity"])
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("AGE-PLUGIN-YUBIKEY-"))
        .map(str::to_owned)
        .collect())
}

/// Is a YubiKey carrying an age identity plugged in right now?
///
/// The old function of this name was `true` unconditionally.
pub fn is_yubikey_connected() -> bool {
    list_identities().map(|v| !v.is_empty()).unwrap_or(false)
}

/// Callbacks for the plugin protocol.
///
/// `request_passphrase` hands back the PIN the user typed into the unlock box. Every
/// other prompt is declined rather than guessed: there is no interactive terminal behind
/// a desktop wallet, and inventing an answer to "should I try this other key?" is how a
/// plugin ends up silently using a device the user did not intend.
#[derive(Clone)]
struct PinCallbacks {
    pin: age::secrecy::SecretString,
}

/// What the user should do with the key right now, while a decrypt is in progress; `None`
/// otherwise. The UI polls it. age-plugin-yubikey 0.5.1 has no "touch now" message of its own
/// (its only messages are "please insert the key with serial …" and errors), so the wallet
/// sets the touch line itself the moment it hands the plugin the decrypt: the PIN is passed
/// without any user action, so the whole wait from then on is the touch wait. The plugin's
/// own lines override it when they come. On 2026-10-02 a bare loop outside the wallet showed
/// that every "Failed to decrypt YubiKey stanza" came from a touch made before the plugin was
/// listening (a YubiKey 4 fires its OTP applet instead, and the real window then expires).
pub const TOUCH_NOW: &str = "Touch the YubiKey now (its light is blinking)";
static YUBI_MESSAGE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

pub fn yubikey_message() -> Option<String> {
    YUBI_MESSAGE.lock().ok().and_then(|m| m.clone())
}

fn set_yubikey_message(m: Option<String>) {
    if let Ok(mut g) = YUBI_MESSAGE.lock() {
        *g = m;
    }
}

/// Clears the status line when a decrypt ends, whichever way it ends.
struct ClearMessageOnDrop;
impl Drop for ClearMessageOnDrop {
    fn drop(&mut self) {
        set_yubikey_message(None);
    }
}

impl age::Callbacks for PinCallbacks {
    fn display_message(&self, message: &str) {
        // Reaches the user through the app's stdout log and, via `yubikey_message`, the
        // screen. The plugin uses this to say "touch the YubiKey", which must not be swallowed.
        println!("[yubikey] {message}");
        set_yubikey_message(Some(message.to_owned()));
    }

    fn confirm(&self, _message: &str, _yes: &str, _no: Option<&str>) -> Option<bool> {
        None
    }

    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }

    fn request_passphrase(&self, _description: &str) -> Option<age::secrecy::SecretString> {
        Some(self.pin.clone())
    }
}

/// Encrypt `plaintext` to a YubiKey recipient.
///
/// Used once, when a wallet opts in: the age identity that guards the seed is sealed to
/// the device instead of to a password.
pub fn encrypt_to_yubikey(plaintext: &[u8], recipient: &str) -> Result<Vec<u8>> {
    let recipient = age::plugin::Recipient::from_str(recipient)
        .map_err(|e| anyhow!("not a YubiKey age recipient: {e}"))?;

    let plugin = age::plugin::RecipientPluginV1::new(
        PLUGIN_NAME,
        &[recipient],
        &[],
        PinCallbacks {
            // Encryption needs a public key only; the device is not asked to do anything
            // secret here, so there is no PIN to supply.
            pin: age::secrecy::SecretString::new(String::new()),
        },
    )
    .map_err(|e| anyhow!("could not start {PLUGIN_BINARY}: {e}"))?;

    let encryptor =
        age::Encryptor::with_recipients(vec![Box::new(plugin) as Box<dyn age::Recipient + Send>])
            .ok_or_else(|| anyhow!("could not prepare YubiKey encryption"))?;

    let mut out = vec![];
    {
        let mut writer = encryptor.wrap_output(&mut out)?;
        std::io::Write::write_all(&mut writer, plaintext)?;
        writer.finish()?;
    }
    Ok(out)
}

/// Decrypt `ciphertext` on the YubiKey named by `identity_stub`, using `pin`.
///
/// The private key never leaves the device; the plugin performs the ECDH on the card.
pub fn decrypt_with_yubikey(
    ciphertext: &[u8],
    identity_stub: &str,
    pin: &str,
) -> Result<Vec<u8>> {
    use std::io::Read;

    set_yubikey_message(None);
    let _clear = ClearMessageOnDrop;

    let identity = age::plugin::Identity::from_str(identity_stub)
        .map_err(|e| anyhow!("not a YubiKey age identity: {e}"))?;

    let plugin = age::plugin::IdentityPluginV1::new(
        PLUGIN_NAME,
        &[identity],
        PinCallbacks {
            pin: age::secrecy::SecretString::new(pin.to_owned()),
        },
    )
    .map_err(|e| anyhow!("could not start {PLUGIN_BINARY}: {e}"))?;

    let decryptor = match age::Decryptor::new(ciphertext)
        .map_err(|e| anyhow!("wallet identity is unreadable: {e}"))?
    {
        age::Decryptor::Recipients(d) => d,
        // A passphrase-encrypted file in a YubiKey wallet means the two halves of the
        // wallet directory disagree. Say so plainly rather than reporting a PIN failure.
        age::Decryptor::Passphrase(_) => bail!(
            "this wallet's identity is password-encrypted, but a YubiKey stub is present. \
             The wallet directory is inconsistent; do not guess which half is current."
        ),
    };

    set_yubikey_message(Some(TOUCH_NOW.to_owned()));
    let mut reader = decryptor
        .decrypt(std::iter::once(&plugin as &dyn age::Identity))
        // Deliberately opaque, for the same reason as the password path: the underlying
        // error separates a wrong PIN from a missing device from a malformed file, and
        // handing that distinction to whoever is holding the laptop is not a kindness.
        .map_err(|_| {
            anyhow!("The YubiKey could not open this wallet. Check the key is inserted and the PIN is correct.")
        })?;

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod message_tests {
    use super::*;
    use age::Callbacks;

    #[test]
    fn plugin_message_is_shown_while_waiting_and_cleared_after() {
        set_yubikey_message(None);
        assert_eq!(yubikey_message(), None);
        {
            let _clear = ClearMessageOnDrop;
            set_yubikey_message(Some(TOUCH_NOW.to_owned()));
            assert_eq!(yubikey_message().as_deref(), Some(TOUCH_NOW));
            let cb = PinCallbacks { pin: age::secrecy::SecretString::new(String::new()) };
            cb.display_message("Please insert YubiKey with serial 1");
            assert_eq!(yubikey_message().as_deref(), Some("Please insert YubiKey with serial 1"), "the plugin's own line wins");
        }
        assert_eq!(yubikey_message(), None, "the line must not outlive the decrypt");
    }
}
