use serde_json::Value;
use anyhow::Result;
use bip0039::{Count, English, Mnemonic};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use once_cell::sync::Lazy;

/// The lightwalletd gRPC client.
///
/// This used to be a second copy of the protos compiled locally by build.rs.
/// Because that copy was generated against a different prost major version than
/// zcash_client_backend's, every compact block had to be re-encoded and decoded
/// to cross between the two representations. Aliasing the backend's own
/// generated module removes the duplicate codegen, the round-trip, build.rs,
/// proto/, tonic-build, and the second prost dependency.
///
/// Verified present here: BlockId, BlockRange, Empty, RawTransaction,
/// GetAddressUtxosArg, compact_tx_streamer_client.
pub use zcash_client_backend::proto::service as lightwallet;

use tokio::time::{sleep, Duration};
use zcash_client_sqlite::WalletDb;
use zcash_protocol::consensus::MainNetwork;
use zcash_client_sqlite::util::SystemClock;
use rand::rngs::OsRng;
use zcash_protocol::consensus::BlockHeight;

pub static WALLET_PASSWORD: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

/// Verify a passphrase by actually decrypting the age identity.
///
/// W5. This is the check the previous version skipped. The identity file is
/// passphrase-encrypted with age; if the passphrase is wrong, decryption fails.
/// There is no cheaper way to be sure — a stored hash would only prove someone
/// typed the right string, not that the key material is recoverable.
///
/// Mirrors `ironwood_shield/src/shield_iw.rs:44-64`, which is the code path that
/// successfully unlocked this wallet to build the mined Ironwood transaction.
/// Parse a seed phrase into a mnemonic. **Every phrase entering this wallet goes through
/// here**, and there are two reasons it exists rather than calling `from_phrase` directly.
///
/// # 1. NFKD, which `bip0039` does not do for the seed
///
/// BIP-39 requires the phrase be NFKD-normalised before PBKDF2. `bip0039 0.12` normalises
/// for the **checksum** — `mnemonic.rs:365`, inside `phrase_to_entropy`, on a *local* copy
/// — and then `from_phrase` stores `phrase.split_whitespace().join(" ")` from the
/// **original** text. `to_seed` hashes that stored text under this comment:
///
/// ```text
/// // the phrase has been normalized
/// let normalized_password = self.phrase();
/// ```
///
/// It has not been. So a phrase carrying compatibility characters passes the checksum and
/// derives a seed **no other BIP-39 wallet would derive** — silently, with no error, into
/// an empty wallet.
///
/// Measured on 2026-09-23: `fine` written with U+FB01 gives `03e79f69…`, the ASCII
/// spelling gives `a830c0d3…`, and NFKD folds the first onto the second. The realistic
/// route is a phrase copied out of a PDF whose renderer substituted ligatures, and the
/// affected words are ordinary: *fine finger finish fire firm first fish fit fix flag
/// flame flash flat flavor flee effort*.
///
/// A second reviewer read `bip0039` and concluded it normalises correctly, having believed
/// that comment. Two passes disagreed; the test settled it, because it calls the crate
/// instead of reading it.
///
/// # 2. The error must never contain the phrase
///
/// `wallet.rs:207` and `:478` formatted the decrypted phrase into an `anyhow` error that
/// reaches a UI toast, a log, or a bug report. The `rpc.rs` entry points already refused to
/// do this; `wallet.rs` did not get the memo. The returned error names a word count and
/// nothing else — never the phrase, never which word failed, since that tells anyone
/// holding a partial phrase exactly what they still need.
pub(crate) fn phrase_to_mnemonic(phrase: &str) -> Result<Mnemonic<English>> {
    use unicode_normalization::UnicodeNormalization;

    // NFKD first, then collapse whitespace. Order matters: some compatibility characters
    // decompose to sequences containing spaces.
    // F5. Both intermediates hold the phrase; both are wiped on drop. `from_phrase` takes
    // its own owned copy, which the Mnemonic wipes when it drops (bip0039 impls Zeroize).
    let nfkd = zeroize::Zeroizing::new(phrase.nfkd().collect::<String>());
    let normalized = zeroize::Zeroizing::new(nfkd.split_whitespace().collect::<Vec<_>>().join(" "));
    let words = normalized.split_whitespace().count();

    Mnemonic::<English>::from_phrase(normalized.as_str()).map_err(|_| {
        if words != 24 {
            anyhow::anyhow!("A recovery phrase is 24 words. This one has {words}.")
        } else {
            anyhow::anyhow!(
                "This recovery phrase is not valid. Check for a mistyped or transposed word."
            )
        }
    })
}

/// The real ZIP-32 seed fingerprint for a phrase.
///
/// The three writers of `ext_zecboat_keystore_mnemonics` each stored `vec![0u8; 32]` here,
/// under the comment *"Use a dummy 32-byte array for the fingerprint to satisfy the schema
/// constraint"*. The column is declared `BLOB NOT NULL UNIQUE` and exists to say WHICH seed
/// the stored mnemonic belongs to; a constant says nothing, and a constant in a UNIQUE
/// column says it about every wallet at once.
///
/// What it costs: nothing detects a database whose mnemonic and account disagree. A
/// mismatched restore or a half-copied directory shows one wallet's balance and signs with
/// another's key, and the failure surfaces at the first spend rather than at unlock.
/// `zcash_client_sqlite` computes a genuine `SeedFingerprint` into `accounts` already — see
/// `verify_seed_matches_account`, which compares against that rather than trusting this.
fn seed_fingerprint(mnemonic: &Mnemonic<English>) -> Vec<u8> {
    let seed = zeroize::Zeroizing::new(mnemonic.to_seed(""));
    zip32::fingerprint::SeedFingerprint::from_seed(&*seed)
        .expect("a BIP-39 seed is 64 bytes, within the 32..=252 the fingerprint accepts")
        .to_bytes()
        .to_vec()
}

/// Is the mnemonic this wallet stores the one its account was derived from?
///
/// Compares the fingerprint of the decrypted phrase against `accounts.hd_seed_fingerprint`,
/// which the backend computed independently when the account was created. **Deliberately
/// not compared against our own column**: trusting a value we wrote ourselves would only
/// prove we are self-consistent, and every wallet created before this change has zeros
/// there.
///
/// Returns Ok(()) when they agree or when the account carries no fingerprint to compare.
fn verify_seed_matches_account(conn: &rusqlite::Connection, mnemonic: &Mnemonic<English>) -> Result<()> {
    let ours = seed_fingerprint(mnemonic);

    // EVERY account, not the first.
    //
    // An earlier draft compared against `accounts LIMIT 1`, on the belief that
    // `import_wallet` ADDS an account and a database could hold two rows. Measuring it
    // showed otherwise: import moves `wallet.db` aside and builds a fresh one, so there is
    // a single row. The belief was wrong; reading every row is still right, because it
    // costs nothing and does not depend on that behaviour staying true.
    let mut stmt = conn.prepare("SELECT hd_seed_fingerprint FROM accounts")?;
    let rows: Vec<Option<Vec<u8>>> = stmt
        .query_map([], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?;

    // Nothing to compare against: no accounts yet, or accounts carrying no fingerprint,
    // which a view-only import legitimately has. Not an error.
    let known: Vec<Vec<u8>> = rows
        .into_iter()
        .flatten()
        .filter(|f| !f.iter().all(|b| *b == 0))
        .collect();
    if known.is_empty() || known.iter().any(|f| *f == ours) {
        return Ok(());
    }

    anyhow::bail!(
        "this wallet's stored seed phrase does not belong to any of its accounts.\n\n\
         The account(s) were derived from a different seed than the phrase stored beside \
         them — a database and an encryption identity from different wallets have been put \
         together, most often by restoring a backup over a newer wallet. The balance shown \
         would be one wallet's and any signature another's.\n\n\
         Do not send from this wallet. Recover from your 24-word phrase instead."
    )
}

/// Is this wallet sealed to a YubiKey?
///
/// The stub file is the mode — see [`unlock_wallet`]. The UI needs this so the unlock
/// box can ask for a PIN rather than a password, which are not the same thing and have
/// very different consequences for getting wrong: three bad PINs block the device.
pub async fn wallet_uses_yubikey() -> Result<bool> {
    Ok(crate::paths::yubikey_stub_path()?.exists())
}

/// Decrypt `encryption-identity.txt` and return the X25519 identity inside it.
///
/// **The wallet directory decides how**, not the caller: if the YubiKey stub is present
/// the file is opened on the device, otherwise with the unlock password. Four call sites
/// previously each opened it themselves, all four hardcoding
/// `Decryptor::Passphrase`, so a YubiKey wallet would have failed in three of them with
/// "Expected passphrase-based age encryption" — and any future call site would have
/// inherited the same bug by copying its neighbour.
///
/// This is the same move `lock_zmap_carriers` made: put the rule where a forgetful call
/// site cannot bypass it, rather than asking every caller to remember.
pub(crate) fn decrypt_identity() -> Result<age::x25519::Identity> {
    use std::io::Read;
    use std::str::FromStr;

    let secret = WALLET_PASSWORD
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Wallet is locked. Please unlock the wallet first."))?;

    let identity_path = crate::paths::identity_path()?;
    let encrypted = std::fs::read(&identity_path)
        .map_err(|e| anyhow::anyhow!("could not read the encryption identity file: {e}"))?;

    let stub_path = crate::paths::yubikey_stub_path()?;
    let text = if stub_path.exists() {
        let stub = std::fs::read_to_string(&stub_path)?;
        let stub = stub
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("AGE-PLUGIN-YUBIKEY-"))
            .ok_or_else(|| {
                anyhow::anyhow!("the YubiKey stub contains no identity line")
            })?;
        // In YubiKey mode WALLET_PASSWORD holds the PIV PIN.
        String::from_utf8(crate::yubi::decrypt_with_yubikey(&encrypted, stub, &secret)?)
            .map_err(|e| anyhow::anyhow!("decrypted identity is not valid text: {e}"))?
    } else {
        let decryptor = match age::Decryptor::new(&encrypted[..]) {
            Ok(age::Decryptor::Passphrase(d)) => d,
            // `.unwrap()` here once panicked the backend on a damaged identity file.
            Ok(_) => {
                return Err(anyhow::anyhow!(
                    "the encryption identity file is not passphrase-protected as expected. \
                     It may have been replaced or corrupted."
                ))
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "could not read the encryption identity file ({e}). It may be damaged or \
                     truncated. This file is one half of a wallet backup; without it the seed \
                     phrase in the database cannot be decrypted."
                ))
            }
        };
        let mut reader = decryptor
            .decrypt(&age::secrecy::Secret::new(secret), Some(22))
            // Deliberately opaque — see the note on the unlock path.
            .map_err(|_| anyhow::anyhow!("Incorrect password."))?;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        String::from_utf8(buf)
            .map_err(|e| anyhow::anyhow!("decrypted data is not valid UTF-8: {e}"))?
    };

    let key_line = text
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .ok_or_else(|| anyhow::anyhow!("No AGE-SECRET-KEY found in decrypted identity"))?;
    age::x25519::Identity::from_str(key_line)
        .map_err(|e| anyhow::anyhow!("the encryption identity is not in a recognised format: {e}"))
}

fn verify_wallet_passphrase(passphrase: &str) -> Result<()> {
    use std::io::Read;
    use std::str::FromStr;

    let identity_path = crate::paths::as_string::identity_path()?;
    let encrypted = std::fs::read(&identity_path).map_err(|e| {
        anyhow::anyhow!("could not read the wallet identity at {}: {}", identity_path, e)
    })?;

    let decryptor = match age::Decryptor::new(&encrypted[..])
        .map_err(|e| anyhow::anyhow!("wallet identity is unreadable: {}", e))?
    {
        age::Decryptor::Passphrase(d) => d,
        _ => anyhow::bail!("wallet identity is not passphrase-encrypted"),
    };

    let mut reader = decryptor
        .decrypt(&age::secrecy::Secret::new(passphrase.to_owned()), Some(22))
        // Deliberately opaque. The underlying age error distinguishes a wrong
        // passphrase from a malformed file, and surfacing that difference tells an
        // attacker which one they got. Do not add context here.
        .map_err(|_| anyhow::anyhow!("Incorrect password."))?;

    // Decryption succeeding is the proof; confirm the plaintext really is an age
    // identity so a corrupt file cannot masquerade as a successful unlock.
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("could not read the decrypted identity: {}", e))?;
    let text = String::from_utf8(buf)
        .map_err(|e| anyhow::anyhow!("decrypted identity is not valid text: {e}"))?;
    let key_line = text
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .ok_or_else(|| anyhow::anyhow!("decrypted identity contains no age secret key"))?;
    age::x25519::Identity::from_str(key_line)
        .map_err(|e| anyhow::anyhow!("decrypted identity is malformed: {}", e))?;

    Ok(())
}

pub async fn unlock_wallet(password: String, _use_yubikey: bool) -> Result<()> {

    // `use_yubikey` is ignored, deliberately. It used to be a caller-supplied flag, which
    // meant a caller could ask for the password path on a wallet sealed to a device — and
    // get an "Incorrect password." for a wallet that has no password. **The wallet
    // directory decides, not the call site**: the presence of the stub file is the mode.
    //
    // That also makes the refusal unconditional. There is no argument any caller can pass
    // that opens a YubiKey wallet without the key, which is what the ship gate asks for.
    let stub_path = crate::paths::yubikey_stub_path()?;
    let final_password = if stub_path.exists() {
        let stub = std::fs::read_to_string(&stub_path)?;
        let stub = stub
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("AGE-PLUGIN-YUBIKEY-"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the YubiKey stub at {} contains no identity line; the wallet cannot \
                     be opened without it",
                    stub_path.display()
                )
            })?;

        // The typed string is the PIV PIN. Decryption happens on the card.
        let identity = crate::yubi::decrypt_with_yubikey(
            &std::fs::read(crate::paths::identity_path()?)?,
            stub,
            &password,
        )?;
        let identity = String::from_utf8(identity)
            .map_err(|e| anyhow::anyhow!("decrypted identity is not valid text: {e}"))?;

        // Same structural check the password path makes: decryption succeeding is the
        // proof, but confirm the plaintext really is an age identity so a corrupt file
        // cannot masquerade as a successful unlock.
        use std::str::FromStr;
        let key_line = identity
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-"))
            .ok_or_else(|| anyhow::anyhow!("decrypted identity contains no age secret key"))?;
        age::x25519::Identity::from_str(key_line)
            .map_err(|e| anyhow::anyhow!("decrypted identity is malformed: {}", e))?;

        // Everything downstream reads WALLET_PASSWORD to re-open the identity file. In
        // YubiKey mode the PIN plays that role, and `decrypt_identity` routes on the same
        // stub check, so the two stay consistent.
        password.clone()
    } else {
        verify_wallet_passphrase(&password)?;
        password.clone()
    };

    // W5, 2026-08-11. This block previously read:
    //
    //     // BYPASS IDENTITY DECRYPTION CHECK TO FORCE AUTO-RECOVERY
    //     // We already verified this password is correct for the database.
    //     println!("Bypassing identity decryption check for auto-recovery.");
    //
    // The second line was not true — nothing verified the password anywhere.
    // Any string unlocked the wallet, so the unlock screen was decoration.
    // The bypass existed to reach the "auto-recovery" code below it, which has
    // also been removed; see the note further down.
    //
    // 2026-09-27: the verification happens INSIDE each branch above. The password branch
    // calls `verify_wallet_passphrase`; the YubiKey branch proves the PIN by decrypting the
    // identity on the device, which is the only check that file admits. A trailing
    // `verify_wallet_passphrase(&final_password)` stood here and ran for both, so a YubiKey
    // wallet whose key had just opened the identity was refused with "wallet identity is
    // not passphrase-encrypted". Found by the v0.7.0 A4 refusal demo
    // (`examples/yubikey_refusal.rs`), the first time a YubiKey wallet was unlocked through
    // this function.
    *WALLET_PASSWORD.lock().unwrap() = Some(final_password);

    // The "AUTO-NULLIFIER RECOVERY" block that stood here has been deleted.
    //
    // It looked for notes with a NULL nullifier, rewound the wallet to just
    // before the earliest one, and — whether or not the rewind succeeded —
    // executed:
    //
    //     DELETE FROM scan_queue;
    //     INSERT INTO scan_queue (block_range_start, block_range_end, priority)
    //       VALUES (safe_height, 4000000, 10);
    //
    // That fabricated a chain tip of 4,000,000. It is why the wallet reported a
    // chain height of 3,999,999, and `grpc_sync.rs:70` had to delete the row
    // before it could scan. Its SQL fallback also deleted rows from `blocks`,
    // `transactions` and `orchard_received_notes` directly, which is precisely
    // the kind of tape job the project guardrails prohibit.
    //
    // A NULL nullifier means the wallet scanned a chain it can no longer extend.
    // The sync engine now diagnoses that properly as a continuity error and
    // rewinds by a measured amount (see SYNC_RETREAT_STEPS), so the symptom this
    // block chased no longer needs chasing.

    // Start the local background sync engine.
    start_sync_engine();

    Ok(())
}

use zcash_client_backend::proto::compact_formats::CompactBlock as BackendCompactBlock;

pub struct MemoryBlockSource(Vec<BackendCompactBlock>);

impl zcash_client_backend::data_api::chain::BlockSource for MemoryBlockSource {
    type Error = std::convert::Infallible;

    fn with_blocks<F, WalletErrT>(
        &self,
        from_height: Option<BlockHeight>,
        _limit: Option<usize>,
        mut with_block: F,
    ) -> Result<(), zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>>
    where
        F: FnMut(BackendCompactBlock) -> Result<(), zcash_client_backend::data_api::chain::error::Error<WalletErrT, Self::Error>>,
    {
        for block in &self.0 {
            if let Some(fh) = from_height {
                if block.height() < fh {
                    continue;
                }
            }
            with_block(block.clone())?;
        }
        Ok(())
    }
}

use std::sync::atomic::AtomicBool;
static SYNC_ENGINE_STARTED: AtomicBool = AtomicBool::new(false);

// ── Sync engine tuning (W4) ────────────────────────────────────────────────
//
// Ported from ironwood_shield/src/grpc_sync.rs, which synced this wallet to tip
// and built 133 Ironwood checkpoints. The old engine differed in four ways that
// each mattered:
//
//   1. It fetched 1000 blocks in one GetBlockRange with no retry. One dropped
//      stream produced nothing, silently. 200-block chunks with reconnect
//      survived zaino rebuilding its index underneath the scan.
//   2. It fetched a single TreeState for the whole run. The anchor must be the
//      frontier at chunk_start - 1, per chunk.
//   3. It never called update_chain_tip, so the wallet's notion of the tip never
//      advanced — which is what caps the shield anchor height.
//   4. It swallowed every error in `if let Ok(..)`, so a permanent failure was
//      indistinguishable from success.

/// Blocks per GetBlockRange call.
const SYNC_CHUNK: u32 = 200;

/// Attempts per chunk before giving up; the client is reconnected between tries.
const SYNC_FETCH_ATTEMPTS: u32 = 4;

/// Chunks per pass, so status is refreshed rather than blocking on a full sync.
const SYNC_CHUNKS_PER_PASS: u32 = 10;

/// How far to rewind on successive continuity failures.
///
/// A `PrevHashMismatch` means the wallet's stored block hash disagrees with the
/// chain — either an ordinary reorg (shallow) or, as here, scan data inherited
/// from a pre-Ironwood scanner that followed a different chain (deep). Retreat
/// gently first so a one-block reorg does not discard thousands of scanned
/// blocks, then escalate.
pub(crate) const SYNC_RETREAT_STEPS: [u32; 5] = [10, 100, 1_000, 10_000, 100_000];

/// Outcome of one sync pass.
pub(crate) enum SyncStep {
    /// Scanned up to this height; more remains.
    Advanced(u32),
    /// Wallet is level with the indexer at this height.
    AtTip(u32),
    /// The wallet's chain view diverges here and must be truncated below it.
    Continuity(BlockHeight),
}

pub fn start_sync_engine() {
    if SYNC_ENGINE_STARTED.swap(true, Ordering::SeqCst) {
        println!("[sync] engine already running; ignoring duplicate start");
        return;
    }

    tokio::spawn(async move {
        // A spawned task returns `()`, so `?` is unavailable here. Refuse loudly
        // rather than syncing into a guessed path: if HOME is unset the old code
        // built `/.AppVault/data/wallet.db` at the filesystem root and reported an
        // empty balance, which reads as lost funds. Not starting is the safe failure.
        let db_path = match crate::paths::as_string::wallet_db_path() {
            Ok(p) => p,
            Err(e) => {
                println!("[sync] REFUSING to start: {}", e);
                SYNC_ENGINE_STARTED.store(false, Ordering::SeqCst);
                return;
            }
        };

        println!("[sync] starting Zecboat sync engine (gRPC)");

        // W7: the schema must be current before any write, or the first
        // update_chain_tip fails with `no such table: ironwood_tree_shards`.
        // Retried rather than fatal: the wallet may not exist yet on first run.
        loop {
            match ensure_wallet_migrated(&db_path) {
                Ok(()) => break,
                Err(e) => {
                    println!("[wallet] not ready to migrate ({}); retrying in 5s", e);
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }

        // After migration, before the first sync write. WAL is persistent, so this is
        // the only place it needs doing. Failure is logged, not fatal.
        if let Err(e) = ensure_wal_mode(&db_path) {
            println!("[wallet] could not enable WAL mode ({}); continuing without it", e);
        }

        // Index into SYNC_RETREAT_STEPS; escalates while continuity keeps failing
        // and resets as soon as a pass scans cleanly.
        let mut retreat: usize = 0;

        loop {
            // B8: a user-requested rescan, applied between passes so it never races a scan.
            let requested = RESCAN_REQUEST.lock().unwrap().take();
            if let Some(h) = requested {
                match truncate_wallet_to(&db_path, h) {
                    Ok(actual) => {
                        println!("[sync] user rescan: rewound to {} (asked {})", u32::from(actual), h);
                        WALLET_HEIGHT.store(u32::from(actual) as u64, Ordering::Relaxed);
                        retreat = 0;
                    }
                    Err(e) => println!("[sync] user rescan: rewind to {} failed: {}", h, e),
                }
            }
            match sync_pass(&db_path).await {
                Ok(SyncStep::AtTip(height)) => {
                    retreat = 0;
                    WALLET_HEIGHT.store(height as u64, Ordering::Relaxed);
                    // At the tip, new blocks arrive about every 75s.
                    sleep(Duration::from_secs(30)).await;
                }
                Ok(SyncStep::Advanced(height)) => {
                    retreat = 0;
                    WALLET_HEIGHT.store(height as u64, Ordering::Relaxed);
                    println!("[sync] advanced to {}", height);
                    // More to do: continue promptly, but yield briefly.
                    sleep(Duration::from_millis(200)).await;
                }
                Ok(SyncStep::Continuity(at)) => {
                    // The wallet's chain view diverges from the indexer's. Rewind
                    // below the divergence and rescan. Without this the engine
                    // retries the same block forever, which is exactly what left
                    // this wallet stuck at 3,428,291.
                    let step = SYNC_RETREAT_STEPS[retreat.min(SYNC_RETREAT_STEPS.len() - 1)];
                    let target = u32::from(at).saturating_sub(step);

                    println!(
                        "[sync] chain divergence at {}; rewinding {} blocks to {} and rescanning",
                        u32::from(at),
                        step,
                        target
                    );

                    match truncate_wallet_to(&db_path, target) {
                        Ok(actual) => println!("[sync] rewound to {}", u32::from(actual)),
                        Err(e) => println!("[sync] rewind failed: {}", e),
                    }

                    if retreat + 1 < SYNC_RETREAT_STEPS.len() {
                        retreat += 1;
                    } else {
                        // Exhausted the ladder: something is wrong beyond a reorg.
                        // Keep retrying at maximum depth rather than spinning fast.
                        println!(
                            "[sync] still diverging after rewinding {} blocks. The wallet may \
                             need a rescan from its birthday.",
                            SYNC_RETREAT_STEPS[SYNC_RETREAT_STEPS.len() - 1]
                        );
                        sleep(Duration::from_secs(30)).await;
                    }
                }
                Err(e) => {
                    // Surfaced, not swallowed. The old engine hid these.
                    println!("[sync] pass failed: {:#}", e);
                    sleep(Duration::from_secs(15)).await;
                }
            }
        }
    });
}

/// Satisfy the wallet's outstanding transaction-data requests (W9).
///
/// **Why this exists.** Compact blocks carry only shielded commitments —
/// transparent inputs and outputs are stripped out. So `scan_cached_blocks` can
/// never learn that a transparent UTXO was spent, and a wallet that relies on
/// scanning alone keeps counting spent transparent funds forever. That is
/// exactly what happened here: the wallet reported 0.0998 ZEC when it held
/// 0.04985, double-counting a 5,000,000-zat UTXO that the shield at height
/// 3,430,966 had already consumed into the Ironwood note.
///
/// The backend solves this by *asking*. `transaction_data_requests()` returns
/// work the wallet cannot do for itself, and the caller answers each item using
/// lightwalletd RPCs over the channel we already hold:
///
/// | Request | Answered with |
/// |---|---|
/// | `TransactionsInvolvingAddress` | `GetTaddressTxids`, then `decrypt_and_store_transaction` per tx, or `notify_address_checked` when none |
/// | `Enhancement(txid)` | `GetTransaction` → `decrypt_and_store_transaction` |
/// | `GetStatus(txid)` | `GetTransaction` → `set_transaction_status` |
///
/// Everything is recorded through the data API. Writing to
/// `transparent_received_output_spends` directly would be a tape job, and would
/// also skip the note/nullifier bookkeeping the backend does alongside it.
///
/// Returns the number of requests serviced.
async fn service_transaction_data_requests(
    db_path: &str,
    client: &mut lightwallet::compact_tx_streamer_client::CompactTxStreamerClient<
        tonic::transport::Channel,
    >,
    chain_tip: u32,
) -> Result<usize> {
    use zcash_client_backend::data_api::{
        TransactionDataRequest, TransactionStatus, WalletRead, WalletWrite,
    };
    use zcash_client_backend::encoding::AddressCodec;
    use zcash_primitives::transaction::Transaction;

    let requests = {
        let wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
            .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
        wallet_db
            .transaction_data_requests()
            .map_err(|e| anyhow::anyhow!("could not read transaction data requests: {:?}", e))?
    };

    if requests.is_empty() {
        return Ok(0);
    }

    // Fetch a whole transaction by txid. The node returns it with the height it
    // was mined at, or a sentinel when it is only in the mempool.
    async fn fetch_tx(
        client: &mut lightwallet::compact_tx_streamer_client::CompactTxStreamerClient<
            tonic::transport::Channel,
        >,
        txid: zcash_primitives::transaction::TxId,
    ) -> Option<(Vec<u8>, u64)> {
        let filter = lightwallet::TxFilter {
            block: None,
            index: 0,
            hash: txid.as_ref().to_vec(),
        };
        let raw = client
            .get_transaction(tonic::Request::new(filter))
            .await
            .ok()?
            .into_inner();
        Some((raw.data, raw.height))
    }

    let mut serviced = 0usize;

    for request in requests {
        match request {
            TransactionDataRequest::TransactionsInvolvingAddress(req) => {
                let addr = req.address().encode(&MainNetwork);
                let start = u32::from(req.block_range_start());
                let end = req.block_range_end().map(u32::from).unwrap_or(chain_tip + 1);

                // THE PRIVACY GATE. Off by default.
                //
                // Everything else this wallet does is private from the server:
                // shielded scanning pulls compact blocks and trial-decrypts them
                // locally, so lightwalletd never learns which notes are yours.
                //
                // `GetTaddressTxids` cannot work that way. It sends the address in
                // cleartext and asks what touched it — telling the server **this
                // address is mine**, and tying it to your IP and to the timing of
                // every other request in the same session. One such call undoes,
                // for that address, the privacy the rest of the wallet maintains.
                //
                // Older wallets carry transparent receivers on all 25 of their
                // derived addresses (see generate_new_address), so without this gate
                // the wallet volunteers a list of addresses the user never chose to
                // expose, on every sync, forever.
                //
                // `notify_address_checked` marks the range examined so the backend
                // advances instead of re-requesting for eternity. The cost is real
                // and worth stating: **transparent funds sent to this wallet will
                // not be seen while the gate is closed.** That is the trade — no
                // silent scanning of addresses nobody asked to expose.
                if !transparent_scan_enabled() {
                    let as_of = BlockHeight::from_u32(end.saturating_sub(1));
                    let mut wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
                        .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
                    wallet_db
                        .notify_address_checked(req, as_of)
                        .map_err(|e| anyhow::anyhow!("notify_address_checked failed: {:?}", e))?;
                    serviced += 1;
                    continue;
                }

                let filter = lightwallet::TransparentAddressBlockFilter {
                    address: addr.clone(),
                    range: Some(lightwallet::BlockRange {
                        start: Some(lightwallet::BlockId { height: start as u64, hash: vec![] }),
                        end: Some(lightwallet::BlockId {
                            height: end.saturating_sub(1) as u64,
                            hash: vec![],
                        }),
                        pool_types: vec![],
                    }),
                };

                // Collect first: decrypt_and_store_transaction is synchronous and
                // needs the wallet open, which must not straddle an await.
                let mut found: Vec<(Vec<u8>, u64)> = Vec::new();
                match client.get_taddress_txids(tonic::Request::new(filter)).await {
                    Ok(response) => {
                        let mut stream = response.into_inner();
                        while let Ok(Some(raw)) = stream.message().await {
                            found.push((raw.data, raw.height));
                        }
                    }
                    Err(e) => {
                        println!("[w9] GetTaddressTxids({}) failed: {}", addr, e);
                        continue;
                    }
                }

                let mut wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
                    .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;

                if found.is_empty() {
                    // Nothing involving this address in the range. Tell the backend
                    // so it advances max_observed_unspent_height instead of asking
                    // again forever.
                    let as_of = BlockHeight::from_u32(end.saturating_sub(1));
                    wallet_db
                        .notify_address_checked(req, as_of)
                        .map_err(|e| anyhow::anyhow!("notify_address_checked failed: {:?}", e))?;
                    println!("[w9] {} — no transactions in [{},{}); checked to {}", addr, start, end, u32::from(as_of));
                } else {
                    let n = found.len();
                    for (data, height) in found {
                        // The same rule as the enhancement below: a server's height 0 is "no
                        // height", not block 0. A transparent transaction is not in the
                        // shielded scan, so there is no known block to fall back on: skipped.
                        let h = match height {
                            0 => {
                                println!("[w9] a transaction for {} skipped: the server reports no height for it", addr);
                                continue;
                            }
                            s => BlockHeight::from_u32(s as u32),
                        };
                        let tx = match Transaction::read(&data[..], zcash_protocol::consensus::BranchId::for_height(&MainNetwork, h)) {
                            Ok(tx) => tx,
                            Err(e) => {
                                println!("[w9] could not parse a transaction for {}: {}", addr, e);
                                continue;
                            }
                        };
                        if let Err(e) = zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
                            &MainNetwork,
                            &mut wallet_db,
                            &tx,
                            Some(h),
                        ) {
                            println!("[w9] could not store a transaction for {}: {:?}", addr, e);
                        }
                    }
                    println!("[w9] {} — stored {} transaction(s) from [{},{})", addr, n, start, end);
                }
                serviced += 1;
            }

            TransactionDataRequest::Enhancement(txid) => {
                if let Some((data, height)) = fetch_tx(client, txid).await {
                    let mut wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
                        .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
                    // The height the server reports is not relied on. Some servers answer 0 for
                    // a transaction outside their recent window although it is mined (zaino,
                    // seen 2026-10-06 and again 2026-10-10 on zec.rocks for the registry's
                    // transactions, 14,000 blocks old); storing it "mined at 0" fails the
                    // database's height_consistency rule, so the transaction was never stored,
                    // and a collection's close was never read: every registry check of a
                    // collection older than the server's window failed. The wallet's own scan
                    // already knows the block the transaction is in; that height is used.
                    let known = wallet_db.get_tx_height(txid).ok().flatten();
                    let h = match (height, known) {
                        (0, Some(k)) => k,
                        (0, None) => {
                            println!("[w9] enhancement of {} skipped: the server reports no height and the scan has not placed it yet", txid);
                            serviced += 1;
                            continue;
                        }
                        (s, _) => BlockHeight::from_u32(s as u32),
                    };
                    match Transaction::read(
                        &data[..],
                        zcash_protocol::consensus::BranchId::for_height(&MainNetwork, h),
                    ) {
                        Ok(tx) => {
                            if let Err(e) = zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
                                &MainNetwork, &mut wallet_db, &tx, Some(h),
                            ) {
                                println!("[w9] enhancement of {} failed: {:?}", txid, e);
                            }
                        }
                        Err(e) => println!("[w9] could not parse {}: {}", txid, e),
                    }
                } else {
                    // Node does not know it; record that so the request retires.
                    let mut wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
                        .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
                    let _ = wallet_db.set_transaction_status(txid, TransactionStatus::TxidNotRecognized);
                }
                serviced += 1;
            }

            TransactionDataRequest::GetStatus(txid) => {
                let status = match fetch_tx(client, txid).await {
                    Some((_, height)) if height > 0 && height < u64::from(u32::MAX) => {
                        TransactionStatus::Mined(BlockHeight::from_u32(height as u32))
                    }
                    Some(_) => TransactionStatus::NotInMainChain,
                    None => TransactionStatus::TxidNotRecognized,
                };
                let mut wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
                    .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
                wallet_db
                    .set_transaction_status(txid, status)
                    .map_err(|e| anyhow::anyhow!("set_transaction_status failed: {:?}", e))?;
                serviced += 1;
            }

            // Other variants are gated behind features this build does not enable.
            #[allow(unreachable_patterns)]
            _ => {}
        }
    }

    Ok(serviced)
}

/// Bring the wallet database schema up to date, backing it up first.
///
/// W7. `WalletDb::for_path` opens a database but does **not** migrate it, so on
/// the Ironwood crates an un-migrated wallet fails at the first write with
/// `no such table: ironwood_tree_shards`. `init_wallet_db` applies the pending
/// migrations; it is idempotent, so calling it on an already-current database is
/// a no-op.
///
/// **The migration is one-way.** It takes the schema from 29 tables / 48
/// migrations to 45 / 57, adding the `ironwood_*` and `orchard_ironwood_migration_*`
/// families. The previous release of this app — anything on
/// zcash_client_sqlite 0.21 — cannot open the result. Because this wallet holds
/// real funds, a timestamped copy is taken first and never overwritten.
/// Put the wallet database into WAL (write-ahead logging) mode.
///
/// SQLite's default rollback journal allows exactly one writer, and a writer blocks
/// readers. This wallet has at least two writers in normal operation — the sync engine
/// storing scanned blocks, and anything building a transaction — so they collide, and
/// the loser gets `SQLITE_BUSY`. That surfaced as the app appearing to freeze, and as
/// carrier locking failing during a send (see `native_builder.rs`, which now refuses to
/// build rather than proceeding unprotected).
///
/// WAL lets readers and one writer proceed concurrently, which does not eliminate
/// contention but makes it rare rather than routine.
///
/// **The setting is persistent** — SQLite records it in the database header, so this
/// only has to succeed once and every later connection inherits it, including the ones
/// `WalletDb::for_path` opens internally. That is why this is called here rather than
/// being scattered across the several dozen places a connection is opened.
///
/// Non-fatal by design: an older SQLite, or a filesystem that cannot support the shared
/// memory WAL needs (some network mounts), will refuse. The wallet still works in that
/// case, just with the old contention.
/// Move a file out of the way instead of deleting it, returning where it went.
///
/// Three call sites used to do `let _ = std::fs::remove_file(...)` on the wallet database
/// and the encryption identity. Both are irreplaceable, and **either one alone is
/// worthless** — the database holds the encrypted mnemonic and the identity file is the
/// key to it, so losing one loses the wallet as surely as losing both.
///
/// Worse, `let _ =` discarded the result: a failed delete was indistinguishable from a
/// successful one, and creation proceeded either way.
///
/// A user who imports a seed phrase while already holding a funded wallet, or who reaches
/// initialisation by mistake, previously lost that wallet with no recovery unless their own
/// seed was written down elsewhere. Renaming costs a few megabytes and makes the mistake
/// survivable.
///
/// Errors are returned rather than swallowed: if the old wallet cannot be moved aside, the
/// caller must not go on to create a new one on top of it.
fn preserve_replaced_file(path: &str) -> Result<Option<String>> {
    if !std::path::Path::new(path).exists() {
        return Ok(None);
    }

    // Seconds alone are not enough. `rename` onto an existing name replaces it silently on
    // Unix, so two calls inside the same second — a double-submitted wizard button, both
    // Tauri commands being async with no lock between them — moved A to `.replaced-S` and
    // then B to `.replaced-S`, destroying the only copy of A. That is the exact failure
    // this function exists to prevent, occurring inside the function itself.
    //
    // Nanoseconds make the name unique in practice; the guard below makes it certain.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}-{:09}", d.as_secs(), d.subsec_nanos()))
        .unwrap_or_else(|_| "0-000000000".to_string());
    let mut backup = format!("{}.replaced-{}", path, stamp);
    let mut n = 1;
    while std::path::Path::new(&backup).exists() {
        backup = format!("{}.replaced-{}.{}", path, stamp, n);
        n += 1;
    }

    std::fs::rename(path, &backup).map_err(|e| {
        anyhow::anyhow!(
            "refusing to continue: could not move the existing file aside before replacing it \
             ({} -> {}): {}. Continuing would destroy it.",
            path, backup, e
        )
    })?;

    // SQLite's write-ahead log and shared-memory files belong to the database that was just
    // renamed. Leaving one beside a NEW file of the same name lets SQLite replay one
    // database's log into another, which corrupts the new wallet on first open.
    //
    // These were previously renamed with `let _ =`, discarding the result. That is the same
    // defect this whole function exists to remove, and it was more dangerous here than
    // anywhere else: enabling WAL is what created these files in the first place, so the
    // risk was introduced by an earlier fix in this same session.
    //
    // A sidecar that cannot be moved must not be left behind, so failing to move it is a
    // hard error.
    //
    // The unwind has to put back EVERY file that moved, not just the database. A `-wal`
    // holds committed transactions that have not yet been folded into the main file, so
    // restoring `wallet.db` while its log stayed behind with the backup silently discards
    // them — the same class of quiet data loss this function exists to prevent, just moved
    // one step along. So each successful move is recorded and undone in reverse.
    let mut moved: Vec<String> = Vec::new();

    for suffix in ["-wal", "-shm", "-journal"] {
        let side = format!("{}{}", path, suffix);
        if !std::path::Path::new(&side).exists() {
            continue;
        }
        if let Err(e) = std::fs::rename(&side, format!("{}{}", backup, suffix)) {
            // Undo, newest first: the sidecars that did move, then the database itself.
            let mut restored = true;
            for done in moved.iter().rev() {
                if std::fs::rename(format!("{}{}", backup, done), format!("{}{}", path, done))
                    .is_err()
                {
                    restored = false;
                }
            }
            if std::fs::rename(&backup, path).is_err() {
                restored = false;
            }

            // Never claim a clean restore that did not happen — that would send the user
            // away believing their wallet is where they left it.
            let tail = if restored {
                "The existing wallet has been left as it was; close any program using it and \
                 try again."
                    .to_string()
            } else {
                format!(
                    "The wallet could NOT be put back cleanly. Nothing was deleted — every \
                     file is present under the name {} or {}. Do not create or import a \
                     wallet at this path until they have been reunited.",
                    path, backup
                )
            };

            return Err(anyhow::anyhow!(
                "refusing to continue: {}{} could not be moved aside ({}). Left in place it \
                 would be replayed into the new database and corrupt it. {}",
                path, suffix, e, tail
            ));
        }
        moved.push(suffix.to_string());
    }

    println!("[wallet] existing file preserved: {}", backup);
    Ok(Some(backup))
}

/// Undo a [`preserve_replaced_file`] move: put `backup` (and its sidecars) back at `path`.
///
/// Used only on an unwind, where a caller has already replaced a file and then failed. It
/// is deliberately total rather than fail-fast: every file it can put back, it puts back,
/// and it reports whether all of them made it. Stopping at the first error would strand
/// the rest, and a half-restored wallet directory is the state this exists to avoid.
///
/// `-wal` is why the sidecars are not optional. It holds committed transactions that have
/// not been folded into the main file, so restoring `wallet.db` alone silently discards
/// them.
/// One file this operation replaced: where it lives, and the `.replaced-<stamp>` copy of
/// what was there before, if anything was.
pub(crate) struct Replaced {
    pub path: String,
    pub kept: Option<String>,
}

/// Put back everything a failed wallet replacement moved aside.
///
/// Three functions replace a wallet in place — `initialize_new_wallet`,
/// `recover_wallet_from_seed` and `import_wallet` — and each moves files aside and then does
/// fallible work. Only `recover_wallet_from_seed` had an unwind; the other two left the
/// directory in the state hardest for a user to reason about: a new identity beside no
/// database, where the old password opens nothing and the new one opens nothing worth
/// opening. Nothing is lost — the originals are under `.replaced-<stamp>` — but recovering
/// them means knowing that convention and renaming files by hand, which is not a bar to set
/// for someone whose wallet creation just failed.
///
/// Written once here rather than copied a third time, for the same reason `decrypt_identity`
/// and `phrase_to_mnemonic` exist: a rule in one place cannot be half-applied.
///
/// **Order matters.** Items are unwound in reverse, so a file replaced last is put back
/// first — the mirror of how they were replaced.
///
/// **A `None` in `kept` is not "nothing to do".** It means no previous file existed, so the
/// NEW one must still be removed: an identity with no wallet beside it reads as an
/// initialised install and sends `check_initialization_status` the wrong answer.
///
/// Returns an error that says which of the two happened, because "nothing was changed" and
/// "it could not be put back" call for very different responses from the user.
pub(crate) fn unwind_replacements(items: &[Replaced], e: anyhow::Error, data_dir: &str, what: &str) -> anyhow::Error {
    let mut clean = true;

    for item in items.iter().rev() {
        // Remove what we wrote. SQLite sidecars belong to the database that was renamed:
        // a `-wal` left beside a restored file is replayed into it on first open.
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{}", item.path, suffix));
        }
        // Only if we actually moved one. When `preserve_replaced_file` is what failed,
        // `kept` is None and the original is still at `path` untouched — removing it above
        // would be the exact disaster this exists to prevent, so that case is why the
        // caller must record `kept` from preserve_replaced_file's own return value.
        if let Some(backup) = item.kept.as_deref() {
            if !restore_preserved(&item.path, backup) {
                clean = false;
            }
        }
    }

    if clean {
        anyhow::anyhow!(
            "{what} failed and nothing was changed: {e}. The wallet that was here before is \
             back in place and your old password still opens it."
        )
    } else {
        anyhow::anyhow!(
            "{what} failed ({e}), and the previous wallet could NOT be put back cleanly. \
             Nothing was deleted — every file is present in {data_dir} either under its own \
             name or with a `.replaced-<timestamp>` suffix. Do not create or recover another \
             wallet at this path until they have been reunited."
        )
    }
}

fn restore_preserved(path: &str, backup: &str) -> bool {
    let mut ok = std::fs::rename(backup, path).is_ok();
    for suffix in ["-wal", "-shm", "-journal"] {
        let side = format!("{}{}", backup, suffix);
        if std::path::Path::new(&side).exists()
            && std::fs::rename(&side, format!("{}{}", path, suffix)).is_err()
        {
            ok = false;
        }
    }
    ok
}

fn ensure_wal_mode(db_path: &str) -> Result<()> {
    let conn = rusqlite::Connection::open(db_path)
        .map_err(|e| anyhow::anyhow!("could not open wallet database: {}", e))?;

    // Returns the mode actually in force, which is not necessarily the one requested.
    let mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
        .map_err(|e| anyhow::anyhow!("could not set journal mode: {}", e))?;

    if mode.eq_ignore_ascii_case("wal") {
        println!("[wallet] journal mode: WAL");
    } else {
        println!("[wallet] journal mode: {} (WAL refused; contention will be higher)", mode);
    }

    // NOT a busy_timeout.
    //
    // An earlier version of this function set `conn.busy_timeout(5s)` here and claimed it
    // would ride out sync writes. It did nothing at all: `busy_timeout` is per-connection
    // and is not recorded in the database file, and this connection is dropped on the next
    // line. Every other connection in the process — the deadpool pool, and the ones
    // `WalletDb::for_path` opens inside `zcash_client_sqlite` — never saw it.
    //
    // Removed rather than moved, because there is nowhere correct to move it to: the
    // library's own connections are not reachable from here. WAL itself is the fix that
    // works, and it is persistent, which is why it is the only thing this function does.
    //
    // If SQLITE_BUSY still shows up in practice, the places to address it are
    // `db.rs`'s pool configuration and the call sites that hold a connection longer than
    // they need to — not a pragma on a throwaway handle.
    Ok(())
}

fn ensure_wallet_migrated(db_path: &str) -> Result<()> {
    use zcash_client_backend::data_api::WalletRead;

    // Cheap check: if the wallet already has the Ironwood tables there is
    // nothing to do, and no reason to touch the disk.
    {
        let conn = rusqlite::Connection::open(db_path)
            .map_err(|e| anyhow::anyhow!("could not open wallet database: {}", e))?;
        let present: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ironwood_tree_shards'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if present > 0 {
            return Ok(());
        }
    }

    // One-way migration on a real-funds wallet: keep a pre-migration copy.
    let backup = format!("{}.pre-ironwood", db_path);
    if !std::path::Path::new(&backup).exists() {
        crate::paths::copy_private(db_path, &backup)
            .map_err(|e| anyhow::anyhow!("could not back up the wallet before migrating: {}", e))?;
        println!("[wallet] backed up pre-Ironwood wallet to {}", backup);
    }

    println!("[wallet] migrating the wallet database to the Ironwood schema (one-way)");
    let mut wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
        .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
    zcash_client_sqlite::wallet::init::init_wallet_db(&mut wallet_db, None)
        .map_err(|e| anyhow::anyhow!("wallet migration failed: {:?}", e))?;

    let scanned = wallet_db
        .chain_height()
        .ok()
        .flatten()
        .map(|h| u32::from(h).to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("[wallet] migration complete; wallet chain height {}", scanned);

    Ok(())
}

/// Rewind the wallet to `height` so a divergent range can be rescanned.
pub(crate) fn truncate_wallet_to(db_path: &str, height: u32) -> Result<BlockHeight> {
    use zcash_client_backend::data_api::WalletWrite;
    let mut wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
        .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
    wallet_db
        .truncate_to_height(BlockHeight::from_u32(height))
        .map_err(|e| anyhow::anyhow!("truncate to {} failed: {:?}", height, e))
}

/// One bounded unit of sync work.
///
/// Scans at most `SYNC_CHUNKS_PER_PASS * SYNC_CHUNK` blocks and returns, so the
/// caller can refresh status and react to divergence rather than blocking on a
/// full sync.
pub(crate) async fn sync_pass(db_path: &str) -> Result<SyncStep> {
    sync_pass_with(db_path, false).await
}

/// A pass that gives way to the wallet's own sync: short (three chunks), and paused whenever
/// the wallet is behind the tip, so its small requests get through a node that serves one
/// stream at a time (a zainod in pass-through mode, 2026-10-10: a Check held the wallet at
/// "18 to scan, no progress for 18 min"). For the registry read and the collection audits.
pub(crate) async fn sync_pass_polite(db_path: &str) -> Result<SyncStep> {
    sync_pass_with(db_path, true).await
}

async fn sync_pass_with(db_path: &str, polite: bool) -> Result<SyncStep> {
    use zcash_client_backend::data_api::WalletWrite;

    use zcash_client_backend::data_api::WalletRead;

    // The wallet database must exist and be initialised before scanning.
    {
        let conn = rusqlite::Connection::open(db_path)
            .map_err(|e| anyhow::anyhow!("could not open wallet database: {}", e))?;
        let initialised: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='accounts'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        if initialised == 0 {
            anyhow::bail!("wallet database is not initialised yet");
        }
    }

    let endpoint = grpc_endpoint();
    let mut client =
        lightwallet::compact_tx_streamer_client::CompactTxStreamerClient::connect(endpoint.clone())
            .await
            .map_err(|e| anyhow::anyhow!("could not reach the node at {}: {}", endpoint, e))?;

    let tip = client
        .get_lightd_info(tonic::Request::new(lightwallet::Empty {}))
        .await
        .map_err(|e| anyhow::anyhow!("GetLightdInfo failed: {}", e))?
        .into_inner()
        .block_height as u32;
    let chain_tip = tip;

    // Tell the wallet where the chain ends. This is also what refreshes the scan
    // queue, so it must happen before asking what to scan.
    {
        let mut wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
            .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
        wallet_db
            .update_chain_tip(BlockHeight::from_u32(tip))
            .map_err(|e| anyhow::anyhow!("update_chain_tip({}) failed: {:?}", tip, e))?;
    }

    // ── What to scan next ───────────────────────────────────────────────────
    //
    // 2026-08-13: this used to compute `local_height = MAX(height) FROM blocks`
    // and scan forward from there, returning `AtTip` as soon as that reached the
    // chain tip. That is wrong in a way that is invisible until you try to spend:
    // `MAX(height)` is the HIGHEST scanned block, not proof that everything below
    // it was scanned. Any gap underneath — for instance the one W4's divergence
    // recovery leaves when it rewinds and rescans *forward* — was skipped
    // permanently, because the engine never looked below the maximum again.
    //
    // The symptom was a wallet that reported itself at the tip while holding a
    // 140-block hole at [3,428,143 .. 3,428,283), so no witness could be built
    // and a spend failed with `InsufficientFunds { available: 0 }` despite a
    // visible balance.
    //
    // `suggest_scan_ranges()` is the backend's answer to "what still needs
    // scanning", already ordered by priority — `Verify` ranges first, which must
    // precede everything else to avoid continuity errors after a reorg.
    let ranges = {
        let wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
            .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
        wallet_db
            .suggest_scan_ranges()
            .map_err(|e| anyhow::anyhow!("could not read suggested scan ranges: {:?}", e))?
    };

    let Some(range) = ranges.first() else {
        // Genuinely nothing left to scan. Transparent spends are invisible to
        // compact-block scanning, so this is where they get resolved (W9).
        match service_transaction_data_requests(db_path, &mut client, tip).await {
            Ok(n) if n > 0 => println!("[w9] serviced {} transaction data request(s)", n),
            Ok(_) => {}
            Err(e) => println!("[w9] request servicing failed: {:#}", e),
        }
        return Ok(SyncStep::AtTip(tip));
    };

    let range_start = u32::from(range.block_range().start);
    let range_end = u32::from(range.block_range().end); // exclusive
    let outstanding: usize = ranges.iter().map(|r| r.len()).sum();
    println!(
        "[sync] {} range(s) outstanding ({} blocks); scanning [{}..{}) at {:?}",
        ranges.len(), outstanding, range_start, range_end, range.priority()
    );

    let mut cur = range_start;
    let mut scanned_to = range_start.saturating_sub(1);
    let tip = range_end.saturating_sub(1); // bound this pass to the chosen range

    // A polite pass takes the node in 50-block pieces, three per pass, and before each piece
    // waits as long as the wallet is behind the tip (three minutes at most, so a wallet whose
    // own loop is stuck cannot hold the registry forever). A zainod in pass-through mode
    // serves one stream at a time and takes longer than a short wait to deliver a 200-block
    // piece, so a 15-second wait never let the wallet's seven blocks through (2026-10-10).
    let chunks = if polite { 3 } else { SYNC_CHUNKS_PER_PASS };
    let chunk = if polite { 50 } else { SYNC_CHUNK };
    for _ in 0..chunks {
        if cur > tip {
            break;
        }
        if polite {
            let mut waited = 0u32;
            while waited < 240 && (WALLET_HEIGHT.load(Ordering::Relaxed) as u32) + 1 < chain_tip {
                sleep(Duration::from_millis(750)).await;
                waited += 1;
            }
        }
        let end = std::cmp::min(cur + chunk - 1, tip);

        // The commitment-tree frontier as of the block before this chunk. Must be
        // fetched per chunk; one tree state for a whole run is wrong.
        let chain_state = client
            .get_tree_state(tonic::Request::new(lightwallet::BlockId {
                height: (cur - 1) as u64,
                hash: vec![],
            }))
            .await
            .map_err(|e| anyhow::anyhow!("GetTreeState({}) failed: {}", cur - 1, e))?
            .into_inner()
            .to_chain_state()
            .map_err(|e| anyhow::anyhow!("tree state at {} is unusable: {:?}", cur - 1, e))?;

        // Fetch with retry, reconnecting between attempts. A broken stream is
        // normal while the indexer is busy and must not abort the sync.
        // The loop yields the fetched blocks rather than assigning into an outer
        // binding, so there is no throwaway Vec allocated before the first try.
        let mut attempt = 0;
        let blocks = loop {
            attempt += 1;
            let range = lightwallet::BlockRange {
                start: Some(lightwallet::BlockId { height: cur as u64, hash: vec![] }),
                end: Some(lightwallet::BlockId { height: end as u64, hash: vec![] }),
                pool_types: vec![],
            };

            let fetched: Result<Vec<_>> = async {
                let mut stream = client
                    .get_block_range(tonic::Request::new(range))
                    .await
                    .map_err(|e| anyhow::anyhow!("GetBlockRange failed: {}", e))?
                    .into_inner();
                let mut v = Vec::new();
                while let Some(block) = stream
                    .message()
                    .await
                    .map_err(|e| anyhow::anyhow!("block stream broke: {}", e))?
                {
                    v.push(block);
                }
                Ok(v)
            }
            .await;

            match fetched {
                Ok(v) => break v,
                Err(e) if attempt < SYNC_FETCH_ATTEMPTS => {
                    println!("[sync] chunk [{},{}] attempt {} failed: {}; reconnecting", cur, end, attempt, e);
                    client = lightwallet::compact_tx_streamer_client::CompactTxStreamerClient::connect(
                        endpoint.clone(),
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("reconnect failed: {}", e))?;
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "chunk [{},{}] failed after {} attempts: {}",
                        cur, end, attempt, e
                    ))
                }
            }
        };

        if blocks.is_empty() {
            break;
        }

        let count = blocks.len();
        let source = MemoryBlockSource(blocks);

        let mut wallet_db = WalletDb::for_path(db_path, MainNetwork, SystemClock, OsRng)
            .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;

        // Trial decryption of a 2,000-block batch is CPU work for seconds to minutes. Run inline
        // it held an async worker thread, so a second scan on the same runtime (the registry's,
        // or a collection audit's) starved the wallet's own sync: "last batch 754 s ago" with
        // twelve blocks to scan (fresh wallet on el5353, 2026-10-10). block_in_place hands the
        // thread to the blocking pool for the duration; the runtime is multi-threaded.
        let scanned = tokio::task::block_in_place(|| {
            zcash_client_backend::data_api::chain::scan_cached_blocks(
                &MainNetwork,
                &source,
                &mut wallet_db,
                BlockHeight::from_u32(cur),
                &chain_state,
                count,
            )
        });
        match scanned {
            Ok(_) => {
                scanned_to = end;
                cur = end + 1;
            }
            Err(zcash_client_backend::data_api::chain::error::Error::Scan(scan_err))
                if scan_err.is_continuity_error() =>
            {
                // The wallet's view of the chain diverges here. Recoverable, but
                // only by rewinding — reported up so the caller can do that.
                return Ok(SyncStep::Continuity(scan_err.at_height()));
            }
            Err(e) => return Err(anyhow::anyhow!("scan of [{},{}] failed: {:?}", cur, end, e)),
        }
    }

    // Always `Advanced`, never `AtTip`.
    //
    // Finishing the range chosen for this pass says nothing about whether other
    // ranges remain — there may be a lower-priority gap still queued elsewhere.
    // Only an empty `suggest_scan_ranges()` means the wallet is fully scanned,
    // and that case returned `AtTip` at the top of this function.
    //
    // Reporting `AtTip` here would stop the engine while gaps remained, which is
    // the same class of mistake as keying off `MAX(height)` in the first place.
    Ok(SyncStep::Advanced(scanned_to))
}

pub fn lock_wallet() {
    *WALLET_PASSWORD.lock().unwrap() = None;
}

// Global state to mock wallet scanning progress
static WALLET_HEIGHT: AtomicU64 = AtomicU64::new(0);

/// B8 (v0.7.0): a rescan the user asked for, honoured by the sync engine between passes so
/// the truncation never races a scan in progress. `None` when nothing is pending.
pub static RESCAN_REQUEST: Mutex<Option<u32>> = Mutex::new(None);

/// Rescan the wallet from `height` (Settings → Wallet Management → Rescan from Height).
///
/// The wallet is rewound with the backend's own `truncate_to_height`, the same call the
/// engine makes when it detects a chain divergence: transactions above the height are
/// un-mined, blocks and tree state above it are dropped, the scan queue is trimmed, and the
/// engine scans forward again. Note rows are not deleted; the rescan writes each note back
/// with its tree position, which is what a note recorded without one (A5's "unpositioned"
/// bucket) needs.
///
/// Guards: the wallet must be unlocked; the height must be below what the wallet has already
/// scanned (otherwise there is nothing to rescan); a height below the wallet's birthday is
/// raised to the birthday, since no block before it can hold this wallet's notes. The
/// backend may choose a slightly lower height than asked, the nearest retained checkpoint;
/// the message says which.
///
/// If the engine is running the request is queued and applied before its next pass; if it
/// is not, the rewind happens now and scanning resumes when the engine starts.
pub async fn rescan_from_height(height: u32) -> Result<String> {
    if WALLET_PASSWORD.lock().unwrap().is_none() {
        anyhow::bail!("Unlock the wallet before asking for a rescan.");
    }
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let (birthday, scanned) = {
        use zcash_client_backend::data_api::WalletRead;
        let db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, OsRng)
            .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
        let birthday = db.get_wallet_birthday().map_err(|e| anyhow::anyhow!("{e:?}"))?.map(u32::from);
        let scanned = db
            .block_max_scanned()
            .map_err(|e| anyhow::anyhow!("{e:?}"))?
            .map(|m| u32::from(m.block_height()));
        (birthday, scanned)
    };
    let Some(scanned) = scanned else {
        anyhow::bail!("This wallet has not scanned any blocks yet, so there is nothing to rescan.");
    };
    if height >= scanned {
        anyhow::bail!(
            "The wallet has scanned up to block {scanned}; a rescan has to start below that. \
             Enter a lower height."
        );
    }
    let (target, clamped) = match birthday {
        Some(b) if height < b => (b, Some(b)),
        _ => (height, None),
    };
    let clamp_note = clamped
        .map(|b| format!(" (raised from {height} to the wallet's birthday {b}: no earlier block can hold its notes)"))
        .unwrap_or_default();

    if SYNC_ENGINE_STARTED.load(Ordering::SeqCst) {
        *RESCAN_REQUEST.lock().unwrap() = Some(target);
        Ok(format!(
            "Rescan from block {target} queued{clamp_note}. The wallet's height will drop to {target} \
             within a minute and climb back as the sync engine rescans; balances and the \
             \"needs a rescan\" line settle when it reaches the tip again."
        ))
    } else {
        let actual = truncate_wallet_to(&db_path, target)?;
        WALLET_HEIGHT.store(u32::from(actual) as u64, Ordering::Relaxed);
        Ok(format!(
            "Wallet rewound to block {}{clamp_note}. Scanning resumes from there when the sync \
             engine starts.",
            u32::from(actual)
        ))
    }
}

// Global state for Provider/Node URL
//
// Defaults to a public lightwalletd, not loopback. A stranger installing this
// wallet has no node on 127.0.0.1, so a loopback default guarantees
// "Disconnected" with no indication of why.
//
// The default must serve Ironwood (NU6.3). One that does not will report a ZERO
// balance for funds that are really there — indistinguishable, to the person
// looking at it, from having lost their money.
//
// https, not http: the endpoint terminates TLS and tonic is built with
// tls-ring + tls-webpki-roots, so the NoApplicationProtocol panic documented in
// the archive does not apply.
//
// Anyone running their own node overrides this in Settings; the endpoint stays
// user-editable precisely so using Port is a choice, not a requirement. Port can
// see which blocks a client fetches, and the UI should say so.
// `ZECBOAT_PROVIDER` overrides the default at startup. The desktop wallet
// persists its choice in the webview and calls `set_provider_url` on load, so the
// UI still wins there. Headless consumers — Galley, scripts, tests — have no such
// store and were previously pinned to this constant with no way to point them
// anywhere else. That is why Galley could only ever talk to Port.
pub static PROVIDER_URL: Lazy<Mutex<String>> = Lazy::new(|| {
    Mutex::new(
        std::env::var("ZECBOAT_PROVIDER")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            // Default changed from https://port.zecboat.com:9067, which is retired: it
            // still resolves but answers nothing, so any consumer that did not set
            // ZECBOAT_PROVIDER silently had no node at all. zec.rocks is public and
            // serves Ironwood (NU6.3) — a node that does not serve Ironwood reports a
            // ZERO balance for funds that are really there, which reads as data loss.
            .unwrap_or_else(|| "https://zec.rocks:443".to_string()),
    )
});

/// Base URL of the asset registry — where artwork and metadata are fetched from.
///
/// Overridable with `ZECBOAT_REGISTRY`. It was hardcoded to `https://zecboat.com`, which is correct
/// for the production domain and wrong everywhere else: during development the registry lives at
/// `https://ocean.zecboat.com`, and `zecboat.com/collection/...` currently answers 301, so a fresh
/// install shows no artwork at all and gives no clue why.
///
/// Anyone running their own registry points here too, which is the more important reason: a wallet
/// that can only fetch assets from one company's host is not much of an open format.
/// Read a response body up to `max` bytes; more is an error, not a bigger allocation
/// (audit 2026-10-08, Zecboat K).
pub(crate) async fn read_bounded(mut res: reqwest::Response, max: usize) -> anyhow::Result<String> {
    if let Some(n) = res.content_length() {
        if n as usize > max {
            anyhow::bail!("response of {n} bytes exceeds the {max}-byte limit");
        }
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = res.chunk().await? {
        if buf.len() + chunk.len() > max {
            anyhow::bail!("response exceeds the {max}-byte limit");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(buf)?)
}

pub fn registry_base() -> String {
    std::env::var("ZECBOAT_REGISTRY")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://zecboat.com".to_string())
}

pub async fn set_provider_url(new_url: String) -> Result<()> {
    *PROVIDER_URL.lock().unwrap() = new_url;
    Ok(())
}

/// What the backend resolved at startup — `ZECBOAT_PROVIDER` if it was set, the
/// compiled-in default otherwise.
///
/// The UI needs this because it cannot otherwise tell the two apart, and the
/// difference matters: an operator who exported `ZECBOAT_PROVIDER` has already
/// stated which node they trust, and a wizard that offers them a preset list
/// without it will quietly overrule that choice on the one screen where the
/// stakes are highest — the one where a seed phrase is being typed.
pub async fn get_provider_url() -> Result<String> {
    Ok(PROVIDER_URL.lock().unwrap().clone())
}

/// The gRPC endpoint for the currently selected provider.
///
/// Used verbatim. This previously special-cased the Port host, rewriting it to add
/// :9067 because the stored URL carried no port; that host is retired and the rewrite
/// went with it. Every provider — a public lightwalletd, loopback zaino, or one
/// elsewhere on a LAN — must now carry its own port, which is what the Settings
/// presets and the Custom field supply.
pub fn grpc_endpoint() -> String {
    PROVIDER_URL.lock().unwrap().clone()
}

/// The chain tip as reported by the node we are configured to use.
///
/// One implementation for every provider — loopback zaino, LAN zaino, or Port —
/// because they all speak the same lightwalletd gRPC. Replaces two hand-rolled
/// lookups that branched on whether the provider string contained "127.0.0.1",
/// issued HTTP/1 requests to REST paths that only `zecboat_provider` serves, and
/// fell back to hardcoded heights when that failed.
///
/// Deliberately has no fallback: a send built against an invented height is worse
/// than a send that refuses to start.
/// Whether to ask lightwalletd about this wallet's transparent addresses.
///
/// **Off unless `ZECBOAT_TRANSPARENT_SCAN=1`.**
///
/// Enable it only when you have deliberately given someone a `t` address — an
/// exchange withdrawal, or a sender that cannot parse a unified address — and want
/// the wallet to notice the payment. It is a per-run switch rather than a stored
/// setting so that turning it on is a decision, not a state you forget you are in.
///
/// Leaving it off does not lose money: transparent funds sent to an address of
/// yours remain spendable, they are simply not detected until a scan is enabled.
fn transparent_scan_enabled() -> bool {
    matches!(
        std::env::var("ZECBOAT_TRANSPARENT_SCAN").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

pub async fn current_chain_tip() -> Result<u32> {
    let endpoint = grpc_endpoint();
    let mut client =
        lightwallet::compact_tx_streamer_client::CompactTxStreamerClient::connect(endpoint.clone())
            .await
            .map_err(|e| anyhow::anyhow!("could not reach the node at {}: {}", endpoint, e))?;

    let info = client
        .get_lightd_info(tonic::Request::new(lightwallet::Empty {}))
        .await
        .map_err(|e| anyhow::anyhow!("GetLightdInfo failed: {}", e))?
        .into_inner();

    let height = info.block_height as u32;
    if height == 0 {
        anyhow::bail!("the node at {} reported chain height 0", endpoint);
    }
    Ok(height)
}

/// Broadcast a signed transaction over the same gRPC channel used for sync.
///
/// Replaces the previous split path, which posted `sendrawtransaction` to
/// zebrad's JSON-RPC when the provider string happened to contain "127.0.0.1"
/// and otherwise POSTed to `{provider}/api/v1/broadcast`. That branch was wrong
/// for any non-loopback local node: pointing the app at a LAN zaino
/// (a zaino on the LAN) sent broadcasts to an /api/v1/broadcast endpoint that
/// only zecboat_provider serves, so sends failed. Routing through
/// CompactTxStreamer.SendTransaction means one endpoint setting governs sync
/// and broadcast together, with no dependency on zebrad's RPC or on Port.
///
/// lightwalletd semantics: `error_code == 0` means success and the txid is
/// returned in `error_message` (see zaino
/// packages/zaino-state/src/indexer/node_backed_indexer.rs:1431-1439).
/// A non-zero code makes `error_message` the failure reason.
/// Why a broadcast attempt did not return a txid.
///
/// The distinction is the whole point. `Rejected` means the node read the bytes
/// and refused them — retrying sends the same invalid transaction again, so the
/// attempt stops there. `Unreachable` means we never got an answer, which says
/// nothing about whether the node received it; those are the ones worth retrying
/// and the ones that stranded HBD #001 and #002.
enum BroadcastFailure {
    Rejected(String),
    Unreachable(String),
}

/// One attempt at CompactTxStreamer.SendTransaction.
async fn try_broadcast_grpc(tx_bytes: &[u8]) -> std::result::Result<String, BroadcastFailure> {
    let endpoint = grpc_endpoint();

    let mut client =
        lightwallet::compact_tx_streamer_client::CompactTxStreamerClient::connect(endpoint.clone())
            .await
            .map_err(|e| {
                BroadcastFailure::Unreachable(format!("could not reach the node at {}: {}", endpoint, e))
            })?;

    let response = client
        .send_transaction(tonic::Request::new(lightwallet::RawTransaction {
            data: tx_bytes.to_vec(),
            height: 0, // 0 = "in the mempool"; the node assigns the real height
        }))
        .await
        // A tonic transport/status error is a delivery failure, not a verdict on
        // the transaction. P1-10 arrives here as
        // "InternalServerError: error receiving data from backing node".
        .map_err(|e| BroadcastFailure::Unreachable(format!("SendTransaction failed: {}", e)))?
        .into_inner();

    if response.error_code != 0 {
        return Err(BroadcastFailure::Rejected(format!(
            "node rejected the transaction (code {}): {}",
            response.error_code, response.error_message
        )));
    }

    Ok(response.error_message)
}

/// zebrad's JSON-RPC endpoint, used only as a broadcast fallback.
///
/// Defaults to loopback because that is the one address a zebrad RPC port should
/// ever be bound to; Port deliberately keeps `:8232` on 127.0.0.1 and must keep
/// doing so. Override with `ZECBOAT_ZEBRAD_RPC` when the node is on the LAN.
///
/// This is the path ZecBoat Glass used for everything — six stock zebrad
/// JSON-RPC methods, no indexer. Here it is narrowed to the single call that
/// matters when the indexer is the thing that is broken.
pub(crate) fn zebrad_rpc_endpoint() -> String {
    std::env::var("ZECBOAT_ZEBRAD_RPC").unwrap_or_else(|_| "http://127.0.0.1:8232".to_string())
}

/// Hand the signed bytes straight to zebrad, bypassing the indexer entirely.
///
/// Returns the txid zebrad echoes back, or an empty string when zebrad reports
/// it already has the transaction — which is a *success*: it means an earlier
/// attempt did land and only the response was lost. Rebroadcasting is safe for
/// exactly this reason.
async fn try_broadcast_zebrad(raw_tx_hex: &str) -> std::result::Result<String, BroadcastFailure> {
    let endpoint = zebrad_rpc_endpoint();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .no_proxy()
        // A node that answers with a redirect is not the node that was named: a signed
        // transaction goes to the address chosen and nowhere else (gate fifth pass, Finding 3).
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| BroadcastFailure::Unreachable(format!("could not build an HTTP client: {}", e)))?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendrawtransaction",
        "params": [raw_tx_hex],
    });

    let response = client
        .post(&endpoint)
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            BroadcastFailure::Unreachable(format!("could not reach zebrad at {}: {}", endpoint, e))
        })?;

    // Read under a bound, as every other client's reply is (gate sixth pass, Finding 6): a
    // node named by ZECBOAT_ZEBRAD_RPC can be any host.
    let text = read_bounded(response, 256 * 1024).await.map_err(|e| {
        BroadcastFailure::Unreachable(format!("zebrad at {} sent an unreadable reply: {}", endpoint, e))
    })?;
    let parsed: Value = serde_json::from_str(&text).map_err(|e| {
        BroadcastFailure::Unreachable(format!("zebrad at {} sent an unreadable reply: {}", endpoint, e))
    })?;

    if let Some(error) = parsed.get("error") {
        if !error.is_null() {
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("no message")
                .to_string();

            // zebrad already holds it. An earlier attempt reached the mempool and
            // only the acknowledgement was lost — the transaction is fine.
            let lowered = message.to_lowercase();
            if lowered.contains("already in mempool")
                || lowered.contains("already known")
                || lowered.contains("duplicate")
            {
                return Ok(String::new());
            }

            return Err(BroadcastFailure::Rejected(format!(
                "zebrad rejected the transaction: {}",
                message
            )));
        }
    }

    match parsed.get("result").and_then(|r| r.as_str()) {
        Some(txid) => Ok(txid.to_string()),
        None => Err(BroadcastFailure::Unreachable(format!(
            "zebrad at {} returned neither a result nor an error",
            endpoint
        ))),
    }
}

/// Broadcast a signed transaction, retrying and falling back before giving up.
///
/// # Why this is not a single call
///
/// P1-10, three times: the gRPC call returns "error receiving data from backing
/// node" while the transaction itself is perfectly valid — zebrad accepted the
/// identical bytes on the first try, by hand, every time. The inputs are already
/// marked spent by `create_proposed_transactions` at that point, so a lost
/// response looked exactly like a destroyed carrier note and took a manual
/// `sendrawtransaction` over SSH to recover, racing `expiry_height`.
///
/// The order of attempts follows from what each failure means:
///
///   1. gRPC via the configured provider — the normal path.
///   2. gRPC once more after a pause, but **only** for a delivery failure. A
///      rejection is a verdict on the bytes and repeating it is pointless.
///   3. zebrad's own `sendrawtransaction`, which skips the indexer. Both HBD
///      failures were inside zaino, after it had accepted the request; zebrad's
///      log was clean at every one of them.
///
/// Only when all three fail does this return an error — and that error says the
/// transaction is *built and recoverable*, not lost.
pub async fn broadcast_raw_tx(raw_tx_hex: &str) -> Result<String> {
    let tx_bytes = hex::decode(raw_tx_hex)
        .map_err(|e| anyhow::anyhow!("raw transaction is not valid hex: {}", e))?;

    let first = match try_broadcast_grpc(&tx_bytes).await {
        Ok(txid) => return Ok(txid),
        // The node read it and said no. Retrying and falling back would only ask
        // two more nodes to refuse the same bytes.
        Err(BroadcastFailure::Rejected(reason)) => anyhow::bail!("{}", reason),
        Err(BroadcastFailure::Unreachable(reason)) => reason,
    };
    eprintln!("[broadcast] attempt 1 failed: {} — retrying", first);

    sleep(Duration::from_secs(2)).await;

    let second = match try_broadcast_grpc(&tx_bytes).await {
        Ok(txid) => return Ok(txid),
        Err(BroadcastFailure::Rejected(reason)) => anyhow::bail!("{}", reason),
        Err(BroadcastFailure::Unreachable(reason)) => reason,
    };
    eprintln!(
        "[broadcast] attempt 2 failed: {} — falling back to zebrad at {}",
        second,
        zebrad_rpc_endpoint()
    );

    let third = match try_broadcast_zebrad(raw_tx_hex).await {
        Ok(txid) => {
            eprintln!("[broadcast] zebrad accepted the transaction");
            return Ok(txid);
        }
        Err(BroadcastFailure::Rejected(reason)) => anyhow::bail!("{}", reason),
        Err(BroadcastFailure::Unreachable(reason)) => reason,
    };

    // Every route failed to deliver. Say precisely that, because the wallet has
    // still built and stored a valid transaction and the notes are spendable
    // through it and nothing else.
    anyhow::bail!(
        "The transaction was built and signed, but could not be delivered to the network.\n\
         \n\
         It is NOT lost. The signed transaction is stored in the wallet and can be resent \
         until it expires. Use \"Resend pending\" — or leave and reopen the wallet, which \
         checks on startup.\n\
         \n\
         What was tried:\n  \
           node ({}), twice: {}\n  \
           zebrad ({}): {}",
        grpc_endpoint(),
        second,
        zebrad_rpc_endpoint(),
        third
    );
}

/// A transaction the wallet built and signed but never saw confirmed.
#[derive(serde::Serialize, Clone)]
pub struct PendingBroadcast {
    /// Display order, as a block explorer shows it.
    pub txid: String,
    pub expiry_height: u32,
    /// Blocks left before the transaction dies. `None` once expired.
    pub blocks_remaining: Option<u32>,
    pub expired: bool,
    pub size_bytes: usize,
    pub raw_hex: String,
}

/// Signed transactions sitting in the wallet with no `mined_height`.
///
/// This is the query that would have caught P1-10 the first time. `raw` holds the
/// complete signed transaction — 9,166 bytes for each stranded HBD send — and
/// nothing in the wallet had ever looked at it. Both manual rescues were this
/// query plus a `sendrawtransaction`.
///
/// `expiry_height = 0` means the transaction never expires, so it is never stale.
pub fn pending_broadcasts(tip: Option<u32>) -> Result<Vec<PendingBroadcast>> {
    let db_path = crate::paths::as_string::wallet_db_path()?;

    if !std::path::Path::new(&db_path).exists() {
        return Ok(Vec::new());
    }

    // Read-only: this runs on startup and must never be the thing that damages a
    // wallet database it was opened to protect.
    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )?;

    let mut statement = conn.prepare(
        "SELECT hex(txid), COALESCE(expiry_height, 0), hex(raw)
           FROM transactions
          WHERE mined_height IS NULL
            AND raw IS NOT NULL
          ORDER BY id_tx DESC",
    )?;

    let rows = statement.query_map([], |row| {
        let txid_internal: String = row.get(0)?;
        let expiry_height: u32 = row.get::<_, i64>(1)? as u32;
        let raw_hex: String = row.get(2)?;
        Ok((txid_internal, expiry_height, raw_hex))
    })?;

    let mut pending = Vec::new();
    for row in rows {
        let (txid_internal, expiry_height, raw_hex) = row?;

        // SQLite stores txid in internal order; explorers and zebrad show the
        // reverse. Getting this backwards is what made an earlier hand-written
        // `hex(t.txid) = UPPER(?)` comparison match nothing, silently.
        let txid = match hex::decode(&txid_internal) {
            Ok(mut bytes) => {
                bytes.reverse();
                hex::encode(bytes)
            }
            Err(_) => txid_internal.to_lowercase(),
        };

        let (expired, blocks_remaining) = match (tip, expiry_height) {
            (_, 0) => (false, None),                       // never expires
            (Some(tip), expiry) if expiry <= tip => (true, None),
            (Some(tip), expiry) => (false, Some(expiry - tip)),
            (None, _) => (false, None),                    // no tip: do not guess
        };

        pending.push(PendingBroadcast {
            txid,
            expiry_height,
            blocks_remaining,
            expired,
            size_bytes: raw_hex.len() / 2,
            raw_hex: raw_hex.to_lowercase(),
        });
    }

    Ok(pending)
}

/// Startup and pre-send check: is anything built but unconfirmed?
///
/// Fetches the tip so expiry is real rather than assumed. If the node cannot be
/// reached the check still runs — it simply reports without expiry information,
/// because a wallet that cannot see the chain is exactly when this matters most.
pub async fn check_pending_broadcasts() -> Result<Vec<PendingBroadcast>> {
    let tip = current_chain_tip().await.ok();
    pending_broadcasts(tip)
}

/// Release the inputs of transactions that expired without ever being mined.
///
/// # The problem
///
/// When a transaction is built, its inputs are marked spent locally so they cannot be
/// selected again. If it is then never mined — a dropped connection, a node that never
/// relayed it — and its expiry height passes, the network will never accept it. But the
/// wallet still believes those notes are spent. The balance is short, and the only
/// documented recovery was a full rescan taking about an hour.
///
/// # Why this is safe, and the one thing that makes it safe
///
/// **Expiry is consensus-enforced.** Past `expiry_height` a transaction *cannot* be mined
/// by anyone — it is not a matter of probability. So a transaction that is past expiry and
/// absent from the chain is permanently dead, and its inputs were never actually spent.
///
/// The danger is the other case: a transaction that *was* mined shortly before expiry and
/// that this wallet simply has not scanned yet. Releasing those inputs would show funds
/// that are genuinely gone, and the user would build a transaction the network rejects.
///
/// So the node is asked directly, per transaction, and **anything other than a clear
/// "not found" is left alone**:
///
/// * node reports a height  → mined. Leave it; the scanner will catch up.
/// * node cannot be reached → unknown. Leave it.
/// * node says not found    → dead, and only then are the inputs released.
///
/// Erring toward leaving a note marked spent is recoverable by rescan. Erring the other
/// way hands the user a balance that is not real.
pub async fn release_expired_transactions() -> Result<String> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    if !std::path::Path::new(&db_path).exists() {
        return Ok("No wallet database.".to_string());
    }

    let tip = match current_chain_tip().await {
        Ok(t) => t,
        Err(e) => {
            return Ok(format!(
                "Chain tip unavailable ({e}); not releasing anything. Expiry cannot be judged \
                 without knowing the current height."
            ))
        }
    };

    let candidates: Vec<(String, u32)> = {
        let conn = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        let mut st = conn.prepare(
            "SELECT hex(txid), expiry_height
               FROM transactions
              WHERE mined_height IS NULL
                AND expiry_height IS NOT NULL
                AND expiry_height > 0
                AND expiry_height <= ?1",
        )?;
        let rows = st.query_map([tip], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u32)))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()?
    };

    if candidates.is_empty() {
        return Ok("No expired unmined transactions.".to_string());
    }

    let provider = PROVIDER_URL.lock().unwrap().clone();
    let mut client =
        match lightwallet::compact_tx_streamer_client::CompactTxStreamerClient::connect(provider)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                return Ok(format!(
                    "Found {} expired transaction(s) but could not reach a node to confirm they \
                     are absent from the chain ({e}). Nothing released.",
                    candidates.len()
                ))
            }
        };

    let mut released = Vec::new();
    let mut skipped = Vec::new();

    for (txid_hex, expiry) in candidates {
        let mut bytes = match hex::decode(&txid_hex) {
            Ok(b) => b,
            Err(_) => continue,
        };
        // stored internal order; the display order used everywhere else is the reverse
        let display = {
            let mut d = bytes.clone();
            d.reverse();
            hex::encode(d)
        };

        let filter = lightwallet::TxFilter {
            block: None,
            index: 0,
            hash: std::mem::take(&mut bytes),
        };

        match client.get_transaction(tonic::Request::new(filter)).await {
            Ok(resp) => {
                let r = resp.into_inner();
                if r.height > 0 || !r.data.is_empty() {
                    skipped.push(format!("{} (on chain at height {})", display, r.height));
                    continue;
                }
                // Empty response without an error: treat as not found.
            }
            Err(status) if status.code() == tonic::Code::NotFound => { /* dead — proceed */ }
            Err(e) => {
                skipped.push(format!("{} (node error: {})", display, e));
                continue;
            }
        }

        // Confirmed absent and past expiry. Drop the spend links so the inputs return.
        let conn = rusqlite::Connection::open(&db_path)?;
        let tx_id: i64 = match conn.query_row(
            "SELECT id_tx FROM transactions WHERE hex(txid) = ?1",
            [&txid_hex],
            |r| r.get(0),
        ) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let mut removed = 0usize;
        for table in [
            "sapling_received_note_spends",
            "orchard_received_note_spends",
            "ironwood_received_note_spends",
            "transparent_received_output_spends",
        ] {
            removed += conn
                .execute(
                    &format!("DELETE FROM {table} WHERE transaction_id = ?1"),
                    [tx_id],
                )
                .unwrap_or(0);
        }

        // Clear the stored raw bytes so it stops appearing as resendable.
        let _ = conn.execute("UPDATE transactions SET raw = NULL WHERE id_tx = ?1", [tx_id]);

        println!("[wallet] released {removed} input(s) from expired tx {display} (expiry {expiry}, tip {tip})");
        released.push(format!("{} ({} input(s))", display, removed));
    }

    let mut report = String::new();
    if !released.is_empty() {
        report.push_str(&format!(
            "Released the inputs of {} expired transaction(s); those funds are spendable again:\n  {}\n",
            released.len(),
            released.join("\n  ")
        ));
    }
    if !skipped.is_empty() {
        report.push_str(&format!(
            "\nLeft alone, because they could not be confirmed absent from the chain:\n  {}\n",
            skipped.join("\n  ")
        ));
    }
    if report.is_empty() {
        report.push_str("No expired transactions were eligible for release.");
    }
    Ok(report)
}

/// Rebroadcast every stored transaction that is still alive.
///
/// Safe to run repeatedly. A transaction already in the mempool or already mined
/// comes back as a duplicate, which `try_broadcast_zebrad` treats as success and
/// the gRPC path reports as a rejection naming the duplicate — either way nothing
/// is spent twice, because the inputs were consumed when the transaction was
/// built and only this transaction can spend them.
pub async fn resend_pending_broadcasts() -> Result<String> {
    let pending = check_pending_broadcasts().await?;

    if pending.is_empty() {
        return Ok("No unconfirmed transactions. Nothing to resend.".to_string());
    }

    let mut resent = Vec::new();
    let mut expired = Vec::new();
    let mut failed = Vec::new();

    for entry in pending {
        if entry.expired {
            // Past expiry the network will not accept it. The notes are still
            // marked spent locally and only a rescan releases them.
            expired.push(entry.txid);
            continue;
        }

        match broadcast_raw_tx(&entry.raw_hex).await {
            Ok(_) => resent.push(entry.txid),
            Err(e) => failed.push(format!("{}: {}", entry.txid, e)),
        }
    }

    let mut report = String::new();
    if !resent.is_empty() {
        report.push_str(&format!(
            "Resent {} transaction(s) to the network:\n  {}\n",
            resent.len(),
            resent.join("\n  ")
        ));
    }
    if !expired.is_empty() {
        report.push_str(&format!(
            "\n{} transaction(s) have passed their expiry height and cannot be resent:\n  {}\n\
             \nTheir inputs are still marked spent locally, so that balance is missing. \
             `release_expired_transactions` confirms with a node that each one really is absent \
             from the chain and then releases them — a full rescan is no longer required.\n",
            expired.len(),
            expired.join("\n  ")
        ));
    }
    if !failed.is_empty() {
        report.push_str(&format!(
            "\n{} transaction(s) could not be delivered:\n  {}\n",
            failed.len(),
            failed.join("\n  ")
        ));
    }

    Ok(report)
}

pub async fn sync_status() -> Result<String> {
    let current_provider = PROVIDER_URL.lock().unwrap().clone();
    
    // Was a Port-host rewrite; see grpc_endpoint. The provider is used as given.
    let grpc_provider = current_provider.clone();
    
    // GetLightdInfo carries more than the served height, and the extra fields answer
    // questions the UI could not previously distinguish:
    //
    //   block_height     what this endpoint has actually indexed and will serve
    //   estimated_height what it believes the network tip to be
    //
    // Those two differ when the indexer trails its own full node — the exact case
    // that is invisible when only one number is shown. A wallet that is level with
    // `block_height` but far below `estimated_height` is not behind; its *provider*
    // is. Reported separately so the two are never conflated again.
    let probe_start = std::time::Instant::now();
    let mut node_blocks = 0u64;
    let mut node_estimated = 0u64;
    let mut vendor = String::new();
    let mut version = String::new();
    let mut branch_id = String::new();
    let mut upgrade_name = String::new();
    let mut chain_name = String::new();
    let mut latency_ms: u64 = 0;

    match lightwallet::compact_tx_streamer_client::CompactTxStreamerClient::connect(grpc_provider).await {
        Ok(mut client) => {
            if let Ok(info) = client.get_lightd_info(tonic::Request::new(lightwallet::Empty {})).await {
                let i = info.into_inner();
                node_blocks = i.block_height;
                node_estimated = i.estimated_height;
                vendor = i.vendor;
                version = i.version;
                branch_id = i.consensus_branch_id;
                upgrade_name = i.upgrade_name;
                chain_name = i.chain_name;
                latency_ms = probe_start.elapsed().as_millis() as u64;
            }
        },
        Err(e) => {
            println!("gRPC Connection Error: {:?}", e);
        }
    };

    // `estimated_height` is optional in the protocol and some servers leave it at 0.
    // Treat absent as "no better information than block_height" rather than as a lag
    // of the entire chain.
    let chain_tip = if node_estimated > node_blocks { node_estimated } else { node_blocks };
    let provider_lag = chain_tip.saturating_sub(node_blocks);
    
    let mut current_wallet_height = WALLET_HEIGHT.load(Ordering::Relaxed);
    if current_wallet_height == 0 {
            let db_path = crate::paths::as_string::wallet_db_path()?;
        if let Ok(conn) = rusqlite::Connection::open(&db_path) {
            // Scanned height if there is one; otherwise the account's BIRTHDAY.
            //
            // This was 1,740,000 — an invented number that made a brand new wallet
            // display a height it had never reached and a progress bar near 50%
            // before it had synced anything. Replacing it with 0 was truthful and
            // useless: a fresh wallet then read "This Wallet: 0", which looks like
            // a failure. It is not at block 0. It starts at its birthday and has
            // nothing yet to scan, and that is the number a person needs to see.
            let scanned: Option<i64> = conn
                .query_row("SELECT MAX(height) FROM blocks", [], |row| row.get(0))
                .unwrap_or(None);
            let birthday: Option<i64> = conn
                .query_row("SELECT MIN(birthday_height) FROM accounts", [], |row| row.get(0))
                .unwrap_or(None);
            current_wallet_height = scanned.or(birthday).unwrap_or(0) as u64;
            WALLET_HEIGHT.store(current_wallet_height, Ordering::Relaxed);
        } else {
            current_wallet_height = 0;
        }
    }
    
    let mut progress = 0;
    let mut status_text = "Syncing Data...".to_string();
    let target = node_blocks;
    
    if node_blocks > 0 {
        let total = node_blocks;
        progress = if total > 0 { ((current_wallet_height as f64 / total as f64) * 100.0) as u64 } else { 100 };
        
        // A tolerance, not exact equality. Blocks arrive roughly every 75s, so a
        // wallet that is genuinely caught up still trails by one or two almost
        // all the time — with `>=` the header read "Syncing Data..." forever and
        // never showed a settled state. Matches stack-status.sh's threshold.
        const SYNCED_TOLERANCE: u64 = 2;
        if current_wallet_height + SYNCED_TOLERANCE >= node_blocks {
            status_text = "Full Sync".to_string();
            progress = 100;
        }
    } else {
        status_text = "Disconnected".to_string();
    }
    
    let status = serde_json::json!({
        "status": status_text,
        "blockHeight": current_wallet_height,
        "targetHeight": target,
        "progress": progress,
        "ipAddress": current_provider,

        // Added 2026-08-26. `targetHeight` was already returned and never rendered,
        // which is how the panel came to show wallet state under a node label.
        "chainTip": chain_tip,
        "providerLag": provider_lag,
        "walletLag": target.saturating_sub(current_wallet_height),
        "vendor": vendor,
        "version": version,
        "consensusBranchId": branch_id,
        "upgradeName": upgrade_name,
        "chainName": chain_name,
        "latencyMs": latency_ms
    });
    
    Ok(status.to_string())
}

/// Spendable shielded balance, in ZEC.
///
/// 2026-08-13: this previously summed `orchard_received_notes` and
/// `sapling_received_notes` with hand-written SQL and **never read
/// `ironwood_received_notes` at all**. Post-NU6.3 every new shielded output
/// lands in Ironwood, so the headline balance was computed from pools the wallet
/// may hold nothing in. It looked correct only by coincidence — a spent Orchard
/// note happened to carry the same value as the live Ironwood one.
///
/// Same family as the note-selection bug fixed on 2026-08-12: code written
/// before Ironwood existed, enumerating pools explicitly, never revisited.
///
/// `get_wallet_summary` is the backend's own accounting across all pools, and it
/// already handles spends and confirmations, so there is no per-pool SQL left
/// here to fall out of date when a pool is added.
/// Every zatoshi the wallet knows about, in exactly one named bucket (A5).
///
/// A real wallet showed one number on the card and a smaller one available to send, with
/// nothing between them saying where the rest was. The backend's summary already sorts
/// notes into buckets; this exposes them, and adds the one the backend cannot name:
/// **unpositioned** notes — recorded without a commitment-tree position, so no witness
/// can ever be built and no scan will place them. The backend files those under "pending
/// spendability" indefinitely, which reads as "wait". It is not "wait"; it is a rescan.
///
/// Invariant: `spendable + locked + pending_change + awaiting_scan + unpositioned +
/// uneconomic == shielded_total`. The card can show the sum and every part.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BalanceBreakdown {
    /// Can be selected for a send now.
    pub spendable_zat: u64,
    /// Committed to a pending proposal, or a carrier locked by `lock_zmap_carriers`.
    pub locked_zat: u64,
    /// Change from our own sends, waiting for confirmations.
    pub pending_change_zat: u64,
    /// Received value the scan has not yet made witnessable (or confirmed). Will clear.
    pub awaiting_scan_zat: u64,
    /// Recorded with no tree position: never spendable without a rescan. Will NOT clear.
    pub unpositioned_zat: u64,
    pub unpositioned_notes: u64,
    /// Lowest mined height among the unpositioned notes — where a rescan must start.
    pub unpositioned_from_height: Option<u32>,
    /// Worth less than the marginal fee; spendable only as a grace input.
    pub uneconomic_zat: u64,
    /// Unspent transparent outputs.
    pub transparent_zat: u64,
    pub shielded_total_zat: u64,
}

pub async fn get_balance_breakdown() -> Result<BalanceBreakdown> {
    use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
    use zcash_client_backend::data_api::WalletRead;

    let db_path = crate::paths::as_string::wallet_db_path()?;

    // The backend's buckets. No summary (nothing scanned yet) is a wallet of zeros, not
    // an error — but the unpositioned scan below still runs, because those rows exist
    // independently of any summary.
    // The wallet's own view of the tip, for judging expiry below; 0 when nothing is scanned.
    let mut tip_seen = 0u32;
    let mut spendable = 0u64;
    let mut locked = 0u64;
    let mut pending_change = 0u64;
    let mut pending_spendability = 0u64;
    let mut uneconomic = 0u64;
    let mut shielded_total = 0u64;
    {
        let wallet_db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, OsRng)
            .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
        if let Some(summary) = wallet_db
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .map_err(|e| anyhow::anyhow!("could not read wallet summary: {:?}", e))?
        {
            tip_seen = u32::from(summary.chain_tip_height());
            for b in summary.account_balances().values() {
                for p in [b.sapling_balance(), b.orchard_balance(), b.ironwood_balance()] {
                    spendable += u64::from(p.spendable_value());
                    locked += u64::from(p.locked_value());
                    pending_change += u64::from(p.change_pending_confirmation());
                    pending_spendability += u64::from(p.value_pending_spendability());
                    uneconomic += u64::from(p.uneconomic_value());
                    shielded_total += u64::from(p.total());
                }
            }
        }
    }

    // The bucket the backend cannot name. Unspent, and no commitment-tree position: note
    // selection requires a position to build a witness. Change of a transaction that expired
    // without being mined is not a note at all (the backend already excludes it), so it is left
    // out here too; until 2026-10-02 it was shown as "needs a rescan", which no rescan can fix.
    // (Was:) note
    // selection requires a position to build a witness (it is the first thing
    // select_spendable_notes filters on), so these can never be inputs. The backend counts
    // them in `value_pending_spendability`; they are taken out of that bucket here so
    // "awaiting scan" only holds what a scan will actually resolve.
    let (unpositioned, unpositioned_notes, from_height, transparent) = {
        let conn = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;
        let mut stmt = conn.prepare(
            "SELECT n.value, t.mined_height FROM sapling_received_notes n
               JOIN transactions t ON t.id_tx = n.transaction_id
              WHERE n.commitment_tree_position IS NULL
                AND (t.mined_height IS NOT NULL OR t.expiry_height IS NULL OR t.expiry_height = 0 OR t.expiry_height > ?1)
                AND NOT EXISTS (SELECT 1 FROM sapling_received_note_spends s WHERE s.sapling_received_note_id = n.id)
             UNION ALL
             SELECT n.value, t.mined_height FROM orchard_received_notes n
               JOIN transactions t ON t.id_tx = n.transaction_id
              WHERE n.commitment_tree_position IS NULL
                AND (t.mined_height IS NOT NULL OR t.expiry_height IS NULL OR t.expiry_height = 0 OR t.expiry_height > ?1)
                AND NOT EXISTS (SELECT 1 FROM orchard_received_note_spends s WHERE s.orchard_received_note_id = n.id)
             UNION ALL
             SELECT n.value, t.mined_height FROM ironwood_received_notes n
               JOIN transactions t ON t.id_tx = n.transaction_id
              WHERE n.commitment_tree_position IS NULL
                AND (t.mined_height IS NOT NULL OR t.expiry_height IS NULL OR t.expiry_height = 0 OR t.expiry_height > ?1)
                AND NOT EXISTS (SELECT 1 FROM ironwood_received_note_spends s WHERE s.ironwood_received_note_id = n.id)",
        )?;
        let rows: Vec<(i64, Option<u32>)> = stmt
            .query_map([tip_seen], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let value: u64 = rows.iter().map(|(v, _)| (*v).max(0) as u64).sum();
        let from = rows.iter().filter_map(|(_, h)| *h).min();
        let transparent: u64 = conn
            .query_row(
                "SELECT COALESCE(SUM(value_zat), 0) FROM transparent_received_outputs
                  WHERE id NOT IN (SELECT transparent_received_output_id FROM transparent_received_output_spends)",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v.max(0) as u64)
            .unwrap_or(0);
        (value, rows.len() as u64, from, transparent)
    };

    // Rows that exist outside any summary (a wallet that has not scanned yet) still count
    // toward the total, or the invariant breaks.
    let shielded_total = shielded_total.max(
        spendable + locked + pending_change + pending_spendability + uneconomic,
    ).max(unpositioned + spendable + locked + pending_change + uneconomic);
    let awaiting_scan = pending_spendability.saturating_sub(unpositioned);

    Ok(BalanceBreakdown {
        spendable_zat: spendable,
        locked_zat: locked,
        pending_change_zat: pending_change,
        awaiting_scan_zat: awaiting_scan,
        unpositioned_zat: unpositioned,
        unpositioned_notes,
        unpositioned_from_height: from_height,
        uneconomic_zat: uneconomic,
        transparent_zat: transparent,
        shielded_total_zat: shielded_total,
    })
}

/// Spendable shielded balance, in ZEC. One bucket of `get_balance_breakdown`; kept so
/// the number on the card and the number a send can use are the same number by
/// construction.
pub async fn get_balance() -> Result<f64> {
    Ok(get_balance_breakdown().await?.spendable_zat as f64 / 100_000_000.0)
}

/// The wallet's transparent receiving address, as a bare `t1…` string.
///
/// # Why this exists separately from `get_addresses`
///
/// Every unified address this wallet issues already *contains* a transparent receiver — decoding one
/// gives 128 bytes, which is three receivers (transparent, Sapling, Orchard). A modern sender hands
/// the `u1…` its money and picks a pool itself.
///
/// But an exchange or a legacy service that only speaks transparent cannot parse a UA. It needs the
/// bare `t1…`, and until now the wallet had no way to show one: the capability sat in
/// `src/bin/get_taddr.rs`, a development throwaway that was never promoted to a command. So funds
/// could arrive transparently and be shielded, while the address to hand out was unobtainable
/// without running a side binary.
///
/// # This address is public
///
/// Transparent means transparent. Anything sent here is visible on chain, along with the amount and
/// the counterparty. It is a funding on-ramp, not somewhere to hold value — shield promptly with
/// [`shield_transparent`].
pub async fn get_transparent_address() -> Result<Vec<Value>> {
    use zcash_client_backend::data_api::WalletRead;
    use zcash_client_backend::encoding::AddressCodec;
    use zcash_client_sqlite::util::SystemClock;
    use zcash_client_sqlite::WalletDb;
    use zcash_protocol::consensus::MainNetwork;

    let db_path = crate::paths::as_string::wallet_db_path()?;
    let wallet_db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, rand::rngs::OsRng)
        .map_err(|e| anyhow::anyhow!("could not open the wallet: {:?}", e))?;

    let account = wallet_db
        .get_account_ids()
        .map_err(|e| anyhow::anyhow!("could not read accounts: {:?}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("this wallet has no accounts yet"))?;

    // (include_change, include_ephemeral) — both false: a change or ephemeral address handed to a
    // third party would receive funds the wallet tracks differently, and neither is meant to be
    // published.
    let receivers = wallet_db
        .get_transparent_receivers(account, false, false)
        .map_err(|e| anyhow::anyhow!("could not derive a transparent address: {:?}", e))?;

    let out: Vec<Value> = receivers
        .into_iter()
        .map(|(taddr, _)| {
            serde_json::json!({
                "address": taddr.encode(&MainNetwork),
                "public": true,
            })
        })
        .collect();

    if out.is_empty() {
        return Err(anyhow::anyhow!(
            "no transparent receiver is derived for this account. The wallet must be built with the \
             `transparent-inputs` feature and the account created with a transparent key path."
        ));
    }
    Ok(out)
}

pub async fn get_transparent_balance() -> Result<f64> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    
    if let Ok(conn) = rusqlite::Connection::open(&db_path) {
        let mut total_zats: u64 = 0;
        
        if let Ok(mut stmt) = conn.prepare("SELECT SUM(value_zat) FROM transparent_received_outputs WHERE id NOT IN (SELECT transparent_received_output_id FROM transparent_received_output_spends)") {
            total_zats += stmt.query_row([], |row| row.get::<_, Option<u64>>(0)).unwrap_or(Some(0)).unwrap_or(0);
        }
        
        let balance = total_zats as f64 / 100_000_000.0;
        return Ok(balance);
    }
    
    Ok(0.0)
}

pub async fn batch_send_transaction(outputs: Vec<(String, f64, String)>) -> Result<String> {
    // 1. Validate every output before doing any work. Same NaN/negative/overflow
    //    hazard as the single-send path; here a bad entry anywhere in the batch
    //    would otherwise be silently coerced to a zero-value output.
    let mut outputs_zat: Vec<(String, u64, String)> = Vec::with_capacity(outputs.len());
    for (i, (addr, amt, memo)) in outputs.into_iter().enumerate() {
        let amount_zat = zec_to_zatoshis(amt)
            .map_err(|e| anyhow::anyhow!("Output {}: {}", i + 1, e))?;
        if addr.trim().is_empty() {
            anyhow::bail!("Output {}: enter a recipient address.", i + 1);
        }
        zcash_address::ZcashAddress::try_from_encoded(addr.trim()).map_err(|e| {
            anyhow::anyhow!("Output {}: that does not look like a Zcash address: {}", i + 1, e)
        })?;
        if memo.as_bytes().len() > 512 {
            anyhow::bail!("Output {}: memo is {} bytes; the maximum is 512.", i + 1, memo.as_bytes().len());
        }
        outputs_zat.push((addr, amount_zat, memo));
    }

    
    // Same fix as in `send_transaction` — see the note there. This variant
    // hardcoded the Port URL outright, so it would have queried a REST endpoint
    // on a host the user may not even be using.
    let target_height = current_chain_tip().await?;

    // Flush unconfirmed transactions first — see the note in `send_transaction`.
    match resend_pending_broadcasts().await {
        Ok(report) if !report.starts_with("No unconfirmed") => println!("[pending] {}", report),
        Ok(_) => {}
        Err(e) => eprintln!("[pending] could not check for unconfirmed transactions: {}", e),
    }

    println!("[Data Plane] Constructing Zero-Knowledge Proof for batch locally...");
    // Off the async executor. `crate::wallet::batch_send_transaction` does blocking SQLite I/O
    // and then builds a zero-knowledge proof, which is seconds of solid CPU. Run directly
    // on a tokio worker it monopolises that thread: the sync engine stalls, gRPC calls
    // queue behind it, and the interface stops responding — the "app freezes while
    // sending" behaviour.
    //
    // `spawn_blocking` moves it to tokio's blocking pool, which exists for exactly this.
    // The arguments are owned first because the closure crosses a thread boundary.
    let (raw_tx_hex, proposed_inputs) = tokio::task::spawn_blocking(move || {
        crate::wallet::batch_send_transaction(outputs_zat, target_height)
    })
    .await
    .map_err(|e| anyhow::anyhow!("the transaction builder did not finish: {e}"))??;
    println!("[Data Plane] Successfully generated mathematically pure Zero-Knowledge Proof! ({} bytes)", raw_tx_hex.len() / 2);

    // Broadcast over the same gRPC channel used for sync (W6).
    let tx_id = broadcast_raw_tx(&raw_tx_hex).await?;

    // Spend state is not written here — see the equivalent note in
    // `send_transaction`. The removed block hand-wrote
    // `orchard_received_note_spends` with raw SQL, matched only the Orchard pool
    // (so nothing at all after NU6.3), and compared txids in the wrong byte
    // order. `create_proposed_transactions` records the spend through the data
    // API, and the sync engine confirms it from the chain.
    let _ = proposed_inputs;

    Ok(format!("Batch Transaction broadcasted successfully! TxID: {}", tx_id))
}

/// Convert a ZEC amount to zatoshis, rejecting anything that is not a sane value.
///
/// Added 2026-08-12. The UI passes `parseFloat(amount)` straight through with no
/// validation, so an empty field arrives as `NaN`. In Rust, `(NaN * 1e8) as u64`
/// saturates to **0** rather than trapping — so a blank amount silently became a
/// zero-value send, and a negative amount likewise. Infinity saturates to
/// `u64::MAX`. All three are caught here rather than in the UI, so a malformed
/// call from any caller is rejected.
fn zec_to_zatoshis(amount: f64) -> Result<u64> {
    if amount.is_nan() {
        anyhow::bail!("Enter an amount.");
    }
    if !amount.is_finite() {
        anyhow::bail!("The amount is not a valid number.");
    }
    if amount <= 0.0 {
        anyhow::bail!("The amount must be greater than zero.");
    }
    // 21 million ZEC is the supply cap; anything beyond it is a typo or overflow.
    const MAX_ZEC: f64 = 21_000_000.0;
    if amount > MAX_ZEC {
        anyhow::bail!("The amount exceeds the total Zcash supply.");
    }

    let zat = (amount * 100_000_000.0).round();
    if zat < 1.0 {
        anyhow::bail!("The amount is smaller than one zatoshi (0.00000001 ZEC).");
    }
    Ok(zat as u64)
}

pub async fn send_transaction(address: &str, amount: f64, memo: &str, asset_id: Option<&str>) -> Result<String> {
    send_transaction_with_wake(address, amount, memo, asset_id, false, None, None, None).await
}

/// [`send_transaction`] with the Wake acknowledgement (chapter 8): when `acknowledge_unproven`
/// is false and the unit has no lading, the send is refused with [`crate::wake::UNPROVEN_PREFIX`].
pub async fn send_transaction_with_wake(address: &str, amount: f64, memo: &str, asset_id: Option<&str>, acknowledge_unproven: bool, max_fee_zat: Option<u64>, abandon_lineage: Option<&str>, carrier: Option<&str>) -> Result<String> {
    // 1. Validate and convert to zatoshis — on the value path only.
    //
    // A ZSA transfer moves a carrier note whose value is fixed at CARRIER_ZAT and
    // whose memo is reproduced byte for byte; `send_zmap_asset` ignores both
    // arguments deliberately, because honouring a caller-supplied version of
    // either would let a caller change an asset's identity in flight.
    //
    // `zec_to_zatoshis` rejects `amount <= 0.0`, which is right for a value send
    // (2026-08-12: a blank UI field arrived as NaN and saturated to a zero-value
    // send). Applied to the asset path it rejected the one caller for which the
    // amount is meaningless: Galley's delivery loop passes 0.0 and every delivery
    // failed with "The amount must be greater than zero" before reaching the
    // branch that would have discarded it. Validate where the number is used.
    let amount_zat = match asset_id {
        Some(_) => crate::zmap::CARRIER_ZAT,
        None => zec_to_zatoshis(amount)?,
    };

    if address.trim().is_empty() {
        anyhow::bail!("Enter a recipient address.");
    }
    // Reject a malformed address here rather than after building a proof.
    zcash_address::ZcashAddress::try_from_encoded(address.trim())
        .map_err(|e| anyhow::anyhow!("That does not look like a Zcash address: {}", e))?;

    if memo.as_bytes().len() > 512 {
        anyhow::bail!(
            "The memo is {} bytes; the maximum is 512.",
            memo.as_bytes().len()
        );
    }

    // An item that arrived with a lineage record must have that record collected before it can
    // be sent on: the next proof extends it. Until 2026-10-06 that only happened when the item
    // list was opened, so sending straight after receiving was refused with "the stored lading
    // ... does not end at the carrier being spent". Collect here; a failure is not fatal, the
    // send then reports what is actually missing.
    if asset_id.is_some() {
        if let Ok(db_path) = crate::paths::as_string::wallet_db_path() {
            // Waits for a line another pass is walking (the item list starts a background pass
            // it does not wait for): "being collected" must not read as "absent" here (review
            // 2026-10-09, regression over 12-13, Issue B).
            let aid = asset_id.map(|s| s.to_string()).unwrap_or_default();
            // This asset's carriers only (review 2026-10-09, Knotline A): the send used to walk
            // every holding's line and wait for all of them.
            match tokio::task::spawn_blocking(move || crate::wake::fetch_missing_consignments_scoped(&db_path, crate::wake::FetchScope::for_send(&aid))).await {
                // A walk still running for SOME carrier of the asset is not a reason to refuse:
                // the builder refuses only when the copy it would spend is the one being
                // collected, and a stranger's copy must not block the genuine unit (gate fifth
                // pass, Finding 5).
                Ok(Ok(r)) if !r.in_progress.is_empty() => println!("[wake] a line of {} is still being walked ({}); the send goes on with what is held", r.in_progress.len(), r.in_progress.join(", ")),
                Ok(Ok(r)) if r.fetched > 0 => println!("[wake] collected {} waiting lading(s) before the send", r.fetched),
                Ok(Err(e)) => eprintln!("[wake] could not collect waiting ladings before the send: {e}"),
                _ => {}
            }
        }
    }

    // Ask the node we are already talking to.
    //
    // 2026-08-12: this branched on `provider.contains("127.0.0.1")` — the same
    // broken local/remote test W6 removed from the broadcast path, left behind
    // here. With the app pointed at a zaino on the LAN the test was
    // false, so it fell to the remote branch and issued an HTTP/1 GET against
    // `{provider}/api/v1/status`. That path is served by zecboat_provider, not
    // zaino, and 8137 speaks gRPC (HTTP/2) — producing:
    //
    //     invalid HTTP version parsed
    //
    // Both branches also fell back to hardcoded heights (3415000 / 3376000) on
    // failure, silently substituting a stale number for a real one.
    //
    // GetLightdInfo over the existing gRPC channel works for every provider and
    // has no fallback: if the node cannot be reached, the send fails plainly
    // rather than proceeding against an invented height.
    let target_height = current_chain_tip().await?;

    // 1a. Flush anything built earlier that never reached the network.
    //
    // A transaction whose broadcast response was lost sits in `transactions` with
    // a null `mined_height`, holding its inputs spent, and nothing used to look
    // at it. Rebroadcasting here is idempotent: one still in the mempool comes
    // back as a duplicate and nothing happens. Best-effort by design — a failure
    // to flush must not stop the send the user actually asked for.
    match resend_pending_broadcasts().await {
        Ok(report) if !report.starts_with("No unconfirmed") => {
            println!("[pending] {}", report);
        }
        Ok(_) => {}
        Err(e) => eprintln!("[pending] could not check for unconfirmed transactions: {}", e),
    }

    // 2. Delegate to the native Rust wallet module for dynamic note selection and ZKP construction (Data Plane)
    println!("[Data Plane] Constructing Zero-Knowledge Proof locally...");
    // Off the async executor. `crate::wallet::send_transaction` does blocking SQLite I/O
    // and then builds a zero-knowledge proof, which is seconds of solid CPU. Run directly
    // on a tokio worker it monopolises that thread: the sync engine stalls, gRPC calls
    // queue behind it, and the interface stops responding — the "app freezes while
    // sending" behaviour.
    //
    // `spawn_blocking` moves it to tokio's blocking pool, which exists for exactly this.
    // The arguments are owned first because the closure crosses a thread boundary.
    // Wake: the genesis lookup talks to the registry, so it happens here, before the
    // blocking builder, and its answer travels down as data.
    let wake = crate::wake::SendOptions {
        genesis: match asset_id {
            Some(id) => crate::wake::genesis_outpoint(id).await,
            None => None,
        },
        acknowledge_unproven,
        abandon_lineage: abandon_lineage.map(|s| s.to_string()),
        carrier: carrier.map(|s| s.to_string()),
    };
    let (raw_tx_hex, proposed_inputs) = {
        let address = address.to_string();
        let memo = memo.to_string();
        let asset_id = asset_id.map(|s| s.to_string());
        tokio::task::spawn_blocking(move || {
            crate::wallet::send_transaction(
                &address,
                amount_zat,
                &memo,
                asset_id.as_deref(),
                target_height,
                &wake,
                max_fee_zat,
            )
        })
        .await
        .map_err(|e| anyhow::anyhow!("the transaction builder did not finish: {e}"))??
    };
    println!("[Data Plane] Successfully generated mathematically pure Zero-Knowledge Proof! ({} bytes)", raw_tx_hex.len() / 2);

    // 3. Broadcast: gRPC, retried, then direct to zebrad.
    //
    // The error this can now return says "built but not delivered, and
    // recoverable" instead of "failed". The distinction is not cosmetic — the
    // inputs are already spent by this point, and the old wording made two
    // successful sends look like destroyed assets.
    let tx_id_string = broadcast_raw_tx(&raw_tx_hex).await?;

    let tx_id = tx_id_string.as_str();

    // 4. Nothing to record here.
    //
    // A block previously stood here that hand-wrote rows into `transactions` and
    // `orchard_received_note_spends` with raw SQL. It was removed 2026-08-12 for
    // three reasons, any one of which is sufficient:
    //
    //   * It is a tape job. Writing cryptographic state by hand is exactly what
    //     the project guardrails prohibit; `create_proposed_transactions` already
    //     records the spend when it builds the transaction, through the data API
    //     that also maintains the nullifier and commitment-tree bookkeeping.
    //   * It only ever touched `orchard_received_note_spends`. Post-NU6.3 funds
    //     are Ironwood notes, so after the upgrade it matched nothing at all —
    //     silently, because every statement was `let _ = ...`.
    //   * Its txid byte order was wrong regardless. `broadcast_raw_tx` returns
    //     the node's txid in display order, while SQLite stores `transactions.txid`
    //     in internal (reversed) order — the same inversion that makes the shield
    //     read `896765d8…` in the database and `77b65506…` in a block explorer.
    //     The `hex(t.txid) = UPPER(?)` comparison could not have matched.
    //
    // Spend state is now established by the sync engine reading it back from the
    // chain, which is the only source that cannot be wrong.
    let _ = proposed_inputs;

    Ok(format!("Transaction broadcasted successfully! TxID: {}", tx_id))
}

pub async fn get_addresses() -> Result<Vec<Value>> {
    let db_path_str = crate::paths::as_string::wallet_db_path()?;
    let db_path = db_path_str.as_str();
    match crate::db::WalletPool::new(db_path) {
        Ok(pool) => {
            match pool.get_addresses().await {
                Ok(addrs) => {
                    return Ok(addrs);
                },
                Err(e) => println!("Error getting addresses: {:?}", e),
            }
        }
        Err(e) => println!("Error creating DB pool: {:?}", e),
    }
    Ok(vec![])
}

/// Derive, persist and return the account's next unified address.
///
/// 2026-08-12: this previously returned a **hardcoded UA string** with the
/// comment *"In a real implementation, we would derive the next diversifier
/// index"*. That address is not derived from this wallet's seed — it is absent
/// from the `addresses` table — so the wallet holds no key able to decrypt notes
/// sent to it. Every install of the app returned the same one. Funds received at
/// it would have been unspendable, and the UI (`ReceiveView.svelte:52`) presented
/// it as a legitimate receive address.
///
/// `get_next_available_address` does the real thing: derives the next diversifier
/// from the account's UFVK, records the address so the scanner watches it, and
/// returns it.
///
/// The Orchard receiver is what makes the address Ironwood-capable — Ironwood
/// shares it rather than defining its own (zcash_keys-0.16 `address.rs:447`), so
/// no Ironwood-specific request is needed or possible.
///
/// # `with_transparent` — why this is not always on
///
/// This used to pass `UnifiedAddressRequest::ALLOW_ALL` unconditionally, so every
/// address the wallet derived carried a transparent receiver whether or not anyone
/// wanted one. That is not merely untidy; it costs privacy, and it does so through
/// a channel most people would not expect.
///
/// Shielded scanning is private *from the server*: the wallet downloads compact
/// blocks and trial-decrypts them locally, so lightwalletd never learns which notes
/// are yours. **Transparent detection cannot work that way.** Finding payments to a
/// `t` address means calling `GetTaddressTxids` with that address in cleartext —
/// see the `w9` request servicing in this file. That tells the server *this address
/// is mine*, and links it to your IP and to the timing of every other query in the
/// same session.
///
/// So a transparent receiver nobody asked for is a standing disclosure in exchange
/// for a capability that was never wanted. Shielded-only is the default; a caller
/// that genuinely needs to receive from an exchange or a sender that cannot parse a
/// unified address asks for one explicitly.
///
/// Existing addresses are unaffected — receivers are fixed at derivation, so the
/// 25 addresses an older wallet already holds keep the transparent receivers they
/// were created with. This changes what is derived from here on.
/// Derive a new receiving address. **Shielded only** — no transparent receiver.
///
/// See [`generate_new_address_with`] for why that is the default.
pub async fn generate_new_address() -> Result<String> {
    generate_new_address_with(false).await
}

pub async fn generate_new_address_with(with_transparent: bool) -> Result<String> {
    use zcash_client_backend::data_api::{WalletRead, WalletWrite};
    use zcash_keys::keys::UnifiedAddressRequest;

    let db_path = crate::paths::as_string::wallet_db_path()?;

    let mut wallet_db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, OsRng)
        .map_err(|e| anyhow::anyhow!("could not open wallet: {:?}", e))?;

    let account = wallet_db
        .get_account_ids()
        .map_err(|e| anyhow::anyhow!("could not read accounts: {:?}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("wallet has no accounts"))?;

    // SHIELDED omits the transparent receiver entirely. ALLOW_ALL includes it.
    let request = if with_transparent {
        UnifiedAddressRequest::ALLOW_ALL
    } else {
        UnifiedAddressRequest::SHIELDED
    };

    let (address, diversifier) = wallet_db
        .get_next_available_address(account, request)
        .map_err(|e| anyhow::anyhow!("could not derive a new address: {:?}", e))?
        .ok_or_else(|| anyhow::anyhow!("no address could be derived for this account"))?;

    let encoded = address.encode(&MainNetwork);
    println!("[address] derived new UA at diversifier {:?}", diversifier);
    Ok(encoded)
}

pub fn check_initialization_status() -> Result<bool> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let identity_path = crate::paths::as_string::identity_path()?;
    
    // Returns true if BOTH files exist (initialized)
    Ok(std::path::Path::new(&db_path).exists() && std::path::Path::new(&identity_path).exists())
}

// async so the new account's birthday can be read from the chain tip rather than
// hardcoded. The Tauri command wrapping this was already async.
pub async fn initialize_new_wallet(password: String, use_yubikey: bool, birthday: Option<u32>) -> Result<String> {
    let data_dir = crate::paths::as_string::app_data_dir()?;
    crate::paths::create_private_dir(&data_dir)?;
    
    // A YubiKey wallet must be sealed to a device that is present NOW. Resolve the
    // recipient before anything is written, so the failure is "no key found" with an
    // empty directory rather than a half-built wallet nothing can open.
    //
    // The old code called yubi::get_yubikey_derived_key(), which hashed the password
    // with a fixed string and contacted no hardware. A wallet created that way was
    // protected by a password and told its owner it was protected by a device.
    let yubikey_recipient: Option<String> = if use_yubikey {
        let recipients = crate::yubi::list_recipients()?;
        Some(recipients.into_iter().next().ok_or_else(|| {
            if crate::yubi::plugin_installed() {
                anyhow::anyhow!(
                    "No YubiKey with an age identity was found. Insert the key, then create \
                     an identity on it with:\n    age-plugin-yubikey --generate"
                )
            } else {
                anyhow::anyhow!(
                    "age-plugin-yubikey is not installed, so a YubiKey cannot be used. \
                     Install it with:\n    cargo install age-plugin-yubikey"
                )
            }
        })?)
    } else {
        None
    };
    let final_password = password.clone();
    
    // 1. Generate a secure age cryptographic identity
    let identity = age::x25519::Identity::generate();
    let identity_str = {
        use age::secrecy::ExposeSecret;
        identity.to_string().expose_secret().to_string()
    };
    
    // Seal it: to the YubiKey if one was chosen, otherwise under the password.
    // These are mutually exclusive by age's own rules — an scrypt stanza must be the
    // only recipient stanza in a file — so there is no "both" to offer.
    let mut encrypted_identity = vec![];
    if let Some(recipient) = &yubikey_recipient {
        encrypted_identity = crate::yubi::encrypt_to_yubikey(identity_str.as_bytes(), recipient)?;
    } else {
    let encryptor = age::Encryptor::with_user_passphrase(age::secrecy::Secret::new(final_password.clone()));
    {
        let mut writer = encryptor.wrap_output(&mut encrypted_identity)?;
        std::io::Write::write_all(&mut writer, identity_str.as_bytes())?;
        writer.finish()?;
    }
    }
    
    // A brand new seed has never received anything, so its birthday is now. This was
    // hardcoded to 3,364,599 — around 64,000 blocks BEFORE Ironwood activated at
    // 3,428,143, and further below the tip with every day that passed. Every new
    // wallet paid for scanning a stretch of chain it could not possibly appear in.
    //
    // If the node cannot be reached we fall back to Ironwood activation rather than
    // guessing a recent height: too early only costs scanning time, while too late
    // silently skips blocks. For a NEW seed that floor is already generous.
    //
    // Note this is the opposite of the right call for an imported seed — see
    // import_wallet, where moving the birthday forward would hide real funds.
    const IRONWOOD_ACTIVATION: u32 = 3_428_143;
    // An explicit birthday wins. A new seed's correct answer is the tip, but the
    // caller may know better — a phrase generated elsewhere weeks ago, or a node
    // reporting a tip that is wrong. Lowering it only costs scanning time.
    // 2026-10-10: the fallback is no longer silent. A new wallet whose chosen node did not
    // answer used to be given Ironwood activation as its birthday and then spent its first
    // hour scanning 85,000 blocks it cannot appear in, with nothing on screen saying why
    // (the wizard's default node is the loopback one, which a first-time user rarely has).
    // The honest answer is to say which node did not answer and let the user choose
    // another, or set a birthday, before the wallet exists.
    let birthday_height = match birthday {
        Some(h) => h,
        None => match current_chain_tip().await {
            Ok(tip) => tip,
            Err(e) => {
                anyhow::bail!(
                    "the node chosen for this wallet did not answer ({e}), so its birthday cannot be set. \
                     Go back and choose a node that answers (the public node, or your own once it runs), \
                     or set a birthday yourself. Nothing was created."
                );
            }
        },
    };
    let _ = IRONWOOD_ACTIVATION;
    println!("[wallet] new account birthday: {birthday_height}");

    // Resolved BEFORE anything on disk is replaced. It is the only await in this function,
    // and leaving it in the middle meant the fallible remainder could not run in a closure
    // at all — R4's unwind needs a synchronous body. It also matches what the YubiKey
    // recipient above does and for the same reason: fail with the directory untouched.

    // 2. Save this identity to the filesystem.
    //
    // From here on, files that already existed are being replaced. Every `kept` below is
    // recorded so `unwind_replacements` can put them back if anything after this fails —
    // see R4. Without it, a failure left a NEW identity beside NO database: the old
    // password opens nothing and the new one opens nothing worth opening.
    let identity_path = format!("{}/encryption-identity.txt", data_dir);
    let kept_identity = preserve_replaced_file(&identity_path)?;
    crate::paths::write_private(&identity_path, encrypted_identity)?;

    // The stub is what puts this wallet in YubiKey mode from now on. unlock_wallet reads
    // the directory, not a caller-supplied flag, so writing this file is the whole switch.
    let stub_path = crate::paths::as_string::yubikey_stub_path()?;
    let kept_stub = preserve_replaced_file(&stub_path)?;
    if yubikey_recipient.is_some() {
        let stubs = crate::yubi::list_identities()?;
        let stub = stubs.into_iter().next().ok_or_else(|| {
            anyhow::anyhow!("the YubiKey stopped responding while the wallet was being created")
        })?;
        crate::paths::write_private(&stub_path, format!("{stub}\n"))?;
    }
    // A password wallet must not inherit a stub from whatever was here before — and does
    // not, because preserve_replaced_file above has already moved any previous one aside.
    
    // 3. Generate a fresh 24-word BIP-39 Seed Phrase
    let mnemonic = Mnemonic::<English>::generate(Count::Words24);
    let seed_phrase = mnemonic.phrase().to_string();
    
    // 4. Encrypt the Seed Phrase and store it securely
    let recipient = identity.to_public();
    let seed_encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient.clone()) as Box<dyn age::Recipient + Send>]).unwrap();
    let mut encrypted_mnemonic_bytes = vec![];
    {
        let mut writer = seed_encryptor.wrap_output(&mut encrypted_mnemonic_bytes)?;
        std::io::Write::write_all(&mut writer, seed_phrase.as_bytes())?;
        writer.finish()?;
    }
    
    // 5. Initialize the SQLite wallet.db
    let db_path = format!("{}/wallet.db", data_dir);
    // CRITICAL: A new wallet must be completely clean. Destroy any existing database.
    let kept_db = preserve_replaced_file(&db_path)?;

    // Everything from here can fail with three files already replaced. R4: run it in a
    // closure so the failure path can put all of them back.
    let built = (|| -> Result<String> {
    
    let mut wallet_db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, OsRng)
        .map_err(|e| anyhow::anyhow!("Failed to open wallet DB: {:?}", e))?;

    zcash_client_sqlite::wallet::init::init_wallet_db(&mut wallet_db, None)
        .map_err(|e| anyhow::anyhow!("Failed to init wallet DB: {:?}", e))?;
        
    // Store encrypted mnemonic
    let conn = rusqlite::Connection::open(&db_path)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ext_zecboat_keystore_mnemonics (
            hd_seed_fingerprint BLOB NOT NULL UNIQUE,
            encrypted_mnemonic BLOB NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS market_invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id TEXT NOT NULL UNIQUE,
            date TEXT NOT NULL,
            items TEXT NOT NULL,
            total_zec REAL NOT NULL,
            total_fiat_value REAL NOT NULL,
            txid TEXT NOT NULL
        )",
        [],
    )?;
    
    // The real ZIP-32 fingerprint, not a constant. See seed_fingerprint().
    let seed_fp = seed_fingerprint(&mnemonic);
    conn.execute(
        "INSERT OR REPLACE INTO ext_zecboat_keystore_mnemonics (hd_seed_fingerprint, encrypted_mnemonic) VALUES (?1, ?2)",
        rusqlite::params![seed_fp, encrypted_mnemonic_bytes],
    )?;

    // 6 & 7. Derive Account 0 and Unified Address
    use zcash_client_backend::data_api::WalletWrite;
    use zcash_client_backend::data_api::AccountBirthday;
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_protocol::consensus::BlockHeight;
    use age::secrecy::SecretVec;
    
    let seed_secret = SecretVec::new(zeroize::Zeroizing::new(mnemonic.to_seed("")).to_vec());


    let chain_state = ChainState::empty(BlockHeight::from_u32(birthday_height), zcash_primitives::block::BlockHash([0; 32]));
    let birthday = AccountBirthday::from_parts(chain_state, None);
    wallet_db.create_account("My Wallet", &seed_secret, &birthday, None)
        .map_err(|e| anyhow::anyhow!("Failed to create account: {:?}", e))?;

        Ok(seed_phrase)
    })();

    let seed_phrase = match built {
        Ok(p) => p,
        Err(e) => {
            return Err(unwind_replacements(
                &[
                    Replaced { path: identity_path, kept: kept_identity },
                    Replaced { path: stub_path,     kept: kept_stub },
                    Replaced { path: db_path,       kept: kept_db },
                ],
                e,
                &data_dir,
                "creating the wallet",
            ))
        }
    };

    // Only once the wallet really exists. Setting this on the failure path would leave the
    // process believing it holds the password to a wallet that was rolled back.
    *WALLET_PASSWORD.lock().unwrap() = Some(final_password);

    Ok(seed_phrase)
}

/// Rebuild this machine's wallet from a seed phrase, with a NEW password.
///
/// # Why this exists separately from `import_wallet`
///
/// `import_wallet` requires the wallet to already be unlocked — it decrypts the
/// EXISTING identity with the CURRENT password to store the mnemonic. That makes it
/// useless in the one case a seed phrase is for: **the password is lost.**
///
/// Before this function, a locked-out user had no route back in. The setup wizard
/// makes them write down 24 words, verifies three at random, and warns that losing
/// them loses their funds — and then nothing in the application could accept them.
/// The unlock screen offered a backup restore (same password, so still locked) and
/// "create new wallet" (a NEW seed, so not recovery).
///
/// This writes a **fresh** age identity under a password of the caller's choosing,
/// so no prior secret is needed.
///
/// # Nothing is deleted
///
/// The existing identity and database are moved aside by [`preserve_replaced_file`],
/// never removed. Someone who mistypes a word must still have the wallet they
/// started with, and someone who later remembers the password must be able to go
/// back to it.
///
/// # Birthday
///
/// `birthday` is the height to begin scanning from, defaulting to Sapling
/// activation when absent.
///
/// **The safe direction is DOWN.** A birthday below the first note only costs
/// scanning time. A birthday above it means that note is never scanned, and the
/// wallet then reports a balance of zero for money that is really there —
/// indistinguishable, to the person looking at it, from having lost it.
///
/// This is the opposite of the right default for [`initialize_new_wallet`], where a
/// brand new seed cannot have history and the chain tip is correct.
///
/// Returns the account's birthday height, so the caller can tell the user how much
/// chain is about to be scanned.
pub async fn recover_wallet_from_seed(
    seed: &str,
    password: String,
    birthday: Option<u32>,
) -> Result<u32> {
    // Sapling activation. Everything this wallet can hold exists at or after it, so
    // it is the "I don't know" answer that cannot silently lose funds.
    const SAPLING_ACTIVATION: u32 = 419_200;

    // Validate before touching anything on disk. A mistyped phrase must not cost the
    // user the wallet that is already there.
    //
    // The error stays deliberately vague: bip39 messages can name the offending word
    // or its position, and a seed phrase must never reach a log or a dialog.
    let mnemonic = phrase_to_mnemonic(seed)
        .map_err(|_| anyhow::anyhow!("Invalid BIP-39 seed phrase"))?;

    if password.is_empty() {
        anyhow::bail!("a password is required — it encrypts the recovered wallet on this machine");
    }

    let birthday_height = birthday.unwrap_or(SAPLING_ACTIVATION);

    // Refuse a birthday above the chain. That value guarantees a wallet that can
    // never see its own funds, and the failure is silent — it simply reports zero
    // forever. Say the tip rather than clamping, so the caller learns the real number.
    //
    // A node being unreachable is not a reason to refuse: the default is already
    // safe, and demanding connectivity to recover a wallet would be its own trap.
    match current_chain_tip().await {
        Ok(tip) if birthday_height > tip => {
            anyhow::bail!(
                "birthday {birthday_height} is above the current chain tip {tip}. \
                 A wallet cannot start scanning from a block that does not exist yet, \
                 and would report a zero balance forever. Choose {tip} or lower."
            );
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("[recover] could not check the chain tip ({e}); continuing with {birthday_height}");
        }
    }

    let data_dir = crate::paths::as_string::app_data_dir()?;
    crate::paths::create_private_dir(&data_dir)?;

    // A fresh identity under the NEW password. This is the whole point: no prior
    // secret is consulted, so a forgotten password does not block recovery.
    //
    // use_yubikey is deliberately not a parameter. The hardware integration was a
    // mock, and a recovery path that can put a wallet behind a derived passphrase
    // nobody can reproduce is exactly the lockout this function exists to undo.
    let identity = age::x25519::Identity::generate();
    let identity_str = {
        use age::secrecy::ExposeSecret;
        identity.to_string().expose_secret().to_string()
    };

    let encryptor = age::Encryptor::with_user_passphrase(age::secrecy::Secret::new(password.clone()));
    let mut encrypted_identity = vec![];
    {
        let mut writer = encryptor.wrap_output(&mut encrypted_identity)?;
        std::io::Write::write_all(&mut writer, identity_str.as_bytes())?;
        writer.finish()?;
    }

    let identity_path = format!("{}/encryption-identity.txt", data_dir);
    let kept_identity = preserve_replaced_file(&identity_path)?;
    crate::paths::write_private(&identity_path, encrypted_identity)?;

    // Recovery always produces a PASSWORD wallet, so a stub left by whatever was in this
    // directory before must go. It is not tidiness: the stub is what puts a wallet in
    // YubiKey mode, so leaving one beside a passphrase-encrypted identity produces a
    // directory whose two halves disagree — unlock would take the device path and find a
    // file no device can open.
    //
    // The consequence is worth stating plainly rather than hiding: restoring from seed
    // DROPS YubiKey protection. Re-applying it needs a flag the restore flow does not
    // have yet, and silently keeping a mode the user was never asked about would be
    // worse than losing one they can re-enable deliberately.
    if let Ok(stub) = crate::paths::as_string::yubikey_stub_path() {
        if std::path::Path::new(&stub).exists() {
            preserve_replaced_file(&stub)?;
            let _ = std::fs::remove_file(&stub);
        }
    }

    // Everything from here can fail, and the identity above has ALREADY been replaced.
    // Left alone, a failure here hands the user a directory whose identity is encrypted
    // under the new password while the wallet database is missing or half-built: the old
    // password no longer opens anything, and the new one opens nothing worth opening.
    // Nothing is lost — the originals are under `.replaced-<stamp>` — but recovering them
    // means knowing that convention and renaming files by hand, which is not a bar to set
    // for someone who has just lost their password.
    //
    // So the fallible remainder runs in a closure and the failure path puts both files
    // back. `db_path` and `kept_db` are declared out here because the unwind needs them.
    let db_path = format!("{}/wallet.db", data_dir);
    let mut kept_db: Option<String> = None;

    let built = (|| -> Result<()> {
        // Store the supplied phrase, encrypted to the new identity.
        let recipient = identity.to_public();
        let seed_encryptor = age::Encryptor::with_recipients(
            vec![Box::new(recipient.clone()) as Box<dyn age::Recipient + Send>],
        )
        .ok_or_else(|| anyhow::anyhow!("could not prepare seed encryption"))?;
        let mut encrypted_mnemonic_bytes = vec![];
        {
            let mut writer = seed_encryptor.wrap_output(&mut encrypted_mnemonic_bytes)?;
            std::io::Write::write_all(&mut writer, mnemonic.phrase().as_bytes())?;
            writer.finish()?;
        }

        kept_db = preserve_replaced_file(&db_path)?;

        let mut wallet_db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, OsRng)
            .map_err(|e| anyhow::anyhow!("could not open the new wallet database: {:?}", e))?;
        zcash_client_sqlite::wallet::init::init_wallet_db(&mut wallet_db, None)
            .map_err(|e| anyhow::anyhow!("could not initialise the new wallet database: {:?}", e))?;

        let conn = rusqlite::Connection::open(&db_path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ext_zecboat_keystore_mnemonics (
                hd_seed_fingerprint BLOB NOT NULL UNIQUE,
                encrypted_mnemonic BLOB NOT NULL
            )",
            [],
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS market_invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_id TEXT NOT NULL UNIQUE,
                date TEXT NOT NULL,
                items TEXT NOT NULL,
                total_zec REAL NOT NULL,
                total_fiat_value REAL NOT NULL,
                txid TEXT NOT NULL
            )",
            [],
        )?;
        let seed_fp = seed_fingerprint(&mnemonic);
        conn.execute(
            "INSERT OR REPLACE INTO ext_zecboat_keystore_mnemonics (hd_seed_fingerprint, encrypted_mnemonic) VALUES (?1, ?2)",
            rusqlite::params![seed_fp, encrypted_mnemonic_bytes],
        )?;

        use zcash_client_backend::data_api::chain::ChainState;
        use zcash_client_backend::data_api::AccountBirthday;
        use zcash_client_backend::data_api::WalletWrite;
        use age::secrecy::SecretVec;
        use zcash_protocol::consensus::BlockHeight;

        let seed_secret = SecretVec::new(zeroize::Zeroizing::new(mnemonic.to_seed("")).to_vec());
        let chain_state = ChainState::empty(
            BlockHeight::from_u32(birthday_height),
            zcash_primitives::block::BlockHash([0; 32]),
        );
        let account_birthday = AccountBirthday::from_parts(chain_state, None);
        wallet_db
            .create_account("Recovered Wallet", &seed_secret, &account_birthday, None)
            .map_err(|e| anyhow::anyhow!("could not create the recovered account: {:?}", e))?;

        Ok(())
    })();

    if let Err(e) = built {
        // Was a hand-written unwind, duplicated here. Now the shared one — see
        // unwind_replacements, added by R4 when initialize_new_wallet and import_wallet
        // needed the same thing and copying it a third time would have been the mistake.
        return Err(unwind_replacements(
            &[
                Replaced { path: identity_path.clone(), kept: kept_identity },
                Replaced { path: db_path.clone(),       kept: kept_db.clone() },
            ],
            e,
            &data_dir,
            "recovery",
        ));
    }

    // Unlock as the recovered wallet, so the caller does not have to ask for the
    // password again immediately after setting it.
    *WALLET_PASSWORD.lock().unwrap() = Some(password);

    // The sync engine caches the last height it saw. Left alone it would report the
    // replaced wallet's progress against a database that starts at the birthday.
    WALLET_HEIGHT.store(0, Ordering::Relaxed);

    println!("[recover] wallet recovered; scanning from height {birthday_height}");
    if let Some(k) = kept_db {
        println!("[recover] previous wallet preserved at {k}");
    }
    if let Some(k) = kept_identity {
        println!("[recover] previous identity preserved at {k}");
    }

    Ok(birthday_height)
}

pub async fn import_wallet(seed: &str, birthday: Option<u32>) -> Result<()> {
    // Sapling activation. Everything this wallet can hold exists at or after it, so it is
    // the "I don't know" answer that cannot silently lose funds — the same constant and the
    // same reasoning as recover_wallet_from_seed.
    const SAPLING_ACTIVATION: u32 = 419_200;
    // Validation, and the string this wallet will KEEP: `mnemonic.phrase()` is the
    // NFKD-normalised, single-spaced form, the same one recover_wallet_from_seed stores.
    // The raw `seed` is never written anywhere — storing it as typed meant the export
    // showed the paste artefacts back to the user (F6).
    let mnemonic = phrase_to_mnemonic(seed)
        // The bip39 error is deliberately discarded: it can name the offending word or its
        // position, and a seed phrase must never reach a log or an error dialog.
        .map_err(|_| anyhow::anyhow!("IMPORT_WALLET_ERROR: Invalid BIP-39 seed phrase"))?;
    
    let db_path = crate::paths::as_string::wallet_db_path()?;
    
    // Routed through decrypt_identity() — it used to hardcode Decryptor::Passphrase and
    // would have refused a YubiKey wallet with a message about passphrase protection.
    let identity = decrypt_identity()?;
        
    // 2. Encrypt the new seed phrase
    let recipient = identity.to_public();
    let seed_encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient) as Box<dyn age::Recipient + Send>]).unwrap();
    let mut encrypted_mnemonic_bytes = vec![];
    {
        let mut writer = seed_encryptor.wrap_output(&mut encrypted_mnemonic_bytes)?;
        std::io::Write::write_all(&mut writer, mnemonic.phrase().as_bytes())?;
        writer.finish()?;
    }
    
    let birthday_height = birthday.unwrap_or(SAPLING_ACTIVATION);

    // Refuse a birthday above the chain, the same guard recover_wallet_from_seed carries:
    // that value guarantees a wallet that can never scan the block its funds are in, and
    // would report a zero balance forever. Say the tip rather than clamping, so the caller
    // learns the real number.
    match current_chain_tip().await {
        Ok(tip) if birthday_height > tip => {
            anyhow::bail!(
                "birthday {birthday_height} is above the current chain tip {tip}. \
                 A wallet born above the tip can never scan the block its funds are in \
                 and would report a zero balance forever. Choose {tip} or lower."
            );
        }
        Ok(_) => {}
        Err(e) => eprintln!("[import] could not check the chain tip ({e}); continuing with {birthday_height}"),
    }

    // 3. Save to database and clear old synced blocks
    // CRITICAL: A new wallet must be completely clean. Destroy any existing database.
    let kept_db = preserve_replaced_file(&db_path)?;

    // R4: the remainder can fail with the database already moved aside, leaving a wallet
    // directory with an identity and no database. The closure body is synchronous, which
    // is why the tip check above was moved ahead of it.
    let built = (|| -> Result<()> {
    
    let mut wallet_db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, OsRng)
        .map_err(|e| anyhow::anyhow!("Failed to open wallet DB: {:?}", e))?;

    zcash_client_sqlite::wallet::init::init_wallet_db(&mut wallet_db, None)
        .map_err(|e| anyhow::anyhow!("Failed to init wallet DB: {:?}", e))?;

    // `if let Ok(conn) = ...` swallowed a failed open: the block was skipped, the account
    // below was still created, and Ok(()) returned — leaving a wallet that holds an account
    // and NO stored mnemonic, unable to ever export its own seed. The import would have
    // reported success.
    {
        let conn = rusqlite::Connection::open(&db_path).map_err(|e| {
            anyhow::anyhow!(
                "import failed: the wallet database could not be opened to store the seed \
                 phrase ({e}). Nothing has been imported; the previous wallet was moved \
                 aside and can be put back."
            )
        })?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ext_zecboat_keystore_mnemonics (
                hd_seed_fingerprint BLOB NOT NULL UNIQUE,
                encrypted_mnemonic BLOB NOT NULL
            )",
            [],
        )?;
        
        let seed_fp = seed_fingerprint(&mnemonic);
        conn.execute(
            "INSERT OR REPLACE INTO ext_zecboat_keystore_mnemonics (hd_seed_fingerprint, encrypted_mnemonic) VALUES (?1, ?2)",
            rusqlite::params![seed_fp, encrypted_mnemonic_bytes],
        )?;
    }
    
    // Derive the imported account
    use zcash_client_backend::data_api::WalletWrite;
    use zcash_client_backend::data_api::AccountBirthday;
    use zcash_client_backend::data_api::chain::ChainState;
    use zcash_protocol::consensus::BlockHeight;
    use age::secrecy::SecretVec;
    
    let seed_secret = SecretVec::new(zeroize::Zeroizing::new(mnemonic.to_seed("")).to_vec());

    // An imported seed may have received funds at any past height. A birthday set later
    // than a note's block means that note is never scanned, and the wallet reports zero
    // for money that is really there — indistinguishable, to the person looking at it,
    // from having lost it.
    //
    // This was hardcoded to 3,364,599 under a comment that named the fix and deferred it:
    // "the real fix is to ask the user for their wallet's birthday during import". R5 did
    // that. `None` now means Sapling activation, the answer that cannot silently lose
    // funds, and Settings offers the height as restore always did.
    let birthday_height = birthday.unwrap_or(SAPLING_ACTIVATION);


    let chain_state = ChainState::empty(BlockHeight::from_u32(birthday_height), zcash_primitives::block::BlockHash([0; 32]));
    let birthday = AccountBirthday::from_parts(chain_state, None);
    wallet_db.create_account("Imported Wallet", &seed_secret, &birthday, None)
        .map_err(|e| anyhow::anyhow!("Failed to create account: {:?}", e))?;
    
        Ok(())
    })();

    if let Err(e) = built {
        let data_dir = crate::paths::as_string::app_data_dir()?;
        return Err(unwind_replacements(
            &[Replaced { path: db_path, kept: kept_db }],
            e,
            &data_dir,
            "importing the wallet",
        ));
    }

    // Trigger the rescan in the UI by resetting the mock wallet height
    WALLET_HEIGHT.store(birthday_height as u64, Ordering::Relaxed);

    Ok(())
}

pub async fn get_transactions() -> Result<Vec<Value>> {
    let db_path_str = crate::paths::as_string::wallet_db_path()?;
    let db_path = db_path_str.as_str();
    // Confirmations need the tip. A node being unreachable must not empty the
    // history — the transactions are still real, they just cannot be aged.
    let chain_tip = current_chain_tip().await.ok();

    if let Ok(pool) = crate::db::WalletPool::new(db_path) {
        match pool.get_transactions(chain_tip).await {
            Ok(txs) => return Ok(txs),
            // Previously an `if let Ok(...)` that fell through to an empty list, so a
            // query error and "no transactions" looked identical to the user.
            Err(e) => println!("[tx] could not read transaction history: {e:#}"),
        }
    }
    Ok(vec![])
}

pub async fn get_invoices() -> Result<Vec<Value>> {
    let db_path_str = crate::paths::as_string::wallet_db_path()?;
    let db_path = db_path_str.as_str();
    if let Ok(pool) = crate::db::WalletPool::new(db_path) {
        if let Ok(invoices) = pool.get_invoices().await {
            let mut json_invs = Vec::new();
            for i in invoices {
                json_invs.push(serde_json::to_value(i).unwrap());
            }
            return Ok(json_invs);
        }
    }
    Ok(vec![])
}

pub async fn add_invoice(invoice_id: String, date: String, items: String, total_zec: f64, total_fiat_value: f64, txid: String) -> Result<()> {
    let db_path_str = crate::paths::as_string::wallet_db_path()?;
    let db_path = db_path_str.as_str();
    if let Ok(pool) = crate::db::WalletPool::new(db_path) {
        pool.add_invoice(invoice_id, date, items, total_zec, total_fiat_value, txid).await?;
    }
    Ok(())
}

/// List the ZMAP Layer-2 assets this wallet holds.
///
/// Detection is [`crate::zmap`]'s: a note is an asset only if its value is **exactly**
/// [`crate::zmap::CARRIER_ZAT`] *and* its memo parses as one of the two ZMAP dialects. Holdings are
/// grouped by `asset_id` and counted, so semi-fungible editions report their true quantity.
///
/// `asset_id`, `name` and `amount` are kept for the existing gallery bindings; `amount` is the
/// carrier count. The remaining fields are additive.
pub async fn get_zsas() -> Result<Vec<Value>> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    // Wake (chapter 8): collect any lading a carrier's memo commits to that this wallet does
    // not hold. Best effort; a fetch failure must not hide the holdings.
    // In a thread nobody waits for, with a budget, for assets this wallet has a reason to
    // trust; the item list used to wait 20 s on any line a stranger sent (review 2026-10-09,
    // Knotline A). Its result lands in the database and shows on the next open.
    crate::wake::fetch_missing_consignments_in_background(db_path.clone());
    let pool = crate::db::WalletPool::new(&db_path)?;
    let holdings = pool.get_zmap_holdings().await?;
    let ladings: std::collections::HashMap<String, crate::zmap::Consignment> = {
        let p = db_path.clone();
        tokio::task::spawn_blocking(move || -> Result<_> {
            let conn = rusqlite::Connection::open(&p)?;
            Ok(crate::zmap::list_consignments(&conn)?
                .into_iter()
                .map(|c| (c.asset_id.clone(), c))
                .collect())
        })
        .await??
    };

    Ok(holdings
        .into_iter()
        .map(|h| {
            let lading = ladings.get(&h.asset_id);
            let committed = h.carriers.iter().filter_map(|c| c.consignment_hash.clone()).next();
            serde_json::json!({
                "wake": {
                    "has_lading":       lading.is_some(),
                    "consignment_hash": committed,
                    "verified_at_height": lading.and_then(|c| c.verified_at_height),
                    "hops": lading.and_then(|c| zmap_wake::lading::Lading::parse(&c.json).ok()).map(|l| l.hops.len()),
                },
                "asset_id":     h.asset_id,
                "name":         h.name,
                "amount":       h.quantity,
                "quantity":     h.quantity,
                "symbol":       h.symbol,
                "decimals":     h.decimals,
                "image_hash":   h.image_hash,
                "metadata_uri": h.metadata_uri,
                "dialect":      h.dialect,
                "pools":        h.carriers.iter().map(|c| c.pool_name.clone()).collect::<Vec<_>>(),
            })
        })
        .collect())
}

/// Fetch an asset's published metadata over HTTPS.
///
/// # Why this is not an RPC call
///
/// Until 2026-08-13 this posted `z_viewasset` to `http://127.0.0.1:8238` with hardcoded credentials.
/// That method **does not exist** on the node: it was only ever implemented in the ZecBoat Glass
/// fork, which listened on `:8237`, and even there it did no chain lookup — it fetched
/// `https://zecboat.com/collection/{asset_id}.json`, exactly as this does now.
///
/// The deeper reason is structural: **a node cannot see Layer-2 assets at all.** It holds no viewing
/// keys, so it cannot decrypt the memo that carries the asset's identity. No RPC extension fixes
/// that. The wallet already holds the keys and the memo, so metadata is the only thing left to
/// fetch, and it lives on the web.
///
/// The URL is derived from the `asset_id`, which for both dialects is the SHA-256 of the artwork.
/// That makes the fetched image verifiable against the memo without trusting the host — only the
/// descriptive fields require trust.
///
/// **Never fabricates.** An unreachable or missing record is an error. The pre-v0.5.1 version
/// returned invented `total_supply` / `asset_name` / `issue_height` on failure, which the UI had no
/// way to distinguish from chain data.
pub async fn view_asset(asset_id: String) -> Result<String> {
    if asset_id.len() != 64 || !asset_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "Not a valid ZMAP asset id (expected 64 hex characters): {}",
            asset_id
        ));
    }

    // Only the configured registry, by asset id. The memo's own `metadata_uri` is never fetched:
    // it is written by whoever made the carrier, so fetching it told that party the holder's
    // address and the moment the item was opened (audit 2026-10-08, ZMAP D / Zecboat A). No
    // redirects, https only, and a bounded body.
    let url = format!("{}/collection/{}.json", registry_base(), asset_id);
    const MAX_METADATA_BYTES: usize = 256 * 1024;
    // Through the one registry client (https only, no redirects, no proxy, bounded): this fetch
    // still built its own client and followed a proxy from the environment (review 2026-10-09,
    // regression over 12-13, Issue D).
    let (_, body) = registry_fetch(&url, MAX_METADATA_BYTES)
        .await
        .map_err(|e| anyhow::anyhow!("No metadata published for {} ({})", asset_id, e))?;

    // A missing record is served as the site's HTML page rather than a 404, so the status code alone
    // is not proof. Require it to parse as JSON.
    let parsed: serde_json::Value = serde_json::from_slice(&body).map_err(|_| {
        anyhow::anyhow!(
            "No metadata published for {} — {} returned a page, not JSON",
            asset_id,
            url
        )
    })?;

    Ok(serde_json::to_string_pretty(&parsed)?)
}

/// Fetch an asset's artwork and verify it against the hash the memo commits to.
///
/// # What this proves, and what it does not
///
/// A ZMAP memo commits to `sha256(image)`. Fetching the artwork and re-hashing it proves **the
/// artwork matches what the memo committed to** — with no trust in the host serving it. Combined
/// with the wallet controlling the carrier note, that is the honest pair of claims:
///
/// - *this artwork matches the memo's commitment*, and
/// - *this wallet controls this note*.
///
/// It does **not** prove authenticity, scarcity or ownership history. There is no protocol-level
/// asset support, so nothing prevents a third party minting a carrier with the same memo. The Glass
/// README claimed the image hash was "required to mathematically prove your ownership"; it is not,
/// and this wallet must not repeat that.
///
/// # Why the verified bytes are returned
///
/// The response carries the image as a `data:` URI. That is deliberate: if the UI verified one fetch
/// and then rendered `<img src="https://…">` separately, it would display bytes nobody checked, and
/// the verification would be decorative. Returning the checked bytes makes the displayed image the
/// verified image.
///
/// The URL is derived from the **memo's** hash, never from host-supplied metadata, so a tampered
/// metadata record cannot redirect the fetch.
/// Everything the wallet can honestly say about itself, for the About panel.
///
/// **Why the build hash is here.** Until now the only way to know which binary was running was
/// the launcher script printing it, or `/proc/<pid>/fd`. A wallet holding real funds should be
/// able to answer "what am I running?" from inside itself, so a user can compare it against the
/// published `SHA256SUMS` without a terminal.
///
/// **And the honest limit that ships with it:** a tampered binary can lie about its own hash.
/// This is a convenience for comparing against the published sums, **not** a security control.
/// Saying so is the difference between a useful field and a false one.
///
/// The pinned issuer keys are included because the badge claims to check against "a key pinned
/// in this wallet" — and that claim should be inspectable rather than taken on faith.
pub async fn wallet_about() -> Result<Value> {
    use sha2::{Digest, Sha256};

    // Hash of the running executable. Failure here is not an error: a packaged build may live
    // somewhere unreadable, and "unknown" is a better answer than refusing to render the panel.
    let (build_hash, exe_path) = match std::env::current_exe() {
        Ok(p) => {
            let h = std::fs::read(&p)
                .map(|b| format!("{:x}", Sha256::digest(&b)))
                .unwrap_or_else(|_| "unreadable".into());
            (h, p.display().to_string())
        }
        Err(_) => ("unknown".into(), "unknown".into()),
    };

    Ok(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "build_hash": build_hash,
        "build_hash_caveat":
            "This is the SHA-256 of the running program, computed by the running program. \
             Compare it with SHA256SUMS from the download page. A tampered binary could report \
             a hash it is not — this is a convenience, not a security control.",
        "executable": exe_path,
        "wallet_db": crate::paths::as_string::wallet_db_path().unwrap_or_else(|e| e.to_string()),
        "node": grpc_endpoint(),
        "registry": registry_base(),
        "pinned_issuers": crate::issuance::pinned_issuers(),
        "release_key": "e23a2fed8f8134005ba47a3d800509678ef913d65dbe8e39d2cffc778219ed0d",
        // The next network upgrade this build does not follow. NU7 (ZIP 259) activates on
        // mainnet on 5 November 2026; from that block this build cannot sync or send. The UI
        // shows one line until a build that follows it ships; a build that does sets `null`.
        "upgrade_notice": {
            "name": "NU7",
            "date": "5 November 2026",
            "update_to": "0.7.2",
        },
        "does_not": [
            "Mint. Issuance is a separate application with separate keys — a wallet that can mint is a wallet that can forge.",
            "Prove how many of an asset exist. No ZMAP asset can; see ZMAP-v0.3 §13.",
            "Prove who holds an asset now. Shielded notes do not reveal ownership, to anyone, including us.",
            "See your holdings — and for the same reason, recover them for you."
        ]
    }))
}

/// Pre-flight for the send screen: can this wallet pay a fee, and what is in the way?
///
/// Returned BEFORE a send is attempted, so the UI can explain the constraint instead of
/// surfacing `InsufficientFunds { available: 10000, required: 20000 }` against a balance it is
/// showing as healthy.
pub async fn fee_readiness() -> Result<Value> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let pool = crate::db::WalletPool::new(&db_path)?;
    let r = pool.fee_readiness().await?;
    Ok(serde_json::to_value(r)?)
}

/// Formats the registry may publish. The extension is **routing only**: verification is by hash.
const IMAGE_EXTENSIONS: [&str; 4] = ["png", "jpg", "jpeg", "webp"];

/// Every URL to try for an asset's artwork, in order: the **asset id** in each format.
///
/// Collections publish each image under its asset id, as their signed manifest names it
/// (`/collection/<asset_id>.jpg`); for a pre-v1 asset the asset id is the image hash, so the
/// same rule covers both. The memo's `image_hash` is never put in a URL (audit 2026-10-08,
/// Zecboat B / ZMAP J): it is chosen by whoever wrote the memo, so a sender could plant a
/// unique value and learn from the registry's logs when, and from where, the item is opened.
/// It is still what the fetched image must hash to. On 2026-10-08 every published image on
/// zecboat.com was reachable by its asset id, so nothing is lost.
fn artwork_candidate_urls(base: &str, asset_id: &str) -> Vec<String> {
    IMAGE_EXTENSIONS
        .iter()
        .map(|ext| format!("{}/collection/{}.{}", base, asset_id, ext))
        .collect()
}

/// Every request to the registry goes through one client: https only, no redirects, a
/// timeout, and a body bound chosen by the caller. Until 2026-10-09 only the metadata fetch
/// had these; artwork and manifests followed redirects to any host and read without bound
/// (review, regression Finding 10). `file://` sources are read directly, for tests.
pub(crate) async fn registry_fetch(url: &str, max_bytes: usize) -> Result<(String, Vec<u8>)> {
    if let Some(path) = url.strip_prefix("file://") {
        let b = std::fs::read(path).map_err(|e| anyhow::anyhow!("{path}: {e}"))?;
        return Ok((String::new(), b));
    }
    if !url.starts_with("https://") {
        return Err(anyhow::anyhow!("the registry is reached over https only ({url})"));
    }
    // `no_proxy`: reqwest's default client follows HTTP(S)_PROXY/ALL_PROXY from the
    // environment, which is one more way to redirect a registry request (review 2026-10-09,
    // session 4, Issue M).
    let res = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(30))
        .build()?
        .get(url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
    if !res.status().is_success() {
        return Err(anyhow::anyhow!("{url}: HTTP {}", res.status()));
    }
    let content_type = res
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if res.content_length().map(|n| n as usize > max_bytes).unwrap_or(false) {
        return Err(anyhow::anyhow!("{url}: larger than {max_bytes} bytes"));
    }
    let mut body = Vec::new();
    let mut res = res;
    while let Some(chunk) = res.chunk().await.map_err(|e| anyhow::anyhow!("{url}: {e}"))? {
        if body.len() + chunk.len() > max_bytes {
            return Err(anyhow::anyhow!("{url}: larger than {max_bytes} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((content_type, body))
}

/// Artwork is bounded at this size: a photograph as JPEG is a few hundred kilobytes.
const MAX_ARTWORK_BYTES: usize = 8 * 1024 * 1024;

pub async fn verify_asset_image(asset_id: String) -> Result<Value> {
    if asset_id.len() != 64 || !asset_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "Not a valid ZMAP asset id (expected 64 hex characters): {}",
            asset_id
        ));
    }

    // The hash to check against comes from the memo we hold, not from anything fetched. For legacy
    // prose memos the asset id *is* the image hash; for JSON memos an explicit `image_hash` wins.
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let expected = match crate::db::WalletPool::new(&db_path) {
        Ok(pool) => pool
            .get_zmap_holdings()
            .await
            .ok()
            .and_then(|hs| hs.into_iter().find(|h| h.asset_id == asset_id))
            .and_then(|h| h.image_hash),
        Err(_) => None,
    }
    .unwrap_or_else(|| asset_id.clone());

    // Formats the registry may publish. The extension is **routing only** — verification is by
    // hash, so accepting several formats costs nothing: artwork served under the wrong extension,
    // or substituted for a different image, still fails the hash check below. PNG is tried first
    // because it was the original convention; JPEG matters because photographic artwork is roughly
    // an order of magnitude smaller as JPEG, which is what makes a large collection practical.
    let mut attempts: Vec<String> = Vec::new();
    let mut found: Option<(String, String, bytes::Bytes)> = None;
    let mut first_unverified: Option<(String, String, bytes::Bytes)> = None;

    for url in artwork_candidate_urls(&registry_base(), &asset_id) {
        let (content_type, body) = match registry_fetch(&url, MAX_ARTWORK_BYTES).await {
            Ok(r) => r,
            Err(e) => {
                attempts.push(format!("{e}"));
                continue;
            }
        };
        // A missing artefact is served as the site's HTML page with HTTP 200, so the status code
        // alone proves nothing. Require an image content type before spending time hashing it,
        // and treat a non-image as "not published in this format", not as a hard failure, so the
        // next extension still gets a turn.
        if !content_type.starts_with("image/") {
            attempts.push(format!(
                "{} ({})",
                url,
                if content_type.is_empty() { "no content type" } else { &content_type }
            ));
            continue;
        }
        let b = bytes::Bytes::from(body);
        // A wrong file at one name must not hide the right file at the next: keep going until
        // something hashes to `expected`. If nothing does, the first image found is reported
        // as not verified, as before.
        if crate::zmap::verify_image(&b, &expected).unwrap_or(false) {
            found = Some((url, content_type, b));
            break;
        }
        attempts.push(format!("{} (hash mismatch)", url));
        if first_unverified.is_none() {
            first_unverified = Some((url, content_type, b));
        }
    }
    let found = found.or(first_unverified);

    let (url, content_type, bytes) = found.ok_or_else(|| {
        anyhow::anyhow!(
            "No artwork published for {} in any supported format.\nTried:\n  {}",
            asset_id,
            attempts.join("\n  ")
        )
    })?;

    let actual = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&bytes))
    };
    let verified = crate::zmap::verify_image(&bytes, &expected)?;

    // The registry names every artefact `<name>.<ext>` and a static host derives
    // `Content-Type` from that extension alone. When the two disagree -- a JPEG stored under
    // `.png`, which is exactly what the Happy Birthday collection is -- the server confidently
    // answers `image/png`, and a data URI built from that claim declares PNG while carrying
    // JPEG bytes. Every WebView refuses to render it, so the artwork is blank even though
    // verification passed and the hash matched.
    //
    // The file cannot be corrected: its sha256 **is** the asset id, so re-encoding it to a real
    // PNG would change the identity of the asset. Renaming does not help either, because `png`
    // is tried first and answers 200.
    //
    // So trust the bytes, never the label. The extension is documented above as "routing only";
    // this applies the same rule to rendering.
    fn sniff_image_mime(b: &[u8]) -> Option<&'static str> {
        if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
            return Some("image/jpeg");
        }
        if b.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
            return Some("image/png");
        }
        if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
            return Some("image/gif");
        }
        if b.len() >= 12 && b.starts_with(b"RIFF") && &b[8..12] == b"WEBP" {
            return Some("image/webp");
        }
        None
    }
    let render_type = sniff_image_mime(&bytes)
        .map(|s| s.to_string())
        .unwrap_or_else(|| content_type.clone());

    // Only hand back renderable bytes when they are the bytes that passed. A caller cannot then
    // display unverified artwork by accident.
    let data_uri = if verified {
        use base64::Engine;
        Some(format!(
            "data:{};base64,{}",
            render_type,
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        ))
    } else {
        None
    };

    Ok(serde_json::json!({
        "asset_id":      asset_id,
        "verified":      verified,
        "expected_hash": expected,
        "actual_hash":   actual,
        "source_url":    url,
        "bytes":         bytes.len(),
        "served_type":   content_type,
        "actual_type":   render_type,
        "image":         data_uri,
    }))
}

/// Hardware-wallet signing. **Not implemented — fails loudly.**
///
/// 2026-08-13: this previously returned
///
/// ```text
/// format!("sig_hardware_{}_simulated", tx_data)
/// ```
///
/// a fabricated signature string. `SendView.svelte` and `MarketCheckoutView.svelte`
/// call it whenever the user ticks *use hardware wallet*, so the user was told
/// their YubiKey had signed the transaction when nothing had signed anything.
///
/// It is also handed `amount=…&to=…&memo=…` — a formatted string, not a
/// transaction — so even a correct implementation could not sign what it
/// receives. Implementing this properly means passing the actual transaction and
/// having the device produce a real signature over it.
///
/// Returning an error is the honest state until that work is done. A simulated
/// signature is worse than no feature, because the user cannot tell the
/// difference.
pub async fn sign_transaction_with_hardware(_tx_data: &str) -> Result<String> {
    anyhow::bail!(
        "Hardware wallet signing is not implemented in this build.\n\
         \n\
         Send without the hardware wallet option, or use a build where this is \
         supported. Previous versions of this app returned a simulated signature \
         here, which could not be distinguished from a real one."
    )
}

pub async fn shield_transparent() -> Result<String> {
    use zcash_protocol::consensus::MainNetwork;
    use zcash_client_sqlite::WalletDb;
    use zcash_client_sqlite::util::SystemClock;
    use rand::rngs::OsRng;
    use zcash_proofs::prover::LocalTxProver;
    use zcash_client_backend::data_api::wallet::shield_transparent_funds;
    use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector;
    use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
    use zcash_client_backend::fees::{StandardFeeRule, DustOutputPolicy};
    use zcash_protocol::ShieldedPool;
    use zcash_client_backend::data_api::wallet::{SpendingKeys, ConfirmationsPolicy};
    use zcash_client_backend::data_api::WalletRead;

    let db_path = crate::paths::as_string::wallet_db_path()?;
    // Routed through decrypt_identity() so this works on a YubiKey wallet too; it used
    // to hardcode Decryptor::Passphrase and would have refused one outright.
    let identity = decrypt_identity()?;

    let mut wallet_db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, OsRng)?;
    zcash_client_sqlite::wallet::init::init_wallet_db(&mut wallet_db, None)?;

    let encrypted_mnemonic_bytes: Vec<u8> = {
        let conn = rusqlite::Connection::open(&db_path)?;
        let mut stmt = conn.prepare("SELECT encrypted_mnemonic FROM ext_zecboat_keystore_mnemonics LIMIT 1")?;
        let mut rows = stmt.query([])?;
        let row = rows.next()?.ok_or_else(|| anyhow::anyhow!("No mnemonic found in database"))?;
        row.get(0)?
    };

    let mnemonic_decryptor = match age::Decryptor::new(&encrypted_mnemonic_bytes[..]) {
        Ok(age::Decryptor::Recipients(d)) => d,
        // A malformed blob previously panicked the whole backend here via `.unwrap()`,
        // taking the application down with no message. The wallet database holds this
        // blob, so corruption on disk — a truncated write, a bad restore — reached the
        // user as a crash rather than an explanation.
        Ok(_) => return Err(anyhow::anyhow!(
            "the encrypted seed phrase in this wallet is not in the expected format. \
             The wallet database may be damaged; restore from a backup."
        )),
        Err(e) => return Err(anyhow::anyhow!(
            "could not read the encrypted seed phrase from this wallet ({e}). The wallet \
             database may be damaged or truncated; restore from a backup — remember it is \
             two files, the database and the encryption identity, and you need both."
        )),
    };

    let mut mnemonic_reader = mnemonic_decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("Failed to decrypt mnemonic: {:?}", e))?;
    let mut decrypted_mnemonic = vec![];
    std::io::Read::read_to_end(&mut mnemonic_reader, &mut decrypted_mnemonic).unwrap();

    let seed_str = zeroize::Zeroizing::new(String::from_utf8(decrypted_mnemonic)?);
    // The one spend-path derivation (wallet.rs). Its error never echoes a seed word.
    let usk = crate::wallet::spending_key_from_phrase(&seed_str)?;
    let spending_keys = SpendingKeys::new(usk);

    // Load Zcash parameters for proving
    let prover = LocalTxProver::with_default_location()
        .ok_or_else(|| anyhow::anyhow!("{}", crate::native_builder::params_not_found()))?;

    let input_selector = GreedyInputSelector::<WalletDb<rusqlite::Connection, MainNetwork, SystemClock, OsRng>>::new();
    let change_strategy = SingleOutputChangeStrategy::<WalletDb<rusqlite::Connection, MainNetwork, SystemClock, OsRng>>::new(
        StandardFeeRule::Zip317,
        None,
        // W3, 2026-08-11. This read `ShieldedProtocol::Sapling` with the comment
        // "Target pool must be Sapling under NU6.3 consensus!" — a workaround from
        // when the crates predated Ironwood. It was half true: NU6.3 froze Orchard,
        // so shielding there would have been rejected, and Sapling was the only
        // pool the old stack could still reach. But it shielded into a dead-end
        // pool with no asset support.
        //
        // On the 0.24 crates Ironwood is available, and it is what
        // ironwood_shield/src/shield_iw.rs:167 used for the transaction mined at
        // height 3,430,966.
        ShieldedPool::Ironwood,
        DustOutputPolicy::default(),
    );

    let account_id = wallet_db.get_account_ids()?.into_iter().next().ok_or_else(|| anyhow::anyhow!("No accounts found"))?;
    
    // Find transparent addresses to shield
    let receivers = wallet_db.get_transparent_receivers(account_id, true, true)?;
    if receivers.is_empty() {
        return Err(anyhow::anyhow!("No transparent addresses found for account."));
    }

    let mut taddrs = vec![];
    for (addr, _) in receivers {
        taddrs.push(addr);
    }

    // Perform shielding
    let shielding_fee = zcash_protocol::value::Zatoshis::from_u64(10_000).unwrap();
    let txids = shield_transparent_funds(
        &mut wallet_db,
        &MainNetwork,
        &prover,
        &prover,
        &input_selector,
        &change_strategy,
        shielding_fee,
        &spending_keys,
        &taddrs,
        account_id,
        ConfirmationsPolicy::MIN,
    ).map_err(|e| anyhow::anyhow!("Auto-shielding failed: {:?}", e))?;

    if txids.is_empty() {
        return Err(anyhow::anyhow!("Failed to create shielding transaction."));
    }

    let txid = txids[0].to_string();
    
    // Submit transaction via our background connection to Zebrad
    let conn = rusqlite::Connection::open(&db_path)?;
    let raw_tx_hex: String = conn.query_row(
        "SELECT hex(raw) FROM transactions WHERE txid = ?1",
        rusqlite::params![txids[0].as_ref()],
        |row| row.get(0),
    )?;
    
    // Broadcast over the same gRPC channel used for sync (W6).
    //
    // The previous Port branch here discarded the HTTP response entirely, so a
    // rejected broadcast still reported "Successfully shielded". broadcast_raw_tx
    // returns an Err on any non-zero error code, so failures now surface.
    let broadcast_txid = broadcast_raw_tx(&raw_tx_hex).await?;

    // The node echoes the txid it accepted. If it disagrees with what the wallet
    // recorded, say so rather than quietly reporting the local value.
    if !broadcast_txid.is_empty() && broadcast_txid != txid {
        return Ok(format!(
            "Shielded transparent funds, but the node reported a different TxID.\n  wallet: {}\n  node:   {}",
            txid, broadcast_txid
        ));
    }

    Ok(format!("Successfully shielded transparent funds! TxID: {}", txid))
}

/// Create an additional account. **Not implemented — fails loudly.**
///
/// 2026-08-13: this previously returned the string
/// `"Account #1 derived successfully."` and **did nothing whatsoever** — no
/// derivation, no database write. Settings → Create New Account reported success
/// every time and created nothing.
///
/// Implementing it means `WalletWrite::create_account` with a seed and a
/// birthday, plus UI for choosing which account is active — the app is
/// single-account throughout. Until that exists, an error is the honest answer.
pub async fn create_new_account() -> Result<String> {
    anyhow::bail!(
        "Creating additional accounts is not supported in this build.\n\
         \n\
         This wallet uses a single account. Earlier versions reported success \
         here without deriving anything."
    )
}

/// `wallet_backup_<stamp>.db` → `wallet_backup_<stamp><suffix>`. `strip_suffix` rather than
/// `replace(".db", …)`, which would rewrite every occurrence of `.db` in the path.
fn backup_sidecar(db_backup_path: &str, suffix: &str) -> String {
    format!("{}{}", db_backup_path.strip_suffix(".db").unwrap_or(db_backup_path), suffix)
}

pub async fn backup_wallet() -> Result<String> {
    let backup_dir = crate::paths::as_string::backup_dir()?;
    crate::paths::create_private_dir(&backup_dir)?;
    let db_path = crate::paths::as_string::wallet_db_path()?;
    // A clock set before 1970 makes `duration_since` return Err, and `.unwrap()` would
    // then panic the backend while the user was trying to *back up their wallet* — the
    // worst possible moment. Fall back to 0 rather than crash; a badly named backup is
    // still a backup.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Two backups inside one second would overwrite each other silently — the same
    // as_secs() defect fixed in preserve_replaced_file, still here. The contents would be
    // identical, but "the backup I took before the change" must remain findable.
    let mut backup_path = format!("{}/wallet_backup_{}.db", backup_dir, stamp);
    let mut n = 1;
    while std::path::Path::new(&backup_path).exists() {
        backup_path = format!("{}/wallet_backup_{}.{}.db", backup_dir, stamp, n);
        n += 1;
    }

    // A BACKUP IS BOTH FILES OR IT IS NOTHING.
    //
    // This used to copy wallet.db alone. `paths::identity_path` has said why that is
    // wrong since it was written: "The wallet will not open without this file, so it is
    // always a pair with wallet_db_path. Backups that carry one without the other are
    // useless." The database holds the seed encrypted to an X25519 key that exists only
    // in encryption-identity.txt, and BOTH `initialize_new_wallet` and
    // `recover_wallet_from_seed` ROTATE that file. So a user who backed up, later
    // recovered from seed, then restored the backup would get a wallet that displays the
    // old balance and cannot spend a zatoshi of it — the only key to it sitting in a
    // `.replaced-<stamp>` file nobody told them about.
    //
    // The 24 words remain the real recovery path. But a button labelled "Backup" that
    // produces something which cannot restore is worse than no button, because it ends
    // the user's search for safety.
    let identity_path = crate::paths::as_string::identity_path()?;
    if !std::path::Path::new(&identity_path).exists() {
        anyhow::bail!(
            "refusing to back up: {} is missing. A wallet database without its encryption \
             identity cannot be opened, so a backup of one without the other would be a \
             backup in name only.",
            identity_path
        );
    }
    let identity_backup = backup_sidecar(&backup_path, ".identity.txt");

    // THE THIRD FILE. `paths::yubikey_stub_path` has said since it was written that the
    // stub "is as much a pair with identity_path as that file is with wallet_db_path":
    // unlock decides its MODE by whether the stub exists. A YubiKey wallet's identity is
    // encrypted to the card; restored without the stub it is opened by the password
    // branch and refused with a message about a damaged file — to a user holding the
    // right key and PIN. Found by review 2026-09-25, in the function R1–R3 had just fixed.
    let stub_path = crate::paths::as_string::yubikey_stub_path()?;
    let has_stub = std::path::Path::new(&stub_path).exists();
    let stub_backup = backup_sidecar(&backup_path, ".yubikey.txt");

    // CHECKPOINT FIRST, OR THE COPY IS INCOMPLETE.
    //
    // The wallet runs in WAL mode (see the PRAGMA in start_sync_engine) and `WalletPool` is
    // a deadpool that holds connections open, so SQLite never checkpoints on close. A bare
    // copy of `wallet.db` mid-session therefore omits every committed transaction still
    // sitting in the log, and can catch the main file mid-checkpoint.
    //
    // `preserve_replaced_file` states this hazard twice, twenty lines from here — "A `-wal`
    // holds committed transactions that have not yet been folded into the main file". That
    // reasoning was applied to restore and not to backup, in the same session, by the same
    // hand. Found by review 2026-09-24.
    //
    // Refusing beats writing a quiet half-backup: the whole point of this function is that
    // what it produces can be restored.
    {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| anyhow::anyhow!("backup aborted: could not open the wallet to \
                                          checkpoint it ({e})"))?;
        let (busy, log_frames, _checkpointed): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .map_err(|e| anyhow::anyhow!("backup aborted: the write-ahead log could not be \
                                          folded into the database ({e})"))?;
        if busy != 0 || log_frames > 0 {
            anyhow::bail!(
                "backup aborted: the wallet's write-ahead log could not be folded into the \
                 database (busy={busy}, {log_frames} frames left). A copy taken now would \
                 silently omit recent transactions. This usually means the wallet is \
                 mid-sync or another window has it open; wait for sync to settle, or close \
                 the other window, and try again."
            );
        }
    }

    crate::paths::copy_private(&db_path, &backup_path)?;
    // If the second copy fails the first must not be left behind advertising itself as a
    // backup in `list_backups`.
    if let Err(e) = crate::paths::copy_private(&identity_path, &identity_backup) {
        let _ = std::fs::remove_file(&backup_path);
        return Err(anyhow::anyhow!(
            "backup aborted: the database copied but its encryption identity did not ({e}). \
             The partial copy has been removed rather than left looking like a usable backup."
        ));
    }
    if has_stub {
        if let Err(e) = crate::paths::copy_private(&stub_path, &stub_backup) {
            let _ = std::fs::remove_file(&backup_path);
            let _ = std::fs::remove_file(&identity_backup);
            return Err(anyhow::anyhow!(
                "backup aborted: the database and identity copied but the YubiKey stub did \
                 not ({e}). Without it the backup would restore into password mode and could \
                 not be unlocked, so the partial copy has been removed."
            ));
        }
    }

    Ok(if has_stub {
        format!(
            "Wallet backed up to {} (with its encryption identity and YubiKey stub beside it)",
            backup_path
        )
    } else {
        format!(
            "Wallet backed up to {} (with its encryption identity beside it)",
            backup_path
        )
    })
}

pub async fn restore_backup(backup_name: String) -> Result<String> {
    // The name is joined onto the backup directory. The UI only ever passes what
    // `list_backups` returned, but this command accepts any string, and a name carrying a
    // path would install an arbitrary file as the wallet database. Accept exactly the
    // shape `list_backups` produces: a bare filename ending in `.db`.
    let is_bare = std::path::Path::new(&backup_name)
        .file_name()
        .map(|f| f == backup_name.as_str())
        .unwrap_or(false);
    if backup_name.is_empty()
        || !is_bare
        || backup_name.contains('/')
        || backup_name.contains('\\')
        || !backup_name.ends_with(".db")
    {
        anyhow::bail!(
            "{:?} is not a backup name. Expected a bare filename ending in .db, as listed \
             by the backup picker.",
            backup_name
        );
    }
    let backup_dir = crate::paths::as_string::backup_dir()?;
    let backup_path = format!("{}/{}", backup_dir, backup_name);

    if !std::path::Path::new(&backup_path).exists() {
        return Err(anyhow::anyhow!("Backup file not found: {}", backup_path));
    }
    
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let identity_path = crate::paths::as_string::identity_path()?;

    // Safety: ensure data dir exists
    crate::paths::create_private_dir(crate::paths::as_string::app_data_dir()?)?;

    // THIS USED TO BE A BARE `std::fs::copy` ONTO THE LIVE DATABASE.
    //
    // Every other replacement in this file goes through `preserve_replaced_file` — 2481,
    // 2723, 2866. Restore was the one that did not, so it destroyed the current wallet
    // with no copy kept. If that wallet was created after the backup was taken and its
    // 24 words were never written down, the loss was total, from a button labelled
    // "restore".
    //
    // `preserve_replaced_file` also moves the `-wal` and `-shm` sidecars, which matters
    // more here than anywhere: a write-ahead log left beside a DIFFERENT database of the
    // same name gets replayed into it on first open, corrupting the thing just restored.
    // A bare copy cannot do that, so the old code could corrupt the backup it was
    // recovering.
    let kept_db = preserve_replaced_file(&db_path)?;

    // A backup taken before this change has no identity beside it. Restoring its database
    // over the current identity would produce precisely the mismatch this pairing exists
    // to prevent, so the two cases are handled differently and the user is told which
    // one happened.
    let identity_backup = backup_sidecar(&backup_path, ".identity.txt");
    let has_identity = std::path::Path::new(&identity_backup).exists();

    let kept_identity = if has_identity {
        preserve_replaced_file(&identity_path)?
    } else {
        None
    };

    // The YubiKey stub travels with the identity, and its presence IS the unlock mode. A
    // backup that carries one puts it back; a backup that carries none must not inherit
    // whatever stub this machine happens to have, or unlock tries the card on a
    // passphrase-encrypted identity. Either way the stub currently here is moved aside,
    // never deleted — same rule as everything else this function replaces.
    let stub_path = crate::paths::as_string::yubikey_stub_path()?;
    let stub_backup = backup_sidecar(&backup_path, ".yubikey.txt");
    let has_stub_backup = std::path::Path::new(&stub_backup).exists();
    let kept_stub = if has_identity && std::path::Path::new(&stub_path).exists() {
        preserve_replaced_file(&stub_path)?
    } else {
        None
    };

    // Everything below can fail with both originals already moved aside. Put them back
    // rather than leaving a half-restored directory, which is the state hardest for a
    // user to reason about and the one most likely to end in a wrong conclusion about
    // where their funds went.
    let restored = (|| -> Result<()> {
        crate::paths::copy_private(&backup_path, &db_path)?;
        if has_identity {
            crate::paths::copy_private(&identity_backup, &identity_path)?;
            if has_stub_backup {
                crate::paths::copy_private(&stub_backup, &stub_path)?;
            }
        }
        Ok(())
    })();

    if let Err(e) = restored {
        let _ = std::fs::remove_file(&db_path);
        if let Some(k) = &kept_db {
            let _ = std::fs::rename(k, &db_path);
        }
        if has_identity {
            let _ = std::fs::remove_file(&identity_path);
            if let Some(k) = &kept_identity {
                let _ = std::fs::rename(k, &identity_path);
            }
            let _ = std::fs::remove_file(&stub_path);
            if let Some(k) = &kept_stub {
                let _ = std::fs::rename(k, &stub_path);
            }
        }
        return Err(anyhow::anyhow!(
            "restore failed and the previous wallet has been put back: {e}"
        ));
    }

    // Wake (chapter 8): "restore re-verifies consignments against the node".
    let wake_note = crate::wake::reverify_after_restore().await;

    if has_identity {
        Ok(format!(
            "Restored wallet and encryption identity from {}{}. The previous wallet was \
             moved aside, not deleted.{wake_note}",
            backup_name,
            if has_stub_backup {
                " (YubiKey mode, stub restored)"
            } else if kept_stub.is_some() {
                " (password mode; this machine's YubiKey stub was moved aside)"
            } else {
                ""
            }
        ))
    } else {
        // Deliberately not an error: the database is still the right one to restore, and
        // refusing would strand anyone holding only an old backup. But it is the case
        // that ends in "I can see my balance and cannot send", so it says so plainly.
        Ok(format!(
            "Restored the database from {}, but this backup predates encryption-identity \
             backup and carries none. The identity already on this machine has been kept. \
             If they are not a matching pair the balance will display but nothing can be \
             sent — recover from your 24-word phrase instead if that happens. The previous \
             wallet was moved aside, not deleted.",
            backup_name
        ))
    }
}

pub async fn list_backups() -> Result<Vec<String>> {
    let backup_dir = crate::paths::as_string::backup_dir()?;
    let mut backups = Vec::new();
    
    if let Ok(entries) = std::fs::read_dir(backup_dir) {
        for entry in entries {
            if let Ok(entry) = entry {
                let file_name = entry.file_name().to_string_lossy().to_string();
                if file_name.ends_with(".db") {
                    backups.push(file_name);
                }
            }
        }
    }
    
    // Sort descending so newest is first (assuming names have timestamps)
    backups.sort_by(|a, b| b.cmp(a));
    Ok(backups)
}

fn extract_mnemonic_internal() -> Result<zeroize::Zeroizing<String>> {
    // Routed through decrypt_identity(): this is the function that hands back the seed
    // phrase, so it is the last place that should carry its own copy of the rule.
    let identity = decrypt_identity()?;

    let db_path = crate::paths::as_string::wallet_db_path()?;
    let encrypted_mnemonic_bytes: Vec<u8> = {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| anyhow::anyhow!("Failed to open DB for mnemonic: {:?}", e))?;
        let mut stmt = conn.prepare("SELECT encrypted_mnemonic FROM ext_zecboat_keystore_mnemonics LIMIT 1")
            .map_err(|e| anyhow::anyhow!("Failed to prepare mnemonic query: {:?}", e))?;
        let mut rows = stmt.query([])
            .map_err(|e| anyhow::anyhow!("Failed to execute mnemonic query: {:?}", e))?;
        let row = rows.next().map_err(|e| anyhow::anyhow!("DB error: {:?}", e))?
            .ok_or_else(|| anyhow::anyhow!("No encrypted mnemonic found in database"))?;
        row.get(0).map_err(|e| anyhow::anyhow!("Failed to read blob: {:?}", e))?
    };

    let mnemonic_decryptor = match age::Decryptor::new(&encrypted_mnemonic_bytes[..]) {
        Ok(age::Decryptor::Recipients(d)) => d,
        // A malformed blob previously panicked the whole backend here via `.unwrap()`,
        // taking the application down with no message. The wallet database holds this
        // blob, so corruption on disk — a truncated write, a bad restore — reached the
        // user as a crash rather than an explanation.
        Ok(_) => return Err(anyhow::anyhow!(
            "the encrypted seed phrase in this wallet is not in the expected format. \
             The wallet database may be damaged; restore from a backup."
        )),
        Err(e) => return Err(anyhow::anyhow!(
            "could not read the encrypted seed phrase from this wallet ({e}). The wallet \
             database may be damaged or truncated; restore from a backup — remember it is \
             two files, the database and the encryption identity, and you need both."
        )),
    };

    let mut mnemonic_reader = mnemonic_decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("Failed to decrypt mnemonic: {:?}", e))?;
    let mut decrypted_mnemonic = vec![];
    std::io::Read::read_to_end(&mut mnemonic_reader, &mut decrypted_mnemonic).unwrap();

    // F5. Wiped when the caller drops it. from_utf8 reuses the Vec's buffer, so there is
    // no second, unwiped copy left behind here.
    let phrase = zeroize::Zeroizing::new(
        String::from_utf8(decrypted_mnemonic)
            .map_err(|e| anyhow::anyhow!("decrypted seed phrase is not valid UTF-8: {e}"))?,
    );

    // THE CHECK NOTHING PERFORMED. Every caller of this function is about to use the seed
    // for something consequential — exporting it, deriving a viewing key, signing. If the
    // phrase stored here does not belong to the account this database describes, the wallet
    // would show one wallet's balance and sign with another's key, and nothing would say so
    // until a transaction went wrong.
    //
    // Checked here rather than at unlock because this is the narrowest place that covers
    // every dangerous path, and because unlock does not decrypt the mnemonic at all.
    {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| anyhow::anyhow!("Failed to open DB to verify the seed: {:?}", e))?;
        let m = phrase_to_mnemonic(&phrase)?;
        verify_seed_matches_account(&conn, &m)?;
    }

    Ok(phrase)
}

/// The recovery phrase, and nothing else, once the passphrase is given again (audit 2026-10-08,
/// Zecboat L). An unlocked wallet left open is not consent to show its seed: whoever reaches
/// the Settings screen must still know the passphrase. In YubiKey mode the typed string is the
/// PIN, which the device proved at unlock; it is compared with the one that opened the wallet,
/// so export needs no second touch. The phrase alone is returned, so a copy holds no prose.
pub async fn export_keys(passphrase: String) -> Result<String> {
    confirm_wallet_secret(&passphrase)?;
    let mnemonic = extract_mnemonic_internal()?;
    // The String handed to the UI is the one copy that cannot be wiped: it is displayed.
    Ok(mnemonic.as_str().to_string())
}

/// The passphrase (or, on a YubiKey wallet, the PIN proved on the device) asked again before
/// a secret is shown: an unlocked wallet left open is not consent to show its seed or its
/// viewing key (audit 2026-10-08, Zecboat L; review 2026-10-09, session 4, Issue J for the
/// viewing key).
fn confirm_wallet_secret(passphrase: &str) -> Result<()> {
    if WALLET_PASSWORD.lock().unwrap().is_none() {
        anyhow::bail!("the wallet is locked");
    }
    let stub_path = crate::paths::yubikey_stub_path()?;
    if stub_path.exists() {
        // The device proves the PIN, as at unlock: one touch, and the key's own retry counter
        // applies. Comparing the typed PIN with the one held in memory (2026-10-08) made this
        // call an offline PIN oracle with no lockout (review 2026-10-09, regression Finding 3).
        let stub = std::fs::read_to_string(&stub_path)?;
        let line = stub
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("AGE-PLUGIN-YUBIKEY-"))
            .ok_or_else(|| anyhow::anyhow!("the YubiKey stub contains no identity line"))?;
        let identity = crate::yubi::decrypt_with_yubikey(&std::fs::read(crate::paths::identity_path()?)?, line, passphrase)
            .map_err(|_| anyhow::anyhow!("Incorrect PIN."))?;
        let ok = String::from_utf8(identity).map(|t| t.lines().any(|l| l.starts_with("AGE-SECRET-KEY-"))).unwrap_or(false);
        if !ok {
            anyhow::bail!("Incorrect PIN.");
        }
    } else {
        verify_wallet_passphrase(passphrase)?;
    }
    Ok(())
}

pub async fn get_viewkey(passphrase: String) -> Result<String> {
    // The viewing key opens the wallet's whole past and future history; it is gated like the
    // seed (review 2026-10-09, session 4, Issue J).
    confirm_wallet_secret(&passphrase)?;
    let phrase = extract_mnemonic_internal()?;
    use zcash_protocol::consensus::MainNetwork;
    // Same derivation a send uses — one function, wallet.rs — so what this shows is
    // what a signature would be made with, not a second implementation of it.
    let usk = crate::wallet::spending_key_from_phrase(&phrase)?;
    let derived = usk.to_unified_full_viewing_key().encode(&MainNetwork);

    // R6. Derivation alone says what the seed WOULD produce. The key the user is asking
    // for is the one this wallet scans and spends with, and that lives in accounts.ufvk.
    // F4 (in extract_mnemonic_internal) already refuses a phrase from a different seed, by
    // fingerprint; it cannot see an account row whose UFVK is not what that seed derives.
    // So compare, and hand out the stored key only when derivation agrees with it — a
    // wallet where the two differ has no single answer, and showing either would be wrong.
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| anyhow::anyhow!("Failed to open DB to check the view key: {:?}", e))?;
    let mut stmt = conn.prepare("SELECT hd_account_index, ufvk FROM accounts")?;
    let rows: Vec<(Option<u32>, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    if rows.is_empty() {
        anyhow::bail!("this wallet has no account yet, so there is no viewing key to show");
    }
    // This wallet is single-account by design (create_new_account refuses), and every
    // derivation site uses account 0. An account row that says otherwise did not come
    // from this code, and its key is not the one derived above.
    let matched = rows.iter().any(|(idx, ufvk)| {
        idx.unwrap_or(0) == 0 && ufvk.as_deref() == Some(derived.as_str())
    });
    if !matched {
        anyhow::bail!(
            "the viewing key derived from this wallet's seed phrase does not match the \
             account stored in its database.\n\n\
             The account was created from a different key than the phrase stored beside it, \
             most often by combining a database and an encryption identity from two different \
             wallets. The key this wallet scans with is not one its seed can reproduce.\n\n\
             Do not send from this wallet. Recover from your 24-word phrase instead."
        );
    }
    Ok(derived)
}


/// Validate a Zcash address by **decoding** it, not by inspecting its prefix.
///
/// The Roster previously accepted anything starting with `u1`/`zs`/`t1`/`t3`, so
/// `u1garbage` was saved as a contact and only failed much later, at send time,
/// after the user had already trusted it. This uses the same decoder
/// `send_transaction` uses, so what the Roster accepts and what a send accepts
/// cannot drift apart.
pub async fn validate_address(address: String) -> Result<Value> {
    let a = address.trim();
    if a.is_empty() {
        anyhow::bail!("Enter an address.");
    }

    zcash_address::ZcashAddress::try_from_encoded(a)
        .map_err(|e| anyhow::anyhow!("That does not look like a Zcash address: {}", e))?;

    // Prefixes are only used to *label* an address that has already decoded.
    let kind = if a.starts_with("u1") {
        "unified"
    } else if a.starts_with("zs") {
        "sapling"
    } else if a.starts_with("t1") || a.starts_with("t3") {
        "transparent"
    } else {
        "other"
    };

    Ok(serde_json::json!({
        "valid": true,
        "kind": kind,
        "address": a,
    }))
}

pub async fn get_roster() -> Result<Vec<Value>> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let conn = rusqlite::Connection::open(&db_path)?;
    conn.execute("CREATE TABLE IF NOT EXISTS roster (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, address TEXT NOT NULL, notes TEXT)", [])?;
    
    let mut stmt = conn.prepare("SELECT id, name, address, notes FROM roster ORDER BY name ASC")?;
    let mut rows = stmt.query([])?;
    
    let mut roster = Vec::new();
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        let address: String = row.get(2)?;
        let notes: String = row.get(3).unwrap_or_default();
        
        roster.push(serde_json::json!({
            "id": id,
            "name": name,
            "address": address,
            "notes": notes
        }));
    }
    Ok(roster)
}

pub async fn add_roster_contact(name: String, address: String, notes: String) -> Result<String> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let conn = rusqlite::Connection::open(&db_path)?;
    conn.execute("CREATE TABLE IF NOT EXISTS roster (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, address TEXT NOT NULL, notes TEXT)", [])?;
    
    conn.execute(
        "INSERT INTO roster (name, address, notes) VALUES (?1, ?2, ?3)",
        rusqlite::params![name, address, notes],
    )?;
    Ok("Contact added successfully".to_string())
}

pub async fn delete_roster_contact(id: i64) -> Result<String> {
    let db_path = crate::paths::as_string::wallet_db_path()?;
    if let Ok(conn) = rusqlite::Connection::open(&db_path) {
        conn.execute("DELETE FROM roster WHERE id = ?1", [id])?;
    }
    Ok("Contact deleted successfully".to_string())
}

#[cfg(test)]
mod tests {
    // Lagos Post Card #010: identity v1, so the asset id and the image hash differ.
    const LPC10_ID: &str = "983427394e7b2e7653470164c4551a1372817a9e4f830460cdb71fa0811b29fc";
    const LPC10_IMG: &str = "73801910be7eeb98e5e3a0b5e2adc5ddb519af45bb76cd1ac24350d9e70495f3";

    #[test]
    fn artwork_is_asked_for_by_asset_id_only() {
        // The memo's image hash (LPC10_IMG here) never reaches a URL: a sender chooses it.
        let urls = super::artwork_candidate_urls("https://zecboat.com", LPC10_ID);
        assert_eq!(urls, ["png", "jpg", "jpeg", "webp"].iter()
            .map(|e| format!("https://zecboat.com/collection/{LPC10_ID}.{e}")).collect::<Vec<_>>());
        assert!(urls.iter().all(|u| !u.contains(LPC10_IMG)));
    }

    use super::*;

    /// Two replacements inside the same second must not overwrite each other's copy.
    ///
    /// `preserve_replaced_file` named its copy with `as_secs()`, and `rename` onto an
    /// existing name replaces it silently on Unix. Two fast calls therefore destroyed the
    /// first rescue copy — the exact failure this function exists to prevent, occurring
    /// inside the function itself.
    ///
    /// This lives here rather than in `tests/` because the function is private, and an
    /// integration test could only reach it through `initialize_new_wallet`, which takes
    /// seconds per call. At that speed the seconds never collide and the test passes
    /// against the defective code — proving nothing. Calling it directly is the only way
    /// to reach the race.
    #[test]
    fn preserve_replaced_file_does_not_collide_within_one_second() {
        let dir = std::env::temp_dir().join(format!("zb-preserve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wallet.db");
        let path_s = path.to_string_lossy().into_owned();

        let mut kept = Vec::new();
        for i in 0..5u8 {
            std::fs::write(&path, [i; 64]).unwrap();
            kept.push(
                preserve_replaced_file(&path_s)
                    .expect("preserve should succeed")
                    .expect("a file existed, so a copy must have been kept"),
            );
        }

        let mut uniq = kept.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), kept.len(), "preserved copies collided: {kept:?}");

        // Every copy must still hold its own distinct contents, not the last writer's.
        for (i, k) in kept.iter().enumerate() {
            let got = std::fs::read(k).unwrap();
            assert_eq!(got, vec![i as u8; 64], "copy {i} was overwritten by a later one");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod unwind_tests {
    use super::*;

    /// A failed replacement must put every moved file back, and say so accurately.
    ///
    /// This is a UNIT test of the mechanism, not an end-to-end one, and the distinction is
    /// worth stating rather than glossing. Inducing a genuine late failure in
    /// `initialize_new_wallet` proved impractical: a directory left at `wallet.db` is simply
    /// renamed aside by `preserve_replaced_file` and SQLite creates a fresh file, and
    /// `create_account` accepts a birthday of `u32::MAX` without complaint. Four attempts,
    /// none reliable.
    ///
    /// So this proves the unwind does what it claims. It does NOT prove the three callers
    /// are wired to it correctly — that is covered only by reading them.
    #[test]
    fn a_failed_replacement_puts_every_file_back() {
        let dir = std::env::temp_dir().join(format!("zb-unwind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let db = dir.join("wallet.db").to_string_lossy().into_owned();
        let id = dir.join("encryption-identity.txt").to_string_lossy().into_owned();

        std::fs::write(&db, b"ORIGINAL DATABASE").unwrap();
        std::fs::write(&id, b"ORIGINAL IDENTITY").unwrap();
        // A -wal belonging to the original. It must travel with it, or it is replayed into
        // whatever file takes its place.
        std::fs::write(format!("{db}-wal"), b"ORIGINAL LOG").unwrap();

        let kept_db = preserve_replaced_file(&db).unwrap();
        let kept_id = preserve_replaced_file(&id).unwrap();
        assert!(kept_db.is_some() && kept_id.is_some(), "both should have been moved aside");

        // What a half-built wallet looks like at the moment of failure.
        std::fs::write(&db, b"half-built").unwrap();
        std::fs::write(&id, b"new identity").unwrap();

        let err = unwind_replacements(
            &[
                Replaced { path: id.clone(), kept: kept_id },
                Replaced { path: db.clone(), kept: kept_db },
            ],
            anyhow::anyhow!("induced"),
            &dir.to_string_lossy(),
            "creating the wallet",
        );

        let msg = format!("{err:#}");
        assert!(msg.contains("nothing was changed"), "expected a clean rollback: {msg}");
        assert_eq!(std::fs::read(&db).unwrap(), b"ORIGINAL DATABASE");
        assert_eq!(std::fs::read(&id).unwrap(), b"ORIGINAL IDENTITY");
        assert_eq!(
            std::fs::read(format!("{db}-wal")).unwrap(),
            b"ORIGINAL LOG",
            "the log must come back with its own database"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With nothing to restore, the NEW file must still go.
    ///
    /// An identity with no wallet beside it reads as an initialised install and sends
    /// `check_initialization_status` the wrong answer — the user is shown an unlock screen
    /// for a wallet that does not exist.
    #[test]
    fn a_first_ever_creation_leaves_nothing_behind() {
        let dir = std::env::temp_dir().join(format!("zb-unwind-first-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let id = dir.join("encryption-identity.txt").to_string_lossy().into_owned();

        // Nothing was there before, so preserve returns None.
        let kept = preserve_replaced_file(&id).unwrap();
        assert!(kept.is_none());
        std::fs::write(&id, b"new identity").unwrap();

        let _ = unwind_replacements(
            &[Replaced { path: id.clone(), kept }],
            anyhow::anyhow!("induced"),
            &dir.to_string_lossy(),
            "creating the wallet",
        );

        assert!(
            !std::path::Path::new(&id).exists(),
            "the new identity must be removed when there was no previous one to restore"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
