# Changelog

Notable changes to the Zecboat desktop wallet. Entries describe the user-visible effect,
not the diff.

## 0.6.5-beta — 2026-09-19

**Theme: make the code portable without porting it.** No new platform ships. This removes
the assumptions that would have made a Windows or macOS port a rewrite — and every item is
a correctness fix on Linux on its own merits, which is why none of it was deferred.

### Fixed

- **A missing `HOME` no longer creates a wallet at the filesystem root.** Every path was
  built from `env::var("HOME").unwrap_or_default()`, which turns an unset `HOME` into an
  empty string — so the wallet database resolved to `/.AppVault/data/wallet.db` and
  *nothing errored*. The wallet would report an empty balance, or quietly create a second
  wallet where nobody would look for it. Paths now come from one module that **refuses**
  rather than guessing. Refusing to open is recoverable; opening the wrong database is not.
- **The proving-parameter error named the wrong directory on Windows and macOS.** It always
  said `~/.zcash-params/`, which is correct only on Linux. It now names the directory for
  the platform the binary is running on, and says what the consequence is: the wallet can
  sync and display, but cannot build a transaction.

### Changed

- **Three C dependencies removed.** The `yubikey` crate was declared but never imported;
  deleting it took `pcsc`/`pcsc-sys` with it and drops `libpcsclite1` from the `.deb`.
  SQLite is now compiled from source rather than linked against whatever the build host
  had. TLS is rustls only — `native-tls` and its OpenSSL dependency are gone. Together
  these remove 677 lines from the lockfiles and most of what made this a Linux-only binary.

### Security

- **The release gate now knows all three home-directory shapes.** It checked artifacts for
  `/home/<user>/` only. A Windows or macOS build would have passed while carrying the
  builder's username, because Rust embeds source paths in debug info and panic messages.
  It now also refuses `C:\Users\<user>\` and `/Users/<user>/`, verified against an
  artifact with all three planted in it.

### Not changed, deliberately

- `yubi.rs` stays. The plan was to delete it alongside the `yubikey` crate, but the two are
  unrelated — it never used that crate — and it is still on the unlock path. A wallet
  created while the YubiKey option existed has its identity encrypted under a derived
  passphrase, and **the wallet records no flag saying so**. Removing it would make such a
  wallet permanently unopenable.

## 0.6.3-beta — 2026-09-07

### Fixed

- **Happy Birthday artwork now renders.** All ten files in that collection are JPEGs stored
  under a `<asset_id>.png` name, because a ZMAP asset id is `sha256(image bytes)` and the
  registry convention appends `.png`. The server labelled them `image/png` from the
  extension and the wallet trusted that label, producing a data URI that declared PNG while
  carrying JPEG bytes — which every WebView refuses to render. Verification had always
  passed; only the display failed. The wallet now identifies the format from the bytes.
  The files themselves cannot be corrected: their hash *is* the asset's identity.

- **Transaction detail no longer offers "Open in explorer."** Following that link handed a
  txid and the user's IP to a third-party server at the moment they were viewing their own
  transaction — a metadata leak the shielded pool otherwise prevents, performed by the
  wallet on the user's behalf.

- **The launcher no longer reports a working registry as broken.** It printed
  "asset artwork will not load" whenever `ZECBOAT_REGISTRY` was unset, which by this release
  is false: the compiled default resolves with no redirect. The message sent operators
  looking for a registry fault instead of the real bug.

### Added

- **Copy buttons** on the asset id, exported keys, viewing key, and completed transactions.
  The transaction button copies the bare 64-hex txid rather than the sentence around it.
  One shared component replaces three separate clipboard implementations; it copies exactly
  the value it displays, so what a user reads and what they paste cannot differ.

- **A headless seed-recovery test** (`zecboat-core/examples/recovery_roundtrip.rs`). Create a
  wallet, take its 24 words, recover into a separate home with a different password, compare
  derived addresses. Previously untestable because it was assumed to need a GUI.

### Security

- **Build paths no longer ship in the binary.** 0.6.2 carried **1,070** occurrences of the
  build machine's home directory, including the source tree's own absolute path, inside
  `usr/bin/zecboat-ui`. Releases are now built with
  `RUSTFLAGS="--remap-path-prefix=$HOME=/build"` and `strip = true`, and refused by
  `tools/release-gate.sh` if any remain. This is also a prerequisite for reproducible builds.

  Scanning the packaged `.deb` reported zero — compression hid every occurrence. The gate
  extracts before scanning.
