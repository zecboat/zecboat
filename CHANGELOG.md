# Changelog

Notable changes to the Zecboat desktop wallet. Entries describe the user-visible effect,
not the diff.

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
