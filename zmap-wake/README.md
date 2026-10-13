# zmap-wake

Proofs of note lineage on Zcash: the reference implementation of `../WAKE-v1.md`, used by
`../ZMAP-v0.5.md` §9 check 7. Separate exploratory project; see `../README.md` and the
build boxes in `../wake_chapters.md`.

**Status: DRAFT. No external review. A missing constraint here is a forgery.** Nothing that
depends on this crate may report "verified" before `WAKE-v1.md` §11 has happened.

## Layout

| Module | Chapter | What |
|---|---|---|
| `witness` | 3 | private inputs from a note and a viewing key; independent recomputation of `cm`, `nf` |
| `wallet_path`, `wallet_notes` | 3, 7, 9 | notes and Merkle paths from a wallet **copy**; `.AppVault` paths are refused |
| `circuit` | 4 | `WAKE_HOP` / `WAKE_GENESIS`, orchard's Action circuit by deletion (`docs/diff_vs_orchard_circuit.md`) |
| `keys`, `prove`, `verify` | 4 | cached keys, pinned `vk_id`s, proving, verifying |
| `lading` | 6 | the delivered format; hash over raw bytes; `anchor_height` per entry |
| `oracle`, `oracle_lightwalletd` | 6 | `ChainOracle`; zebrad (JSON-RPC) and lightwalletd (gRPC, feature `lightwalletd`, untested) |
| `verify::verify_chain` | 6 | W1–W5 with named failures and the oracle's trust level |
| `pin`, `attest`, `manifest` | 9 | the §7.3 on-chain pin, the bridge attestation, `ik` + `genesis[]` |
| `testing` | – | fixtures; not for production |
| `src/bin/wake-issuer.rs` | 9 | the issuer-side CLI |

## Build and test

```sh
cargo test                       # everything but the mainnet test; ~2.5 min, keygen included
cargo test --lib                 # unit tests only, seconds
cargo check --features lightwalletd
cargo clippy --all-targets
```

The `sabotage` feature (chapter 5) exists only for this crate's own tests: it lets a test
build a circuit with one named constraint removed, so every negative test proves it would
catch that constraint's absence. The pinned `vk_id` test shows the knob changes nothing
while unused. Never enable it in a build that proves or verifies for real.

## Mainnet

`tests/mainnet_user2.rs` proves a real hop from a wallet copy against a local zebrad:

```sh
WAKE_WALLET_COPY=$WAKE_COPIES_DIR/user2_wallet.db \
WAKE_TXID=<txid> cargo test --test mainnet_user2 -- --ignored --nocapture
```

Wallet copies are never published and never committed; `WAKE_COPIES_DIR` points at them. Copy `wallet.db`
with the wallet closed, or `sqlite3 wallet.db ".backup copy.db"`. Never point anything here
at a live wallet; the crate refuses any path containing `.AppVault`.

## The issuer CLI

```
wake-issuer genesis        --wallet <mint copy.db> --txid <hex> --index <n> [--unit <u>] --out <file>
wake-issuer manifest add   --manifest <in.json> --out <out.json> [--ik <hex>] --unit <u:txid:index> ...
wake-issuer manifest check --manifest <file>
wake-issuer pin memo       --manifest <file> [--generation <g>]
wake-issuer pin sidecar    --generation <g> --txid <hex> --index <n> --ock <hex> --out <file>
wake-issuer pin verify     --manifest <file> --pin <sidecar.json> --address <UA|hex>
wake-issuer pin check-served --manifest-url <U> --pin-url <U> --address <UA|hex>
wake-issuer attest sign    --key <seed.hex> --cmx <hex> --asset-id <hex> --unit <u> --height <h> --out <file>
wake-issuer attest verify  --file <attestation.json> [--pubkey <hex>]
```

`--zebrad <url>` defaults to `http://127.0.0.1:8232`. Nothing here builds or sends a
transaction: `pin memo` prints the memo for the issuance wallet to send, and `genesis`
needs only the mint wallet's viewing key.

## Dependencies

Pinned to the exact versions in the Zecboat wallet's `Cargo.lock`: `orchard =0.15.3` with
`unstable-voting-circuits`, `halo2_proofs =0.3.2`, `halo2_gadgets =0.5.0`,
`pasta_curves =0.5.1`, `zcash_client_sqlite =0.22.0-rc.4` with `zcash_client_backend
=0.24.0-rc.4` (both must be pinned together). `cargo tree -d` shows one version of each.
