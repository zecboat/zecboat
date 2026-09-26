# zmap-wake, in-tree copy

Copied 2026-09-26 from `~/zebd/ZMAP_v0.5/zmap-wake` (the exploratory Wake project, chapters
3–7 and 9–10 of `wake_chapters.md`) for chapter 8, "the wallet carries it". `zecboat-core`
depends on it by path (`../zmap-wake`). The exploratory directory stays the place where the
circuit, its negative tests and the review package are maintained; changes go there first and
are re-copied here (`target/` and `Cargo.lock` excluded), so the two must not be edited
independently.

Nothing here builds or sends a transaction. The wallet uses: `Witness`, `prove_hop`,
`prove_genesis`, `lading::{Lading, ProofEntry, lading_hash}`, `verify_chain`,
`oracle::ZebradOracle`, `wallet_notes::{received_notes_in_tx_conn, witness_at}`,
`wallet_path::ironwood_paths_at_height`, `seal::{seal, open}`.
