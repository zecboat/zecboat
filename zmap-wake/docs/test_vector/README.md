# WAKE v1 mainnet test vector — Wake Test #004

`WAKE-v1.md` §11 item 5: one real lineage on Zcash mainnet, lading and note ρ given, verifiable
by anyone with a node. A **throwaway** collection made for this purpose on 2026-09-25, so that
publishing the lading links nothing anyone owns.

## The chain

| | txid | height | Action | wallet |
|---|---|---|---|---|
| genesis (mint) | `14b8a35a93fec522b597115e18e5100885c30964f222a998cd8325df9118f362` | 3,496,071 | 4 | testA (first holder) |
| transfer | `196412a60c1758689a6de11e8d5f54e7cce460b3061f2bd5b33b35ce22c3042b` | 3,496,088 | 1 | testB (note in hand) |

Collection "Wake Test", symbol WKT, asset `53fcf47014a61ebc414e3c34c457ea071f6bb603dc686108fbe890f0c1ca7872`
(#004 of 4), 10,000-zat Ironwood carrier with a ZMAP v0.3 memo. Issuer address
`u1kprsfxh9rmfascth7xscsn9lnzhjn5ggfdzmcp7s4qjff44aw7hqkr4xpdtnjma8366mq3lq6d0syf9rlm6m9k8q84ua4kcqx4grh2aprnfvlxg6ltqd7pl8gs5qxq94tjfc83d68edwzezzuv87l8epppyam552gejxv35epc0nqk90`.

## The vector

```
lading            wake_test_004_lading.json   (7,148 bytes; hash the bytes AS-IS)
lading sha256     eea0542d99fc64a7a468e63cd0b592dc86d316f0aa06508a1c7d7339680c992e
note-in-hand ρ    4b5eb176b9f8c8147f63d264241153b7ffb287b174eaee07836e0bd42a1ba339
kind              wake-v1, k = 11
vk_id genesis     decb572630f885fd6a98266f5faea215193597eb5e83a6da8e6912bb083334e9
vk_id hop         c10ee672500b17ea7c94376b6bc1ee988870b9354d1bd391ed1f1324c953707f
```

The lading holds one proof, `WAKE_GENESIS`, with instance `[anchor, cmx_0, nf_0]` and
`anchor_height` 3,496,071. The note in hand is testB's: its ρ equals `nf_0`, which consensus
placed there (ρ_new = nf_old in the same Action) and which is also the nullifier revealed in
Action 1 of the transfer. There is no hop proof: the chain is one transfer long.

## Verify

Against a zebrad (or zcashd-compatible) JSON-RPC at `http://127.0.0.1:8232`:

```sh
cargo run --release --bin wake-holder -- verify \
    --lading docs/test_vector/wake_test_004_lading.json \
    --rho  4b5eb176b9f8c8147f63d264241153b7ffb287b174eaee07836e0bd42a1ba339 \
    --hash eea0542d99fc64a7a468e63cd0b592dc86d316f0aa06508a1c7d7339680c992e
```

Expected: `VERIFIED: 1 proof(s), trust FullNode, genesis cmx fa0474e16a392f4c…, shallowest anchor N deep`
with `N ≥ 100`. Before block 3,496,171 the correct answer is `AnchorTooShallow`.

Run on 2026-09-26 against zebrad at tip 3,496,910: `VERIFIED: 1 proof(s), trust FullNode, genesis cmx
fa0474e16a392f4c…, shallowest anchor 839 deep` (log: `wallet_copies/wake_test_004_verify.log`).

What the verifier checks (`WAKE-v1.md` §8): the lading hash; W1, the genesis `cmx_0` equals the
node's `cmx` at output 4 of the mint transaction; W2, the anchor is the Ironwood tree root at
height 3,496,071 and at least 100 blocks deep; W3, the proof verifies under the genesis key;
W5, the given ρ equals the proof's `nf`. No nullifier-set lookup is made.

## What this vector does not show

A hop proof (`WAKE_HOP`). The two-transfer shape is demonstrated privately on Happy Birthday
#010, whose lading is not published because it links real transactions (§7.3). A second hop for
this throwaway, testB back to testA, can be added later; the wallets are kept.
