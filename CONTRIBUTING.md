# Contributing to Zecboat

Thank you for looking. This is a small project handling real money, so the guidelines below lean
towards caution rather than velocity.

---

## Reporting a security issue

**Do not open a public issue for anything that could lose someone funds.**

Email **speed [at] zecboat.com** with `SECURITY` in the subject. You will get a reply; please allow a
reasonable window to fix the problem before publishing.

Things worth reporting even if you are not certain they are exploitable:

- Anything that could cause funds or an asset to be spent, lost or destroyed
- Anything where the interface reports more than it actually verified
- Key material reachable somewhere it should not be
- A path where a failure is silently treated as a success

**No independent security review has been performed on this software.** If you find something, you
are probably the first person to look.

## Reporting a bug

Open an issue with:

- What you did, what you expected, what happened
- Your OS and version, `rustc --version`, `node --version`
- Which node you were connected to (`ZECBOAT_PROVIDER`)
- Relevant log output

**Never paste a seed phrase, a private key, or an unlocked wallet file into an issue.** If a
reproduction seems to need one, say so and we will find another way.

### Before reporting a zero balance

Check that your `ZECBOAT_PROVIDER` serves Ironwood (NU6.3). A lightwalletd without it reports zero
for funds that are really there. That is the most common report and it is not a wallet bug — see
<https://zecboat.com/guide/what-is-ironwood>.

---

## Code

### Style

This project follows the [`librustzcash` style guides](https://github.com/zcash/librustzcash). In
short: run `cargo fmt`, keep `cargo clippy` clean, and match the surrounding code rather than your
own preference.

### Comments explain *why*

The comments here carry the reasoning, not a restatement of the code. Where a decision looks odd,
there is usually a defect behind it, and the comment says which. Please keep that up — **if you
change something that a comment justifies, update the comment in the same commit.**

### Things that will be rejected

- **A check the caller can bypass.** If a protection can be skipped by a call site that forgets to
  invoke it, it is not a protection. Asset carriers are locked inside note selection for exactly this
  reason.
- **Treating a failure as a pass.** A fetch that fails is not a verification that succeeded. A
  missing price is not free. An absent signature is not valid.
- **Claiming more than was checked.** Any indicator that implies a check the code does not perform.
- **A build pipeline that discards its exit status.** Piping a build into a pager makes the exit code
  the pager's, and a failed build reports success.
- **Hardcoded paths, addresses or credentials.** Everything derives from `$HOME` or configuration.

### Consensus-relevant dependencies

`zcash_client_sqlite` and `zcash_client_backend` are pinned to exact versions with `=`. **Do not
relax those pins**, and do not let them drift between `zecboat-core` and anything depending on it.
Two versions of these crates in one tree produce incompatible duplicate types rather than a clean
error — and a build against the wrong version may be unable to see a user's funds at all.

There is no `[patch.crates-io]` section and there should not be. One previously forced `orchard` to
an older fork with no Ironwood support, and because a patch applies to the whole dependency graph it
silently overrode the version the engine requires.

### Testing

```sh
cd zecboat-core && cargo test
cd zecboat-ui && npm test
```

**Never test against a wallet holding real funds.** Use a separate `$HOME` — see Running two wallets
in the README. Test on mainnet with amounts you would not mind losing, or not at all.

---

## Pull requests

- **One change per pull request.** A refactor bundled with a fix makes both harder to review.
- **Say what you tested and how.** "Builds" is not testing. If you changed anything touching
  transaction construction or note selection, say what you exercised on chain.
- **Keep the commit history readable.** Squash the noise; keep the story.
- **If you found a defect while doing something else, mention it** even if you did not fix it.

---

## Implementing something compatible

The ZMAP protocol is published so that anyone can build a compatible wallet, market or verifier
without our code or permission: <https://zecboat.com/protocol>

If you implement it and something is wrong or underspecified, **that is a defect in the
specification** — please report it. Two things there are mandatory rather than advisory, because
skipping either loses people money or misleads them:

- **Protect asset carriers from ordinary spends** (§5.4). A wallet that does not will destroy one.
- **Never report a note as genuine on an artwork check alone** (§12.1). A forgery passes it.

---

## What this project will not accept

**Mint functionality.** There is no mint command, no mint screen and no issuer key handling in this
wallet, and no pull request will add one. Provenance is meaningful only while issuance is confined to
an identifiable source, and a wallet that can mint is a wallet that can forge. Issuance belongs in a
separate application with separate key material.

If a feature seems to need the wallet to mint, it belongs in the minting application instead.
