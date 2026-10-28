# Zecboat

A desktop Zcash wallet that holds **znfts** (Zec non-fungible things) as well as ZEC.

A znft here is an ordinary Zcash note carrying a memo that names it: a shielded object. Sending one spends
that exact note and writes the same identity into the next note's memo (ZMAP §5.3: the asset id,
the issuer key and the description it derives from, plus the hash of the unit's lineage record),
so custody changes hands while identity does not. It is an ordinary shielded note underneath: no
new cryptography, no second chain, no bridge.

Built on the Ironwood (NU6.3) `librustzcash` stack. Rust core, Tauri 2 shell, Svelte 5 interface.

---

## ⚠️ Beta software

**Zecboat has not had an independent security review.** Releases are signed (an Ed25519 signature
over the download's hashes). The installer checks that signature against the key shipped in the
same archive and prints the key: that check means something only once you have compared the key
with the one published on zecboat.com/download, which a substituted archive cannot forge. There
are no automatic updates, and it handles real value on Zcash mainnet.

**Use amounts you can afford to lose**, and read [Backups](#backups) before putting funds in it.

---

## What it does

- Holds and sends shielded ZEC on Zcash mainnet
- Holds, verifies and transfers znfts
- Fetches artwork from your own IPFS gateway first when you set one (Settings → Artwork), checked against the hash each unit carries (0.7.3)
- Checks for its own next release under the pinned release key, and installs it only after verifying the package against the signed note (0.7.3)
- Protects assets from being spent by accident — see [Asset carriers](#asset-carriers)
- Proves transactions locally; **spending keys never leave your machine**
- Connects to any lightwalletd you choose, including your own node
- No account, no custody, no sign-up

## What it deliberately cannot do

**It cannot create assets.** There is no mint command, no mint screen and no issuer key handling
anywhere in this codebase. Issuance is a separate application with separate key material.

This is structural rather than a decision that could be quietly reversed, and it is what makes a
provenance claim mean anything: **a wallet that can mint is a wallet that can forge.**

---

## What is and is not proven

This is a **beta**. Stated plainly, because a beta that overstates itself is worse than one that
admits its gaps.

**Proven on Zcash mainnet:**

- Sending shielded ZEC — built, proved, broadcast and mined from this codebase.
- Transferring a znft — a 10,000-zatoshi carrier with its memo intact.
- Syncing from a public lightwalletd, and from a local zebrad + zaino stack.
- Building from a clean checkout on a machine that had never seen this source.

**Implemented but NOT tested end to end:**

- **Seed-phrase recovery.** The code exists, compiles and ships. **Nobody has recovered a wallet with
  it.** If you rely on it, test it first against a throwaway wallet — every wallet path derives from
  `$HOME`, so `HOME=/tmp/somewhere zecboat-ui` gives you a completely isolated one.
- The wallet-replacement rollback in `preserve_replaced_file`. It moves files aside and never
  deletes, but the failure path has not been exercised.

**Not done at all:**

- **No independent security audit.** Several review passes by language models found real defects —
  including a hardcoded password that would have replaced a user's wallet — but that is not an audit
  and must not be read as one.
- Sending a znft is refused when the wallet holds a carrier at risk. That is deliberate
  fail-closed behaviour, not a completed feature.
- No hardware signing. A YubiKey can seal the wallet's identity file (the unlock), so a copied
  wallet folder is useless without the key; spending is still signed in software, and the wallet
  says so where the option is turned on. The option needs `age-plugin-yubikey`, built on your
  machine by `packaging/install_yubikey.sh` (shipped in the Debian zip); without it the option
  does not appear.

**Use it with funds you can afford to lose, and write down your seed phrase.**

## Building

Linux only for now — tested on Debian 13 and Ubuntu. Expect **30 to 60 minutes**, most of it
waiting for Rust to compile.

### 1. System dependencies

```sh
sudo apt update
sudo apt install -y \
    build-essential pkg-config curl git \
    libwebkit2gtk-4.1-dev libjavascriptcoregtk-4.1-dev \
    libxdo-dev libssl-dev libayatana-appindicator3-dev \
    librsvg2-dev
```

One of these matters more than it looks:

- **`libwebkit2gtk-4.1-dev`** — the application shell. **Version 4.0 is a different, incompatible
  package** and will not work.

`libpcsclite-dev` was required until 0.6.5 and is no longer. It was pulled in by the `yubikey`
crate, which was declared but never imported; deleting the crate removed `pcsc-sys` and with it
the C library. If you are following older instructions you may have installed it — it is now
harmless but unnecessary.

### 2. Rust and Node

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustc --version    # 1.96 or newer
```

Install Rust from rustup, **not from apt** — the packaged version is usually too old. Node 20 or
newer is needed to build the interface.

### 3. Proving parameters

**Do not skip this.** Without them the wallet installs, syncs and displays balances perfectly — then
fails the moment you try to send anything.

```sh
mkdir -p ~/.zcash-params && cd ~/.zcash-params
curl -O https://download.z.cash/downloads/sapling-spend.params
curl -O https://download.z.cash/downloads/sapling-output.params
```

If you add these while the wallet is running, restart it — the path is resolved once at startup.

### Steps 1 and 3, done for you

`install_depends.sh` performs both — the apt packages and the proving parameters — and reports what
is already present rather than reinstalling it:

```sh
./install_depends.sh --check    # report only, change nothing
./install_depends.sh            # install what is missing
```

It is worth using even if you prefer doing things by hand, for one reason: it resolves **virtual
package names**. Debian 13 renamed several libraries for the 64-bit `time_t` transition, so
`libgtk-3-0` no longer exists as a real package — `libgtk-3-0t64` provides it. `apt` handles that,
but a manual `dpkg -l | grep libgtk-3-0` reports it missing on a machine where it is installed and
working. The script checks providers, so it does not send you after a package that cannot exist.

It also downloads the parameters to a `.part` file and only moves them into place when complete. A
truncated params file fails later, at proving time, with an error that says nothing about downloads.

### 4. Build

```sh
cd zecboat-ui
npm install
npx tauri build --no-bundle
```

The binary lands at `zecboat-ui/src-tauri/target/release/zecboat-ui`.

Expect **around 50 minutes** on a first build — it compiles the whole dependency tree, including the
proving system. Later builds are minutes.

Drop `--no-bundle` if you also want a `.deb` and an AppImage; they appear under
`src-tauri/target/release/bundle/`.

> **Build with the Tauri CLI, not `cargo build`.** Running `cargo build --release` inside `src-tauri`
> compiles the Rust and succeeds, but **does not embed the frontend** — only the Tauri CLI does that.
> The resulting binary falls back to the dev server at `http://localhost:1420`, where nothing is
> listening, and you get **a blank white window** reading *"Could not connect to localhost"*. The
> build looks clean, so this is easy to mistake for a broken application. It is not; it is the wrong
> build command.
>
> To check a binary you already have:
> ```sh
> strings -a src-tauri/target/release/zecboat-ui | grep -c _app/immutable
> ```
> A correctly built binary reports a non-zero count. Zero means the frontend is missing — rebuild
> with the command above.

If `npx tauri` fails with `unrecognized subcommand`, your `node` is a rebranded build (N|Solid, for
instance). The Tauri CLI matches `argv[0]` against `node|nodejs|bun|electron`; anything else falls
through and the interpreter path is parsed as the subcommand. Call the CLI directly instead:

```sh
node -e "require('./node_modules/@tauri-apps/cli/main.js').run(['build','--no-bundle'],'tauri')"
```

---

## Running

```sh
export ZECBOAT_PROVIDER=https://zec.rocks:443

./zecboat-ui/src-tauri/target/release/zecboat-ui
```

Or use `./launch.sh`, which sets it and runs a preflight check. Nothing else needs setting:
artwork comes from `https://zecboat.com` unless `ZECBOAT_REGISTRY` says otherwise, and the
Zecboat Registry itself is read from the chain, never from a server.

### `ZECBOAT_PROVIDER` — which node to sync from

> **The node you choose matters.** Zecboat holds funds in the Ironwood (NU6.3) pool. A lightwalletd
> that does not serve Ironwood will show you **a zero balance for funds that are really there** —
> which looks exactly like losing your funds, and is not.

Nothing is lost in that case; the server simply cannot see into that pool. Switch to one that
supports Ironwood and the balance returns.

Running your own `zebrad` + `zainod` is the private option, and the only arrangement where nobody
else sees which blocks you request.

### `ZECBOAT_REGISTRY` — where asset artwork is fetched from (optional)

Default `https://zecboat.com`; leave it unset. Artwork is fetched as
`<registry>/collection/<asset_id>.jpg` (or `.png`) and re-hashed against the hash the asset's
memo commits to, so a wrong or missing picture is shown as not verified, never as the asset. This
variable chooses the artwork host only: the on-chain Zecboat Registry, lineage and verification
never use it.

---

## Backups

**A backup is two files, and either one alone is worthless.**

```
~/.AppVault/data/wallet.db                  holds the encrypted recovery phrase
~/.AppVault/data/encryption-identity.txt    the key that decrypts it
```

Copy one without the other and you have **no backup at all** — and you will not find out until you
need it. Write your recovery phrase on paper as well, keep it off the machine, and **test the backup
by restoring it somewhere else** before you trust it with anything.

### Running two wallets

Every path is derived from `$HOME`, so a second wallet needs a different one:

```sh
env HOME=/path/to/second/wallet ./zecboat-ui/src-tauri/target/release/zecboat-ui
```

**Forgetting the prefix opens the first wallet, not a new one.** Use a wrapper script rather than
typing it each time.

---

## Asset carriers

An asset lives in a note of a small, fixed value. To an ordinary wallet that looks like loose change
waiting to be swept into a transaction fee — and a wallet that does not protect them will eventually
destroy one by accident.

Zecboat locks each asset individually, so ordinary sends route *around* them rather than being
refused. The protection lives inside note selection, not in a check that runs beforehand and could be
bypassed.

**If you implement a compatible wallet, this is not optional.**

---

## Verification, and its limits

The wallet checks that an asset's artwork matches the identifier committed in its memo — download the
image, hash it, compare. That check needs nobody's cooperation, including ours.

**It is not proof that an asset is genuine.** Anyone can copy a memo and point it at the same
artwork. Confirming *who issued it* needs the issuer's signed record, and confirming that *the note
you hold* is the one they issued needs evidence from whoever sent it to you.

The wallet reports these separately rather than showing a single badge that would mean less than it
appears to. The protocol specification covers what can and cannot be established, including a section
on what it will never prove — ownership is not provable on a shielded chain, and no engineering
changes that.

---

## Proven on mainnet

With this codebase, unassisted:

```
#001  payment   de478c2133e82fa34039d4b637f88398bc0cba9012e536a5e44353f29191be2a   3,459,438
      delivery  d3deb4d05a6bdc05899501d003aea92135f5c4e2ed8968361dc480292c3837ed   3,461,221
#002  payment   72a46e34d8032d2f55d80411e6d089a9c6a7e0fb94dd9be2082e28f6960d35ba   3,461,662
      delivery  a50d8448738c7b127eba084d02a47615d8120c8089e3f02e3c6d06026752de6d   3,461,672
```

Two assets bought from a public catalogue and delivered by an unattended daemon, every leg over
public infrastructure.

Most block explorers have no Ironwood parser and will render these as `vin/vout 0/0` with `fee 0`.
That is a limitation of the explorer, not a defect in the transaction.

---

## Known rough edges

- **No packaging.** No `.deb`, no installer, no code signing, no auto-update.
- **Linux only.** macOS and Windows are not built yet.
- **Deep links are half-wired** — `zecboat://pay` takes the wrong path for a plain ZEC payment. Paste
  into **Send → Payment URI** instead.
- **No independent security review.**

---

## Documentation

- Guides and install instructions — <https://zecboat.com/guide>
- The ZMAP protocol specification — <https://zecboat.com/protocol>
- What znfts are, and are not, good for — <https://zecboat.com/shielded-assets>
- Verifying an asset's issuance — <https://zecboat.com/proof-of-issuance>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports about things that lose funds are the most
valuable contribution.

## Licence

MIT — see [LICENSE](LICENSE).
