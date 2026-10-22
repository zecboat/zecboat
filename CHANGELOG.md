# Changelog

Notable changes to the Zecboat desktop wallet. Entries describe the user-visible effect,
not the diff.

## 0.7.2-beta — unreleased

### NU7 (2026-10-22)

- **The wallet knows the NU7 mainnet activation height, 3,543,405 (about 6 November 2026).**
  The Zcash libraries moved from their pre-release line to the final 0.11 / 0.23 / 0.25 /
  0.31 releases published on 21 October, which carry the height Zebra 7.0.0 announced. From
  that block, send expiry, the carrier lock and the audit re-check follow 25-second blocks
  instead of 75-second ones; before it nothing changes. A test pins the height and its
  branch id. No wallet file, key or screen changed.

- 2026-10-12: wording only. Private folder names and paths removed from comments, docs, two
  ignored mainnet tests and the HOME guard of five dev examples. No code path changed.

### Fixed (2026-10-22, the last three items from the 0.7.1 stranger test)

- **Wallet files are owner-only from the moment they are made.** The wallet database and the
  registry view were created with the desktop's default permissions (readable by every user
  on the machine) by Replace from seed, by a new wallet and by the registry's first fetch; only
  the encrypted identity was private. They are now made private at creation, and every unlock
  tightens a database an earlier version left open, so no step is needed.
- **Settings → Replace from seed: the "I understand this replaces the wallet…" line sits
  centred on its checkbox** and wraps as a block instead of hanging off the box's right edge.
- **The "Scan from" hint says "funds that are really there".**

### Fixed (2026-10-15, from the 0.7.1 stranger test and send tests)

- **Switching to a node that does not answer no longer strands the wallet.** Settings applied
  the new address before testing it, so a typo left the sync engine on a dead node until a
  restart while the screen still showed the old one. The previous node is kept, and the message
  says so.
- **Send is disabled while spendable ZEC is below the fee**, and the warning says how much more
  is needed. The button used to stay enabled and the send was refused later.
- **"No witness is available for position …" now names the fix.** The wallet cannot prove a
  spend of a note whose place in the commitment tree it cannot rebuild at the note's own block;
  the message says which block to rescan from (Settings → Wallet Management → Rescan from
  Height) and that nothing was sent.
- **A record that no rescan can place is no longer shown as "Needs a rescan".** A duplicate row
  an earlier version wrote under the wrong pool, in a block the wallet has already scanned,
  asked for a rescan that could do nothing (seen on a real wallet, 0.0498 ZEC). It is left out of every
  balance bucket, the total included.
- **History shows a send's amount and its fee apart.** "Sent 0.0006" for a 0.0005 send with a
  0.0001 fee now reads −0.0005 · fee 0.0001.
- **The send result is a sentence:** "Sent. Transaction 7e99acb8…", with one copy button for
  the id, instead of "Success! Operation ID: Transaction broadcasted successfully! TxID: …".
- **"Already collected"** when a lineage record was already held, instead of "Nothing to
  collect yet", which read as a failure.
- **The Send screen shows the asset field only for a shielded-asset send**, labelled "Asset to
  send (asset id)". With type ZEC it was still shown as "Sending Address (Source)", and an asset
  id pasted there was silently ignored: the send moved plain ZEC and the unit stayed.
- **Settings no longer offers "Create New Account"**; the command behind it stays refused.
- **Genesis lines say "action #10"** rather than "#10", which read as a unit number; the
  Collections progress lines keep their spaces ("block 3,502,987 of …").
- **Install scripts:** `uninstall_zecboat_deb.sh` removes `~/.local/share/com.zcash.zecboat`
  (window data, saved node choice); `install_depends.sh` run by `install.sh` no longer prints
  "Next: bash install.sh" mid-run; `install.sh` hands apt a world-readable copy of the package,
  so the "download is performed unsandboxed" warning is gone.
- **Docs:** README and `launch.sh` no longer name a dead artwork host; the artwork default is
  zecboat.com and nothing needs setting. CONTRIBUTING and README say funds, not money.

### NU7 (merged from branch `nu7`, 2026-10-15; crate bump of 2026-10-02)

Zcash NU7 activates on mainnet around 5 November 2026 (height set on 20 October; ZIP 259):
new consensus branch ID `0x77190AD9`, 25-second blocks, v4 transactions retired. A wallet
without it cannot sign a transaction any node accepts after the activation block.

### Changed (2026-10-02)

- **Zcash crates moved to the NU7 pre-release stack**: `zcash_protocol` 0.11, `zcash_primitives`
  and `zcash_proofs` 0.31, `zcash_client_backend` 0.25, `zcash_client_sqlite` 0.23, `zcash_keys`
  0.17, `zcash_address` 0.14, `zcash_transparent` 0.11, `pczt` 0.10, `orchard` 0.16, halo2 0.4,
  `pasta_curves` 0.6, `rand` 0.10 (and `sinsemilla` 0.2, `incrementalmerkletree` 0.9,
  `shardtree` 0.8, `zip32` 0.3). These carry the NU7 rules and the testnet activation height;
  the mainnet height arrives with the final releases after 20 October, which is what 0.7.2
  ships with.
- **Wake is unchanged and still `wake-v1`.** The circuits were rebuilt on orchard 0.16 / halo2
  0.4 without a code change; both pinned verifying-key ids are the same, and five real
  mainnet ladings proven under halo2 0.3 verify under 0.4 (`zmap-wake/tests/stored_ladings_verify.rs`,
  run against ladings exported from a wallet copy; never checked in).
- **Addresses and viewing keys stay `u1…` and `uview1…`.** The new key crate encodes unified
  addresses as `zu1…`/`tu1…` and viewing keys as `uvf1…` (ZIP 316 revision 2) by default. Other
  wallets cannot pay those yet and every published manifest and Registry entry uses the
  revision-0 strings, so everything this wallet shows, stores or compares is re-encoded as
  revision 0 (`zecboat-core/src/addr.rs`); revision-2 strings from others are accepted.
- **Block counts that mean time are now time** (`zecboat-core/src/block_time.rs`). Send expiry
  (50 minutes), the carrier lock (35 days) and the audit re-check cadence (8.7 days) are stated
  in seconds and converted at the height of use: 40 / 40,000 / 10,000 blocks before NU7,
  120 / 120,000 / 30,000 after. The library's own send expiry stays a fixed 40 blocks, which
  after NU7 is 17 minutes, so the wallet passes its own. Wake's minimum anchor depth stays 100
  blocks (42 minutes after NU7; the rule is about reorg depth, which is a block count).
- **Existing wallets migrate to the new schema on first open.** The migration guard only
  looked for the Ironwood tables, so a wallet that already had them never received the NU7
  crates' migrations and every scan batch failed with "no such table:
  transparent_spend_locator_map" (found live in testA). The guard now knows each schema
  generation by a sentinel table and takes a one-way backup named for it (`wallet.db.pre-nu7`)
  before migrating.

## 0.7.1-beta — 2026-10-10

0.7.0-beta was tagged and staged but never published: a test on a machine without its own node
showed that lineage, and one step of the issuance check, only worked beside a zebrad, and that
a lineage record could not reach a wallet outside this project's own machines. 0.7.1 is the
first public release of everything listed under 0.7.0, with that fixed.

### Changed

- **The two collections minted before identity v1 are no longer recognised.** Happy Birthday
  and Barcelona Post Card (the 2025 and early-2026 mints, before the signed proof-of-issuance
  manifests) are no longer built into the wallet; no unit of either is held outside the
  project. A unit of one now reads as a collection this wallet does not know. The three
  current collections, Happy Birthday Zcash 10, Barcelona Post Card 2026 and Lagos Post Card,
  are built in with their manifests.
- **Lineage and issuance work without your own node.** Checking a lineage record, checking that
  an item's issuance output is on chain, and sending an item that has a lineage record all asked
  a zebrad on the same machine and nothing else. They now ask your own node when one answers
  and your provider, the light server chosen in Settings, when none does. The proofs are
  checked on your machine either way; only the chain's answers come from the provider.
- **The lineage badge says who answered.** "your own node" when a node on this machine was
  asked; "via your provider" when the provider was. The provider's word about the chain is the
  same trust your balance already rests on, and the badge does not present it as more. Both stay
  amber, "awaiting external review", until the Wake circuit has been reviewed.
- **Messages in plain words.** "No node answered at …" replaces "curl exited with exit status:
  7". The wallet no longer runs the external `curl` program to ask a local node.
- **The "update before 5 November" notice now names 0.7.2**, the release that will follow NU7.

### Added

- **Lineage records you can see, retry and carry.** Settings → Lineage records lists every
  record this wallet sent, with one mark each: delivered, or not yet. A record that could not be
  delivered is tried again by itself at the next sync, and there is a Retry button. **Save file**
  writes the record, sealed so that only the recipient's wallet can open it, into Downloads, to
  be sent by any means; **Open a lineage file…** takes one in. A finished send of an item shows
  the same mark under the transaction id. Before, delivery was tried once and a failure was a
  line on the console.
- **Tiles keep their artwork.** Artwork that passed its hash check when an item was opened is
  kept beside the wallet and shown on the item's tile from then on, with no request to the
  site; the one fetch per item, on open, is still the only fetch.
- **A new wallet starts at the tip, or says why it cannot.** The setup wizard's node screen
  gains "My own node, elsewhere" for a zainod on another machine, so a wallet meant never to
  touch a public node never does. If the node you chose does not answer, the wallet refuses to
  create itself and says which node, instead of silently starting an 85,000-block first sync.
- **Collections say where they are.** The registry read waits until your wallet is synced,
  shows the block it is on and how many remain, and gives way to your wallet's own sync; a
  Check does the same. Both survive leaving the page. The footer says what block the registry
  was read to.
- **Checks through a provider work for collections older than two weeks.** A provider that
  reports no height for an older transaction used to keep the collection's close from being
  stored, so every Check of it failed; and the collection's own registration, sent after the
  close, was counted as an issue. Both fixed; Lagos Post Card checks 17/17 again.
- **You choose the copy when the wallet cannot.** If someone sends you a bare copy of a unit
  you hold and neither carries a lineage the wallet can check, the send no longer refuses for
  good: the confirmation lists the copies with each one's lineage state and you name the one
  to send.
- **No drop-box at all.** The lineage travels in the transfer (the Knotline); a record can
  also be saved as a file and sent by any means. The optional drop-box route of the 0.7.0
  draft (an address you could name in Settings) is gone: nothing in the middle, nothing that
  sees both sides' network addresses, nothing to defend. zecboat.com never ran one.

### For those who build or integrate

- `zmap-wake`: `LightwalletdOracle` is now exercised against a live server
  (`examples/light_verify.rs`), is safe to call from any thread or runtime, and caches the tip and
  tree states; `ZebradOracle` talks plain HTTP itself and keeps `curl` only for `https://` nodes.
- `zecboat-core`: `wake::Chain` (node or provider), `WakeState::ProviderChecked`,
  `wake::{outgoing, export_sealed, import_sealed}` and two
  delivery columns on the consignments table, added in place on first use.
- Wake v1 §8.1 says a server-asserted verdict is reported as unverified. The wallet now reports
  it as its own named state, never as verified by the holder's node. The spec wording is to be
  amended to match before release.

### Reviewed before release, and what is still open

Between 2026-10-08 and 2026-10-09 the lineage code (the WAKE circuits and verifier, the
Knotline, ZMAP v0.5 and the wallet's send and badge paths) went through eleven automated
review sessions by two independent models, each writing in the manner of a published audit
report and each reading the previous reports only after writing its own. Every finding was
answered in twenty signed hardening commits, and the last five sessions were regression passes
over those fixes. The gate for this release was: no Critical or High anywhere, no Medium in
the verifier or in the path by which a lineage record is stored, chosen and sent, and every
claimed fix confirmed by a later pass. The gate was met at the fourth pass and held at the
fifth; the sixth and seventh each found one Medium in the issuance badge's decision for an
asset no manifest lists, fixed in hardening 21 and 22; the eighth found two, older ones, in
the send of a unit that has no lineage and in the registry audit's value check, fixed in
hardening 23; a final pass over the whole found three in the send dialog and the item view,
none in any verdict, fixed in hardening 24. The reports, the trust model and the open questions for a human auditor are in the
`zmap-wake` repository (`docs/REVIEW_PACKAGE.md`, `docs/TRUST_MODEL.md`).

**This is not an external audit.** No cryptographer outside the project has read the WAKE
circuits. Every lineage result in the wallet still says "awaiting external review", and the
green issuance badge is given only with a lineage verified against your own node.

What is open, all rated Low or Informational by the last pass, and left for 0.7.2:

- The order in which the wallet collects lineage records for several copies of one asset is
  a cost to an attacker, not a guarantee: a stranger who sends you copies can delay the
  collection of the genuine one, through a light server, by some minutes per copy. Sends
  refuse safely meanwhile.
- A light server, when you use one instead of your own node, sees which transactions your
  wallet asks for while it collects a lineage record. The block-level cover the wallet uses
  does not hide that from the server itself. A uniform transfer shape is planned.
- An item's badge verifies the record's proofs twice when it is first opened. Cost only.
- A registered collection's genesis outpoint is read from its signed manifest rather than
  from the audit's own chain-derived list; this can harm only that issuer's own holders.
- A transfer of a unit with its lineage has a recognisable shape on chain (14 outputs).

## 0.7.0-beta — 2026-10-02 *(tagged, never published — see 0.7.1-beta)*

### Added

- **"Update before 5 November" notice.** This build does not follow NU7 (ZIP 259), the network
  upgrade that activates on Zcash mainnet on 5 November 2026. From that block it can neither
  sync nor send. One amber line in the header and in Settings → About says so and names the
  release to update to (0.7.1). The line comes from the wallet core itself, so a build that
  follows the upgrade shows nothing.
- **Collections (A3b): the Zecboat Registry, read by the wallet itself.** A new 🔎 Collections page
  lists every collection registered in the Zecboat Registry, read from the chain with the
  registry's viewing key that is pinned in the wallet: nothing comes from zecboat.com. Each
  collection shows one mark (✓ genuine, ✗ failed, ? not checked yet) and a **Check** button that
  audits it from its published viewing key, against your own node: supply, closure, every unit's
  id bound to the collection's key, and every zatoshi the issuer spent. A collection you hold
  units of shows "✦ N yours". Search by name, key or asset id; filter to Mine. Registrations and
  audit results are kept in `registry.db` and `collection_audits/` beside the wallet, public data
  only; your `wallet.db` is only read. Written independently of the mint tool, from the published
  format, and checked to reach the same verdict on Lagos Post Card.

  **The registry is now a source of trust.** Once a collection is checked and passes, its units
  get the "✓ Verified — issued by …" badge, marked "via Zecboat Registry", and their lineage can
  reach Verified, using the manifest recorded on chain. No per-collection line in the wallet is
  needed, and it works with zecboat.com unreachable. Only a complete, passed check counts; a
  registered collection that has not been checked shows amber "not checked yet", never red.

- **YubiKey protection for the wallet identity file.** `encryption-identity.txt` can now be
  encrypted to a PIV key that cannot leave the device, so no copy of the wallet directory is
  useful without the physical key — decryption happens on the card. The unlock box asks for
  the key's PIN rather than a password, and says so. These are not interchangeable: three
  wrong PINs block the device, and someone who thinks they are guessing at a password will
  keep guessing.

  **It does not protect spending.** Zcash spend authorization is RedPallas over Pallas and
  no YubiKey applet implements it. Once the wallet is unlocked, signing is software exactly
  as before. The wallet says this on the screen where you turn the feature on.

  **Requires `age-plugin-yubikey`.** 0.7.1 ships `install_yubikey.sh` beside the installer:
  it installs the smart-card daemon, a Rust toolchain if you have none (the official rustup,
  checked against its published hash, after asking), builds the plugin from its published
  source at a pinned version, and puts it where a wallet started from the menu finds it.
  By hand it is:

  ```
  cargo install age-plugin-yubikey --version 0.5.1 --locked
  ```

  It is not packaged for Debian. We chose not to bundle the plugin: it
  links `libpcsclite`, so shipping it would re-add that dependency for every user, including
  everyone who will never own a YubiKey. Without the plugin the option simply does not
  appear — nothing breaks, but nothing advertises itself either, so this note is the only
  place the feature is announced.

  **Supported:** YubiKey 4 and 5 series, including Nano and USB-C. **Not supported:** the
  pre-YK4 NEO series, or the blue "Security Key by Yubico", which has no PIV applet at all.

  **Two things to know before enabling it.** Restoring from your seed phrase produces a
  password wallet and drops YubiKey protection — keep the 24 words, they remain the only way
  back in if the key is lost. And `yubikey-identity.txt`, written beside the wallet, encodes
  the key's **hardware serial number in plaintext** — it is bech32, not encryption. A leaked
  backup therefore carries a device identifier, so prefer a key dedicated to this wallet over
  one that also does your SSH or website logins.

### Fixed (2026-10-02)

- **"Lineage could not be verified right now: no such column: sent_txid."** The expired-send
  fix below added that column to the consignments table, but only when a lading is stored;
  reading in a wallet whose table predates it (showcase, same day) failed before anything was
  written. Reads now apply the expired-send filter only when the column exists.

- **The setup wizard's "Seal this wallet to the YubiKey" box now creates the wallet.** It used
  to move to the loading screen and call nothing, leaving a blank card (seen live in a
  throwaway wallet, 2026-10-02). Both kinds of wallet go through the same call; the box only
  decides how the identity is sealed.
- **"Touch the YubiKey now" appears when the key is actually waiting.** The plugin has no
  such message of its own, so the wallet shows it the moment it hands the plugin the decrypt
  (the PIN goes across without any user action, so the wait from then on is the touch); the
  plugin's "please insert the key" lines show in the same place. The unlock button and
  the send button now show it, and the unlock screen says not to touch before. The review
  step of a send from a sealed wallet says "Insert your YubiKey" while the key is out and
  keeps Confirm disabled until it is in, since every send opens the identity through the key. A bare loop
  outside the wallet showed every earlier "Failed to decrypt YubiKey stanza" came from a touch
  made before the plugin asked (a YubiKey 4 fires its OTP applet instead, and the real window
  then expires); the key and pcscd were never at fault.

- **An expired, unmined send no longer leaves marks behind.** Its change was shown as "Needs a
  rescan" (no rescan could fix it: the note never existed), and its stored Wake lading blocked
  every later send of that unit. Both now follow the transaction's expiry: once it is past, the
  change is not counted and the previous lading is live again.

### Changed

- **The node is chosen before the seed phrase is typed.** Restoring a wallet previously
  offered no network choice at all: it went straight to seed entry and used whichever node
  was compiled in, so on a downloaded build a public lightwalletd was contacted before you
  had been asked. Restore now passes through the same network screen as wallet creation, and
  if `ZECBOAT_PROVIDER` is set that node is offered preselected rather than overruled by a
  preset.

- **Settings shows the node actually in use.** With no stored choice it displayed the public
  node regardless of where the wallet was really pointed — on the one screen you open to
  find that out.

- **Settings → About** no longer carries the "What this wallet does not do" list. Those
  limits are published in ZMAP-v0.3 §13 and on zecboat.com; a second copy on a panel you
  open to check a build hash only invited the two to drift apart.

### Fixed

- **The YubiKey option used to be a mock.** Before this release the detector reported a key
  as present whether or not one was plugged in, and the "hardware" response was a fixed
  string compiled into the binary. The controls were hidden in September for that reason;
  they return now that the mechanism behind them is real.

---

### Security

- **The wallet no longer opens a listening socket.** Every launch started a JSON-RPC server
  on `127.0.0.1:8238` with no authentication and no origin check, answering `unlock_wallet`,
  `send_transaction` and `batch_send`. Any process on the machine, or any web page (a
  `text/plain` POST needs no browser permission), could spend from an unlocked wallet, guess
  the password, or use up a YubiKey's three PIN attempts. Nothing used it: its only client was
  removed on 2026-08-13. The server, its module and the `axum` dependency are gone.

- **A failed re-check now revokes a collection's Verified badge.** The newest Check of a
  collection decides; an older pass no longer outranks a newer failure. When the last Check is
  more than 10,000 blocks old (about 8.7 days) the badge's detail says a re-check is due.

- **YubiKey-protected wallets can send.** Two spend paths still assumed a password-encrypted
  identity file and refused a YubiKey one, so such a wallet could unlock and show balances but
  never sign. Both now go through the one decryption routine that knows both forms.

- **A remote zebrad is not "your node".** Wake rated anchors from any `ZECBOAT_ZEBRAD_RPC`
  address as self-checked. Only a zebrad on this machine (loopback or localhost) counts now;
  anything else leaves the lineage at Unverified, with the endpoint named in the reason.

- **Wallet files are created owner-only.** The encrypted identity, the database copies, the
  backups and the YubiKey stub were written with the process umask, world-readable on a stock
  desktop. They are now 0600, and the data and backup directories 0700. Files made by earlier
  versions keep their old mode until rewritten: `chmod -R go-rwx ~/.AppVault ~/ZecboatBackups`
  fixes them in place.

- **A crafted close memo can no longer crash the wallet.** A registration whose close memo
  claimed billions of inline commitments made the Check allocate accordingly and abort. The
  count is now bounded by what a memo can carry before anything is allocated.

- **A collection's Check can no longer be sabotaged by sending to its issuer.** The audit
  counted every output the published viewing key could decrypt as something the issuer did,
  so one note sent to the issuance address with a crafted memo failed checks 1, 9 and 10 in
  every wallet, forever. An output now counts only when its transaction spent the account's
  own notes, which nothing but the spending key can do.

- **Transfer memos carry each fact once.** A send adds `consignment_hash` to the carrier memo;
  the minted memos repeated name, symbol and image hash that `desc` already holds, and for
  Barcelona Post Card 2026 and Happy Birthday Zcash 10 that left no room (537 and 534 bytes
  against the 512 limit), so no unit of either could be sent. A transfer memo is now
  `asset_id`, `ik`, `desc`, `consignment_hash`; readers take the rest from `desc`. The asset id
  must derive from `ik` and `desc`, or the transfer is refused. Nothing minted changes.

## 0.6.5-beta.1 — 2026-09-20

**The 0.6.5-beta release was withdrawn. This replaces it.** The wallet is byte-for-byte the
same program; only the installer beside it changed.

### Fixed

- **`install.sh` looked for a file that was not in the download.** It still named the
  previous release's artifact — `Zecboat_0.6.3_amd64.deb` — while the zip contained
  `Zecboat_0.6.5_amd64.deb`, so the documented install path stopped at
  *"Zecboat_0.6.3_amd64.deb is not in …"*. Anyone following the instructions on the
  download page could not install. The package itself was never affected: extracting the
  zip and running `apt install ./Zecboat_0.6.5_amd64.deb` worked throughout.

  The filename is now found by glob rather than written down, and the script refuses unless
  exactly one artifact matches — so a directory holding two releases stops instead of
  guessing. The version now lives in one place: the filename the bundler produces.

### Why it was not caught

The release gate extracts every artifact and scans it, but it looks for leaked builder
paths — it has no opinion about a script that names a file sitting next to it. The source
tarball, both lockfiles and the binary were all correct, so no proxy would have shown this.
**Only running the shipped installer does.** That check belongs in `stage.sh` and is not
there yet.

`0.6.5-beta`'s artifacts were removed from the download server. Its git tag remains: the
code was sound, and rewriting history to hide a packaging bug would be worse than the bug.

---

## 0.6.5-beta — 2026-09-19 *(withdrawn — see 0.6.5-beta.1)*

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
