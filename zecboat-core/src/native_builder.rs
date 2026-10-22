//! Transaction construction — plain ZEC **and** ZMAP asset transfers.
//!
//! Zecboat is an L2 shielded-asset wallet and this file is where both paths are
//! built: ordinary Ironwood (NU6.3) value transfer, and the deliberate spend of
//! an asset carrier. Assets ride on top of plain value, so the plain path has to
//! be correct first.
//!
//! ## How carriers are protected
//!
//! A ZMAP asset is carried by a note of exactly `CARRIER_ZAT` (10,000 zatoshis).
//! `propose_transfer` performs its **own** input selection, so a caller-side
//! check cannot govern what gets spent — see the note on
//! `assert_no_zsa_notes_at_risk` at `lock_zmap_carriers` below for why the
//! previous pre-flight guard was removed rather than kept.
//!
//! The protection now lives in selection itself. `lock_zmap_carriers` locks every
//! carrier before each build; locked outputs are never selected under
//! `LockedInputPolicy::Exclude`, the default carried by `SpendPolicy`. Ordinary
//! spends route **around** carriers instead of being refused, so a wallet holding
//! an asset can still send ZEC. A forgetful call site cannot bypass it, because
//! the enforcement is in the backend rather than in a check this module performs.
//!
//! `crate::wallet::validate_anti_burn` still runs at both `wallet.rs` entry
//! points as a second, caller-side check. It is no longer the only thing standing
//! between an asset holder and a burned asset.
//!
//! ## Sending an asset
//!
//! `send_zmap_asset` (below) is the asset path, reached from the UI as
//! `send_transaction(addr, amount, memo, Some(asset_id))` and routed at
//! `wallet.rs:119`. `crate::zmap::plan_asset_send` picks the carrier and carries
//! its memo.
//!
//! Three rules that are not obvious and must not be "simplified":
//!
//!   * **Inputs are chosen explicitly, not by `propose_transfer`.** Value-based
//!     selection could take *two* carriers of the same asset to cover a fee and
//!     return the surplus as ordinary change, destroying a unit. Only the choice
//!     of inputs is ours; ZIP-317 and the change strategy stay the library's.
//!   * **The fee comes from separate notes.** Fees are inputs minus outputs, so
//!     taking it from the carrier would hand the recipient a sub-carrier note and
//!     destroy the asset. The recipient receives exactly `CARRIER_ZAT`. A wallet
//!     holding *only* carriers therefore cannot send them — it has nothing to pay
//!     the fee with.
//!   * **The memo is reproduced byte for byte and the output is Ironwood**, so
//!     transferring a legacy Orchard carrier performs the pool migration as a side
//!     effect. `send_zmap_asset` deliberately ignores the caller's `amount` and
//!     `memo`: honouring either would let a caller change an asset's identity in
//!     flight.
//!
//! Proven on mainnet — five Happy Birthday carriers sent, mined and
//! nullifier-verified at heights 3,457,204 – 3,459,355.
//!
//! **`build_and_sign_batch_transaction` is the exception: plain ZEC only.**
//! Multi-recipient sends cannot include an asset, and that refusal is correct
//! behaviour rather than an unimplemented feature.
//!
//! ## Why this was rewritten rather than migrated (2026-08-11)
//!
//! The previous version — untracked, and removed by `git clean -xfd` on 2026-09-14;
//! recover it from git history at the pre-Ironwood commit if ever needed —
//! hand-rolled the whole proposal: its own ZIP-317 fee arithmetic, its own change
//! output built by querying the addresses table, ~400 lines duplicated almost
//! verbatim between the single and batch entry points. It was already fragile;
//! `continuous_challenges_0705.md` records a long hunt for an `InsufficientFunds`
//! error caused by that manual fee maths disagreeing with the builder's internal
//! calculation. Under the 0.24 crates it stopped compiling outright (21 errors).
//!
//! `propose_transfer` performs selection, fee calculation and change as one
//! consistent unit — the same path `ironwood_shield/src/shield_iw.rs` used for
//! the transaction mined at height 3,430,966. No local arithmetic remains to
//! fall out of agreement with it.

use anyhow::{anyhow, Result};

use zmap_wake::rng::OsRng;

use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector;
use zcash_client_backend::data_api::wallet::{
    create_pczt_from_proposal, create_proposed_transactions, extract_and_store_transaction_from_pczt,
    propose_transfer, ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::{OutputLockStore, WalletRead};
use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
use zcash_client_backend::fees::{DustOutputPolicy, StandardFeeRule};
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_backend::zip321::{Payment, TransactionRequest};

use zcash_address::ZcashAddress;
use zcash_client_sqlite::WalletDb;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::consensus::{BlockHeight, MainNetwork};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zcash_protocol::ShieldedPool;

/// The wallet database type used throughout the crate.
type Db = WalletDb<rusqlite::Connection, MainNetwork, zcash_client_sqlite::util::SystemClock, OsRng>;

/// Pool that receives change and any shielded output the wallet creates.
///
/// NU6.3 froze Orchard, so Ironwood is the only forward-looking target. Existing
/// Orchard and Sapling notes stay *spendable*; this governs outputs only.
const CHANGE_POOL: ShieldedPool = ShieldedPool::Ironwood;

/// The "proving parameters missing" message, naming the directory for the platform the
/// binary is actually running on.
///
/// Three call sites previously hardcoded `~/.zcash-params/`. That is correct on Linux and
/// wrong everywhere else: `LocalTxProver::with_default_location()` resolves per platform,
/// so a Windows user reading "install them to ~/.zcash-params/" would be sent to a
/// directory the code never looks in. The paths below match what `zcash_proofs` uses and
/// what `zecboat_windows.md` / `zecboat_macOS.md` record.
pub(crate) fn params_not_found() -> String {
    let dir = if cfg!(target_os = "windows") {
        // known_folders::RoamingAppData
        r"%APPDATA%\ZcashParams"
    } else if cfg!(target_os = "macos") {
        // NOT ~/Library/Application Support. zcash_proofs uses the `xdg` crate on macOS
        // (verified in zcash_proofs-0.30.0/src/lib.rs:82-87), so on a stock Mac this is
        // ~/.local/share/ZcashParams. The Apple-conventional path is the correct-LOOKING
        // wrong answer, and zecboat_macOS.md flags it as exactly that trap.
        "~/.local/share/ZcashParams"
    } else {
        // home::home_dir().join(".zcash-params")
        "~/.zcash-params"
    };
    format!(
        "Zcash proving parameters not found. Expected them in {dir}/ \
         (sapling-spend.params and sapling-output.params). \
         Without them the wallet can sync and display, but cannot build a transaction."
    )
}

/// The ZSA/NFT note denomination `validate_anti_burn` protects.
/// Lock every ZMAP carrier note so automatic input selection cannot spend it.
///
/// # Why this replaces `assert_no_zsa_notes_at_risk`
///
/// The old guard refused to build **any** transaction while the wallet held a carrier, because
/// `propose_transfer` picks its own inputs and a caller-side check could not govern them. That was
/// honest — an unenforceable check is worse than none — but it meant a wallet holding one asset
/// could not send ZEC at all.
///
/// The backend already provides the right mechanism. Locked outputs are never selected under
/// [`LockedInputPolicy::Exclude`], which is the default carried by `SpendPolicy`. Locking the
/// carriers moves the protection from a pre-flight assertion into the selection itself: ordinary
/// spends now route *around* carriers instead of being refused, and the protection cannot be
/// bypassed by a call site that forgets to check.
///
/// Locks carry an expiry height, so this is re-run before each build; same-owner re-locking is
/// idempotent and simply refreshes the expiry.
///
/// Returns the number of carriers locked.
fn lock_zmap_carriers(wallet_db: &mut Db, target_height: BlockHeight) -> Result<usize> {
    // Read the carriers through the same code path the UI uses, so what is protected is exactly
    // what is displayed as an asset.
    let holdings = {
        let conn = rusqlite::Connection::open_with_flags(
            wallet_db_path()?,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| anyhow!("could not open the wallet to look for asset notes: {}", e))?;
        let rows = crate::zmap::read_carrier_rows(&conn)
            .map_err(|e| anyhow!("could not read asset notes: {}", e))?;
        crate::zmap::holdings_from_rows(rows)
    };

    // One lock owner per asset, so a later asset-send can unlock exactly the asset it is sending
    // and leave every other carrier protected. See `zmap::carrier_lock_owner`.
    let groups = crate::zmap::carrier_locks(&holdings);
    if groups.is_empty() {
        return Ok(0);
    }

    // Far enough ahead that a lock cannot lapse between builds in normal operation. Locks are
    // advisory and owner-scoped, so an over-long expiry costs nothing: only this wallet's own
    // asset-send path may spend through them.
    let expiry = target_height + crate::block_time::carrier_lock_blocks(target_height);

    // Every carrier that exists must end up locked. Counting them first is the only way to
    // notice a partial success — `lock_outputs` returning fewer rows than it was handed is
    // an `Ok`, and an earlier version of this function passed that count upward unexamined.
    // The caller then saw a plausible number, proceeded, and the carriers that did not lock
    // were left visible to value-driven selection.
    //
    // A loud failure was already fixed at the call site. This is the quiet one.
    let expected: usize = groups.iter().map(|(_, refs)| refs.len()).sum();

    let mut locked = 0usize;
    for (owner, refs) in &groups {
        locked += wallet_db.lock_outputs(refs, *owner, expiry).map_err(|e| {
            anyhow!(
                "could not protect {} asset carrier note(s) from being spent: {:?}",
                refs.len(),
                e
            )
        })?;
    }

    if locked != expected {
        return Err(anyhow!(
            "only {} of {} asset carrier note(s) could be protected from automatic input \
             selection. Refusing to continue: the {} unprotected note(s) could be spent as \
             part of a transaction fee, which destroys the asset. Try again in a moment; if \
             it persists, close any other program using the wallet database.",
            locked,
            expected,
            expected - locked
        ));
    }

    // ── Second pass (ZMAP v0.5 §5.4): lineage notes ────────────────────────────────────────
    //
    // A carrier's lineage is the note whose `rho` is the carrier's nullifier, and before the
    // send path paired Actions it could be the sender's own change: memo-less, unlocked, and
    // one fee spend from silent destruction. Lock every such note under a distinct owner.
    let lineage_rows = {
        let conn = rusqlite::Connection::open_with_flags(
            wallet_db_path()?,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| anyhow!("could not open the wallet to look for lineage notes: {}", e))?;
        crate::zmap::read_lineage_rows(&conn)
            .map_err(|e| anyhow!("could not read lineage notes: {}", e))?
    };
    let lineage_groups = crate::zmap::lineage_locks(&lineage_rows);
    let lineage_expected: usize = lineage_groups.iter().map(|(_, refs)| refs.len()).sum();
    let mut lineage_locked = 0usize;
    for (owner, refs) in &lineage_groups {
        lineage_locked += wallet_db.lock_outputs(refs, *owner, expiry).map_err(|e| {
            anyhow!("could not protect {} lineage note(s): {:?}", refs.len(), e)
        })?;
    }
    if lineage_locked != lineage_expected {
        return Err(anyhow!(
            "only {} of {} lineage note(s) could be protected from automatic input selection; \
             refusing to continue for the same reason as for carriers",
            lineage_locked,
            lineage_expected
        ));
    }
    if lineage_expected > 0 {
        println!("[zsa] locked {lineage_expected} lineage note(s) carrying an asset chain without its memo");
    }

    Ok(locked)
}

/// How far ahead carrier locks are set. ~35 days at 75-second blocks.
// The lock length lives in `block_time::CARRIER_LOCK_SECS` (about 35 days at either spacing).

/// The wallet this crate operates on. Kept in one place so the lock path and the spend path can
/// never diverge onto different databases — a bug the previous guard was explicitly written to
/// avoid by taking its path as an argument.
fn wallet_db_path() -> Result<String> {
    // Was an inlined `env::var("HOME").unwrap_or_default()`. That swallowed a missing
    // HOME into "", producing /.AppVault/data/wallet.db at the filesystem root with no
    // error. `crate::paths` fails instead, and is the single definition every call site
    // now shares — see its module header on why HOME must remain the mechanism.
    crate::paths::as_string::wallet_db_path()
}

/// Build a memo padded to the 512-byte ZIP-302 length.
///
/// Returns `None` for an empty memo so transparent recipients — which cannot
/// carry one — are not rejected by `Payment::new`.
fn build_memo(memo: &[u8]) -> Result<Option<MemoBytes>> {
    if memo.is_empty() || memo.iter().all(|b| *b == 0) {
        return Ok(None);
    }
    if memo.len() > 512 {
        return Err(anyhow!("memo is {} bytes; the maximum is 512", memo.len()));
    }
    let mut buf = memo.to_vec();
    buf.resize(512, 0);
    MemoBytes::from_bytes(&buf)
        .map(Some)
        .map_err(|e| anyhow!("invalid memo: {:?}", e))
}

/// Construct, prove and sign a transaction for `request`, returning its raw hex.
///
/// The single implementation behind both public entry points.
fn build_and_sign_request(
    wallet_db: &mut Db,
    usk: &UnifiedSpendingKey,
    request: TransactionRequest,
) -> Result<String> {
    let network = MainNetwork;

    // Single-account wallet today; this becomes a parameter when that changes.
    let account_id = wallet_db
        .get_account_ids()
        .map_err(|e| anyhow!("could not read accounts: {:?}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("wallet has no accounts"))?;

    // Protect asset carriers before selection runs. Locked outputs are excluded by the default
    // SpendPolicy, so this is what stops a plain ZEC spend consuming a 10,000-zat asset note.
    //
    // Deliberately not fatal: failing to lock must not block an ordinary send, but it must be
    // audible, because it means carriers are momentarily unprotected.
    let (target_height, _) = wallet_db
        .get_target_and_anchor_heights(ConfirmationsPolicy::MIN.trusted())
        .map_err(|e| anyhow!("could not read chain heights: {:?}", e))?
        .ok_or_else(|| anyhow!("wallet is not synced far enough to build a transaction"))?;
    // FAIL CLOSED. This used to warn and continue, which was the most dangerous line in
    // the codebase: carrier protection is enforced *entirely* by these locks — see the
    // SELECTION note below — so if locking fails there is nothing stopping the greedy
    // selector treating a 10,000-zatoshi carrier as ordinary change and spending the
    // user's asset as part of the fee.
    //
    // The old form printed to stderr, which in a packaged desktop application goes
    // nowhere. The user would have seen a successful send and a missing asset.
    //
    // A refusal to build is recoverable. A burned carrier is not.
    match lock_zmap_carriers(wallet_db, target_height.into()) {
        Ok(0) => {}
        Ok(n) => eprintln!("zmap: {} asset carrier note(s) locked against automatic selection", n),
        Err(e) => {
            return Err(anyhow!(
                "refusing to build this transaction: the asset carrier notes in this wallet \
                 could not be protected from automatic input selection ({e}). Building anyway \
                 risks spending an asset as part of the fee. Try again in a moment; if it \
                 persists, close any other program using the wallet database."
            ));
        }
    }

    // ── SELECTION ──────────────────────────────────────────────────────────
    // The one place input selection is decided. Carrier protection is enforced by output locks
    // (see `lock_zmap_carriers`) rather than by a bespoke InputSource: the default SpendPolicy
    // already excludes locked outputs, so the greedy selector simply never sees them.
    let input_selector = GreedyInputSelector::<Db>::new();
    // ───────────────────────────────────────────────────────────────────────

    let change_strategy = SingleOutputChangeStrategy::<Db>::new(
        StandardFeeRule::Zip317,
        None, // no change memo
        CHANGE_POOL,
        DustOutputPolicy::default(),
    );

    // Selection, ZIP-317 fee and change as one consistent unit — no local
    // arithmetic left to disagree with the builder.
    let proposal = propose_transfer::<_, _, _, _, std::convert::Infallible>(
        wallet_db,
        &network,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        &Default::default(), // SpendPolicy
        None,                // no input locking
        None,                // version implied by target height
    )
    .map_err(|e| anyhow!("could not build a spend proposal: {:?}", e))?;

    // Sapling proving parameters. `with_default_location()` resolves per platform — it is
    // NOT always `~/.zcash-params`, so the error must not name one path as if it were.
    let prover = LocalTxProver::with_default_location().ok_or_else(|| anyhow!("{}", params_not_found()))?;

    let spending_keys = SpendingKeys::from_unified_spending_key(usk.clone());

    let txids = create_proposed_transactions::<_, _, std::convert::Infallible, _, std::convert::Infallible, _>(
        wallet_db,
        &network,
        &zcash_client_sqlite::util::SystemClock,
        &mut OsRng,
        &prover,
        &prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        Some(crate::block_time::send_expiry(target_height.into())), // 50 minutes at either block spacing
    )
    .map_err(|e| anyhow!("transaction creation failed: {:?}", e))?;

    // Read the signed transaction back and return its wire encoding. The caller
    // broadcasts it via rpc::broadcast_raw_tx, over gRPC.
    let txid = txids.first();
    let tx = wallet_db
        .get_transaction(*txid)
        .map_err(|e| anyhow!("could not read back the signed transaction: {:?}", e))?
        .ok_or_else(|| anyhow!("signed transaction {} is missing from the wallet database", txid))?;

    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| anyhow!("could not serialize the transaction: {:?}", e))?;

    Ok(hex::encode(raw))
}

/// Send to several recipients in one transaction. **Plain ZEC only.**
///
/// `outputs` is `(address, zatoshis, memo)`. `inputs` is retained for the
/// caller's anti-burn validation; it does **not** control which notes are spent.
/// Carriers are protected by `lock_zmap_carriers`, not by this list — see the
/// module header.
///
/// An asset is sent one at a time by `send_zmap_asset`, never here. Carriers are
/// locked, so automatic selection cannot reach one from this path; the assertion
/// below records that invariant rather than defending against a reachable state.
pub fn build_and_sign_batch_transaction(
    mut wallet_db: Db,
    usk: &UnifiedSpendingKey,
    inputs: &[crate::wallet::ProposedInput],
    outputs: Vec<(String, u64, String)>,
    _target_height_u32: u32,
) -> Result<String> {
    if outputs.is_empty() {
        return Err(anyhow!("no outputs supplied"));
    }

    // `is_explicitly_selected_asset` is constructed `false` at every site and set `true` nowhere,
    // so this cannot fire in a shipped build. It is an invariant, not a user-facing error:
    // a deliberate carrier spend goes through `send_zmap_asset`, which unlocks exactly the one
    // carrier it is sending under a SpendPolicy naming `zmap::CARRIER_LOCK_OWNER`.
    //
    // This was a `return Err("Sending a ZMAP asset is not wired up yet.")` until 2026-09-17.
    // That string was unreachable but shipped, and a competitive analysis reading the stripped
    // binary took it for a live limitation and recommended building a feature that already
    // worked. Dead code that ASSERTS A CAPABILITY IS MISSING is worse than dead code that does
    // nothing — so the invariant stays, the claim does not.
    debug_assert!(
        !inputs.iter().any(|i| i.is_explicitly_selected_asset),
        "batch send reached with an explicitly selected asset input; \
         asset transfers must go through send_zmap_asset"
    );

    let mut payments = Vec::with_capacity(outputs.len());
    for (i, (address, amount_zat, memo)) in outputs.iter().enumerate() {
        let recipient = ZcashAddress::try_from_encoded(address)
            .map_err(|e| anyhow!("output {}: invalid address {}: {}", i, address, e))?;
        let amount = Zatoshis::from_u64(*amount_zat)
            .map_err(|e| anyhow!("output {}: invalid amount {}: {:?}", i, amount_zat, e))?;

        payments.push(
            Payment::new(recipient, Some(amount), build_memo(memo.as_bytes())?, None, None, vec![])
                .map_err(|e| anyhow!("output {}: {:?}", i, e))?,
        );
    }

    let request = TransactionRequest::new(payments)
        .map_err(|e| anyhow!("could not assemble the payment request: {:?}", e))?;

    build_and_sign_request(&mut wallet_db, usk, request)
}

/// Send to a single recipient. **Plain ZEC only.**
pub fn build_and_sign_transaction(
    wallet_db: Db,
    usk: &UnifiedSpendingKey,
    inputs: &[crate::wallet::ProposedInput],
    to_address: &str,
    amount_zat: u64,
    memo_bytes: &[u8],
    target_height_u32: u32,
) -> Result<String> {
    // Previously a near-verbatim copy of the batch function; now one payment
    // through the same path.
    build_and_sign_batch_transaction(
        wallet_db,
        usk,
        inputs,
        vec![(
            to_address.to_string(),
            amount_zat,
            String::from_utf8_lossy(memo_bytes).into_owned(),
        )],
        target_height_u32,
    )
}

/// Send one unit of a ZMAP asset: spend its carrier, re-issue its memo on a fresh Ironwood carrier.
///
/// # Why this cannot use `propose_transfer`
///
/// `propose_transfer` selects inputs by value. Even with the lock override scoped to this asset it
/// could take *two* of its carriers to cover the fee, and the surplus would come back as ordinary
/// change — destroying a unit. So inputs are chosen explicitly here and handed to
/// [`Proposal::single_step`].
///
/// The ZIP-317 fee and change are still computed by the library's own change strategy, never by
/// local arithmetic; only the *choice* of inputs is ours.
///
/// # Expiry
///
/// `expiry_height`: `None` lets the builder derive it from the wallet's own view of the chain
/// (target height + 40), right when the wallet has just synced. A caller that knows the node's
/// tip may pass `Some(tip + 40)` so a build from a wallet that is a little behind is not
/// expired before it is broadcast.
///
/// # Who pays the fee
///
/// The sender, from separate notes. Fees are inputs minus outputs, so taking it from the carrier
/// would leave the recipient a sub-carrier note and destroy the asset. The recipient receives
/// exactly [`crate::zmap::CARRIER_ZAT`]. **A wallet holding only carriers cannot send them.**
/// The prefix of the error a send returns when its transaction is signed and stored but could
/// not be read back for broadcast: not a failure to retry, a transaction that goes out with the
/// next send (gate eighth pass, Issue E).
pub const STORED_NOT_BROADCAST_PREFIX: &str = "STORED_NOT_BROADCAST:";

pub fn send_zmap_asset(
    wallet_db: &mut Db,
    usk: &UnifiedSpendingKey,
    asset_id: &str,
    recipient: &str,
    expiry_height: Option<BlockHeight>,
    wake: &crate::wake::SendOptions,
    max_fee_zat: Option<u64>,
) -> Result<String> {
    use zcash_client_backend::data_api::wallet::input_selection::{
        LockFilter, LockedInputPolicy, NonEmptyBTreeSet, SpendPolicy,
    };
    use zcash_client_backend::data_api::{InputSource, TargetValue};
    use ::orchard::bundle::BundleVersion;
    use zcash_transparent::bundle::TxOut;
    use zcash_client_backend::fees::{sapling as sapling_fees, ChangeStrategy};
    use zcash_client_backend::proposal::{Proposal, ShieldedInputs};
    use nonempty::NonEmpty;
    use zcash_client_backend::wallet::ReceivedNote;

    // ── 1. Resolve exactly which note moves, and what memo it must carry ────────────────────
    let (plan, carrier_note_id) = {
        let conn = rusqlite::Connection::open_with_flags(
            wallet_db_path()?,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let holdings = crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn)?);
        // Among several carriers of one asset, spend the one whose lineage checks out best: an
        // unsolicited copy (anyone can send a carrier with the same memo, and its own lading)
        // must not be the note picked while the genuine unit sits beside it. "Has a lading"
        // was the rule until 2026-10-09; a copy with a garbage lading had one (audit 2026-10-08,
        // Zecboat C; review 2026-10-09, regression Finding 2).
        // The user's own choice of copy outranks the planner: when no copy checks out, the
        // wallet cannot tell a stranger's bare copy from a unit that simply has no lineage,
        // and refusing for good froze the unit (gate eighth pass, Issue A). The choice is
        // theirs; the unproven acknowledgement below then applies to that copy.
        let choice = wake.carrier.as_deref().and_then(crate::wake::parse_carrier_choice);
        let rank = |c: &crate::zmap::CarrierRef| -> u8 {
            crate::wake::rank_with_choice(choice.as_ref(), c, |c| crate::wake::carrier_send_rank(&conn, asset_id, c, wake.genesis.as_ref()))
        };
        let plan = crate::zmap::plan_asset_send_preferring(&holdings, asset_id, &rank)?;
        if let Some((t, i)) = &choice {
            let found = plan.carrier.output_index() as u32 == *i && hex::encode(plan.carrier.txid().as_ref()).eq_ignore_ascii_case(t);
            if !found {
                return Err(anyhow!("the copy named ({t}#{i}) is not one this wallet holds of {asset_id}"));
            }
            // The choice was made because no copy checked out. If one does by now (its lineage
            // was collected meanwhile), the choice is stale: review again (final gate, I-5).
            let checks_out_now = holdings
                .iter()
                .filter(|h| h.asset_id == asset_id)
                .flat_map(|h| h.carriers.iter())
                .any(|c| !(c.txid.eq_ignore_ascii_case(t) && c.output_index as u32 == *i) && crate::wake::carrier_send_rank(&conn, asset_id, c, wake.genesis.as_ref()) >= 5);
            if checks_out_now {
                return Err(anyhow!("another copy of {asset_id} now checks out against the manifest; review the send again without naming a copy"));
            }
        }
        // A lading this unit's memo commits to that another pass is still collecting is not
        // "absent": the send is refused for now rather than offered unproven, which would strip
        // the hash for good (review 2026-10-09, regression over 12-13, Issue B).
        let carriers: Vec<&crate::zmap::CarrierRef> = holdings.iter().filter(|h| h.asset_id == asset_id).flat_map(|h| h.carriers.iter()).collect();
        let chosen = carriers
            .iter()
            .copied()
            .find(|c| c.txid_bytes[..] == plan.carrier.txid().as_ref()[..] && c.output_index as u32 == plan.carrier.output_index());
        if let Some(c) = chosen {
            if c.consignment_hash.is_some() && crate::wake::walk_in_progress(c) {
                return Err(anyhow!("the lineage this unit's memo commits to is still being collected; try again in a moment"));
            }
            // Several copies: the choice must rest on something. Below "lading checks out",
            // or with no manifest genesis in hand, a tie by txid is a guess, and a guess can
            // spend a stranger's copy (review 2026-10-09, regression over 12-15, Issues B, C).
            if carriers.len() > 1 && choice.is_none() {
                let ranks: Vec<(u8, String)> = carriers.iter().map(|x| (rank(x), format!("{}#{}", &x.txid[..12.min(x.txid.len())], x.output_index))).collect();
                let top = ranks.iter().map(|r| r.0).max().unwrap_or(0);
                let decision = crate::wake::send_decision(top, ranks.iter().filter(|r| r.0 == top).count(), wake.genesis.is_some());
                if let Err(why) = decision {
                    return Err(anyhow!(
                        "this wallet holds {} copies of {asset_id} and cannot tell which to send: {why} (copies: {})",
                        carriers.len(),
                        ranks.iter().map(|r| format!("{} rank {}", r.1, r.0)).collect::<Vec<_>>().join(", ")
                    ));
                }
            }
        }
        (plan, chosen.map(|c| c.note_id))
    };

    // The published issuance accounts never send units (TRUST_MODEL row 13): their viewing keys
    // are public, so every knot and key memo they sent would be readable by anyone. Checked
    // against the registry's listed accounts (review 2026-10-09, Knotline G).
    {
        let mine = crate::addr::encode_uview1(&usk.to_unified_full_viewing_key());
        // Fail closed for the pinned collections (their keys are built in); the registry's
        // listing adds the rest when it can be read (review 2026-10-09, regression over 12-15,
        // Issue G: the check used to be skipped when the registry could not be read).
        let mut published = crate::issuance_v1::pinned_issuance_ufvks();
        if let Ok(view) = crate::collections::registry_view() {
            published.extend(view.registrations.iter().filter_map(|r| r.ufvk.as_deref().map(|u| u.trim().to_string())));
        }
        // By the keys inside, not the string: a published key encoded with another set or
        // order of items is the same account (gate second pass, Issue G).
        if published.iter().any(|u| same_viewing_key(u, &mine)) {
            return Err(anyhow!(
                "this wallet is a published issuance account (its viewing key is published); \
                 units are not sent from it, since anyone could read where they went. Send from the treasury wallet."
            ));
        }
    }

    // ── 1a. Wake (chapter 8): prove THIS carrier before anything is built ───────────────────
    //
    // The lading's hash goes into the memo, so the proof must exist before the payment does.
    // A genesis proof if a trusted manifest names this note as the issuance output; otherwise
    // a hop appended to the lading this wallet received. Neither possible: the unit can only
    // travel unproven, and only if the user said so.
    let wake_lading = {
        let conn = rusqlite::Connection::open_with_flags(
            wallet_db_path()?,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let oracle = crate::wake::chain();
        let spent_index = u32::try_from(plan.carrier.output_index())
            .map_err(|_| anyhow!("internal: carrier output index out of range"))?;
        crate::wake::prepare_send_lading(
            &*wallet_db,
            &conn,
            asset_id,
            plan.carrier.txid().as_ref(),
            spent_index,
            wake.genesis.as_ref(),
            &oracle,
        )?
    };
    // PROTOTYPE (wake_memo): with ZECBOAT_LADING_IN_MEMOS set, the lading travels in this same
    // transaction as memos of zero-value outputs: whole to the recipient (`1`), or only its
    // newest hop as one knot on its Knotline (`knotline`).
    let record_memos: Vec<(crate::wake_memo::ExtraTo, [u8; 512])> = match &wake_lading {
        Some(l) => {
            let conn = rusqlite::Connection::open_with_flags(wallet_db_path()?, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let (extras, what) = crate::wake_memo::extra_outputs(&conn, plan.carrier.txid().as_ref(), carrier_note_id, &l.bytes, l.hops)?;
            if !extras.is_empty() {
                println!("[wake] carrying the lading in this transfer: {what}");
            }
            extras
        }
        None => Vec::new(),
    };
    // A memo that commits to a lading this wallet does not hold is not "no lineage": the
    // lading exists and can be collected; sending without it strips the hash for good. Only an
    // explicit abandon, under its own warning, goes on (review 2026-10-09, regression over
    // 12-15, Issue B; the hash follows the prefix so the screen can show it).
    // An Orchard-pool carrier has no Wake lineage to collect, whatever its memo commits to
    // (gate second pass, Issue I): it moves unproven, under the acknowledgement below.
    let ironwood_carrier = holdings_carrier(&plan).map(|c| crate::wake::is_ironwood(&c)).unwrap_or(true);
    if wake_lading.is_none() && ironwood_carrier {
        let committed = crate::zmap::parse_memo(&plan.memo).and_then(|r| r.consignment_hash);
        if let Some(h) = committed {
            if !crate::wake::abandon_applies(wake.abandon_lineage.as_deref(), Some(&h)) {
                return Err(anyhow!(
                    "{}{h}: this unit's memo commits to a lineage record this wallet has not collected; collect it (the item's \
                     'Collect its lineage now'), or abandon that lineage for good",
                    crate::wake::UNCOLLECTED_PREFIX
                ));
            }
            println!("[wake] ABANDONING the lineage {}… of this unit as the user chose", &h[..16]);
        }
    }
    match &wake_lading {
        Some(l) => println!("[wake] lading of {} proof(s) ready, sha256 {}…", l.hops, &l.hash_hex[..16]),
        None if wake.acknowledge_unproven => println!("[wake] no lading for this unit; sending it UNPROVEN as acknowledged"),
        None => {
            // The reason as it is: no manifest at all, or a manifest whose genesis this carrier
            // is not (gate second pass, Issue C: "no manifest" was said in both cases).
            let why = match &wake.genesis {
                Some(g) => format!(
                    "the manifest names {}… output {} as the genesis and this carrier is not it",
                    &g.txid[..16.min(g.txid.len())],
                    g.action_index
                ),
                None => "no trusted manifest names its carrier as the issuance output".to_string(),
            };
            return Err(anyhow!(
                "{} this wallet holds no lineage proof for {} and {why}, so the recipient would \
                 receive it unproven. Acknowledge that to send anyway.",
                crate::wake::UNPROVEN_PREFIX,
                asset_id
            ))
        }
    }
    let memo_bytes: Vec<u8> = match &wake_lading {
        Some(l) => crate::zmap::memo_with_consignment_hash(&plan.memo, &l.hash_hex)?,
        None => crate::zmap::memo_without_consignment_hash(&plan.memo)?,
    };

    let network = MainNetwork;
    let account_id = wallet_db
        .get_account_ids()
        .map_err(|e| anyhow!("could not read accounts: {:?}", e))?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("wallet has no accounts"))?;

    let (target_height, anchor_height) = wallet_db
        .get_target_and_anchor_heights(ConfirmationsPolicy::MIN.trusted())
        .map_err(|e| anyhow!("could not read chain heights: {:?}", e))?
        .ok_or_else(|| anyhow!("wallet is not synced far enough to send"))?;

    // Every carrier stays locked, including other units of this same asset.
    lock_zmap_carriers(wallet_db, target_height.into())?;

    // ── 2. Take the pinned carrier, overriding only its own lock ───────────────────────────
    let unlock_this_asset = SpendPolicy::default().with_locked_input_policy(
        LockedInputPolicy::PreferLocked(NonEmptyBTreeSet::singleton(plan.lock_owner)),
    );
    let source_pool = match plan.source_pool {
        zcash_protocol::PoolType::Shielded(p) => p,
        zcash_protocol::PoolType::Transparent => {
            return Err(anyhow!("a ZMAP carrier cannot be a transparent output"))
        }
    };
    let carrier_note = wallet_db
        .get_spendable_note(
            plan.carrier.txid(),
            source_pool,
            plan.carrier.output_index(),
            target_height,
            LockFilter::Policy(unlock_this_asset.locked_input_policy()),
        )
        .map_err(|e| anyhow!("could not load the asset's carrier note: {:?}", e))?
        .ok_or_else(|| {
            anyhow!(
                "the carrier note for {} is not spendable yet — it may still need confirmations",
                asset_id
            )
        })?;

    // ── 3. Fund the fee from ordinary notes. Default policy excludes every locked carrier. ──
    //
    // THE CARRIER'S OWN POOL IS ASKED FIRST, and the other pool is only added if that
    // cannot cover the fee.
    //
    // This list used to be passed flat as `[Ironwood, Orchard]`. `select_spendable_notes`
    // stops as soon as it reaches the target, so a wallet holding one large Orchard note
    // and little Ironwood had its fee funded entirely from Orchard — and returned ZERO
    // Ironwood notes.
    //
    // That breaks the balance below, because the two pools are balanced as separate
    // bundles: the fee lands on the bundle carrying the payment, which is the carrier's
    // pool. With no Ironwood fee note the Ironwood bundle held only the carrier:
    //
    //     InsufficientFunds { available: Zatoshis(10000), required: Zatoshis(20000) }
    //
    // — 10,000 in, and 10,000 out plus a 10,000 fee required. Observed on mainnet
    // 2026-09-03. The funding was in the wallet the whole time, in the wrong bundle.
    //
    // This is the ordinary state for anyone carrying pre-NU6.3 change: Orchard is closed
    // to new outputs, so old value sits there while carriers are Ironwood. Such a wallet
    // showed "insufficient funds" against a visibly healthy balance.
    // Without record outputs: the long-standing 60,000. With them: the fee itself (5,000 per
    // Action: the carrier, a change output, one per record output, and room for two fee notes)
    // plus a small margin, instead of the 60,000 on top that refused affordable sends.
    let fee_headroom = Zatoshis::from_u64(if record_memos.is_empty() {
        crate::zmap::CARRIER_ZAT * 6
    } else {
        5_000 * (record_memos.len() as u64 + 4) + 10_000
    })
        .map_err(|e| anyhow!("internal: bad fee headroom: {:?}", e))?;

    let other_pool = match source_pool {
        ShieldedPool::Ironwood => ShieldedPool::Orchard,
        ShieldedPool::Orchard => ShieldedPool::Ironwood,
        ShieldedPool::Sapling => return Err(anyhow!("Sapling carriers are not supported")),
    };

    let select = |pools: &[ShieldedPool]| {
        wallet_db.select_spendable_notes(
            account_id,
            TargetValue::AtLeast(fee_headroom),
            pools,
            target_height,
            ConfirmationsPolicy::MIN,
            &[],
            LockFilter::Policy(&LockedInputPolicy::Exclude),
        )
    };

    // Same-pool first. Only if that pool cannot reach the headroom do we widen — a
    // cross-pool fee is still better than refusing a send the wallet can afford, and
    // the balance strategy handles it as long as the carrier's own bundle is funded.
    let fee_notes = match select(&[source_pool]) {
        // ReceivedNotes exposes per-pool accessors, not is_empty(). Only one pool was
        // asked for here, so a non-zero count in either means that pool answered.
        Ok(notes) if notes.ironwood().len() + notes.orchard().len() > 0 => notes,
        same_pool_result => {
            if let Err(ref e) = same_pool_result {
                println!("[zsa] no fee notes in {:?} ({:?}); widening to {:?}", source_pool, e, other_pool);
            } else {
                println!("[zsa] no fee notes in {:?}; widening to {:?}", source_pool, other_pool);
            }
            select(&[source_pool, other_pool]).map_err(|e| {
                anyhow!(
                    "no spendable ZEC to pay the fee for this asset send: {:?}\n\
                     \n\
                     Sending an asset costs a network fee on top of the asset's own 10,000 zatoshi, \
                     and that fee cannot come out of the carrier without destroying the asset. \
                     This wallet needs ordinary ZEC as well as the asset.",
                    e
                )
            })?
        }
    };

    // Say which pool paid, so the next time this misbehaves the log answers it directly
    // instead of requiring the balance error to be reverse-engineered.
    println!(
        "[zsa] fee funded from {} ironwood + {} orchard note(s); carrier pool is {:?}",
        fee_notes.ironwood().len(),
        fee_notes.orchard().len(),
        source_pool
    );

    // ── 4. The payment: same value, same memo, Ironwood output ─────────────────────────────
    // Ironwood because NU6.3 closed Orchard to new outputs — so transferring a legacy Orchard
    // carrier performs the pool migration as a side effect.
    let recipient_addr = ZcashAddress::try_from_encoded(recipient)
        .map_err(|e| anyhow!("invalid recipient address {}: {}", recipient, e))?;
    let amount = Zatoshis::from_u64(plan.amount)
        .map_err(|e| anyhow!("internal: bad carrier value: {:?}", e))?;
    let memo = MemoBytes::from_bytes(&memo_bytes)
        .map_err(|e| anyhow!("the carrier's memo will not fit a memo field: {:?}", e))?;
    let payment = Payment::new(recipient_addr.clone(), Some(amount), Some(memo), None, None, vec![])
        .map_err(|e| anyhow!("could not construct the asset payment: {:?}", e))?;
    let mut payments = vec![payment];
    for (to, m) in &record_memos {
        let memo = MemoBytes::from_bytes(m).map_err(|e| anyhow!("a record memo will not fit a memo field: {:?}", e))?;
        let addr = match to {
            crate::wake_memo::ExtraTo::Recipient => recipient_addr.clone(),
            crate::wake_memo::ExtraTo::Address(ua) => ZcashAddress::try_from_encoded(ua)
                .map_err(|e| anyhow!("internal: bad record address: {}", e))?,
        };
        payments.push(
            Payment::new(addr, Some(Zatoshis::ZERO), Some(memo), None, None, vec![])
                .map_err(|e| anyhow!("could not construct a record output: {:?}", e))?,
        );
    }
    let payment_count = payments.len();
    let request = TransactionRequest::new(payments)
        .map_err(|e| anyhow!("could not construct the transfer request: {:?}", e))?;
    let mut payment_pools = std::collections::BTreeMap::new();
    for i in 0..payment_count {
        payment_pools.insert(i, zcash_protocol::PoolType::IRONWOOD);
    }

    // ── 5. Fee and change from the library, not from local arithmetic ──────────────────────
    let change_strategy = SingleOutputChangeStrategy::<Db>::new(
        StandardFeeRule::Zip317,
        None,
        CHANGE_POOL,
        DustOutputPolicy::default(),
    );

    // Two shapes of the same notes are needed, and this is the crux of the assembly:
    //   * `Proposal`/`ShieldedInputs` want the pool-agnostic `wallet::Note` enum;
    //   * the fee bundle views want the typed `orchard::Note`.
    // `wallet::Note::Orchard` carries a `ValuePool` that distinguishes Orchard from Ironwood, so the
    // conversion is lossless in both directions provided the pool travels with the note.
    use zcash_client_backend::wallet::Note as WalletNote;

    let to_typed = |n: ReceivedNote<_, WalletNote>| -> Result<ReceivedNote<_, ::orchard::Note>> {
        match n.note() {
            WalletNote::Orchard { .. } => Ok(n.map_note(|note| match note {
                WalletNote::Orchard { note, .. } => note,
                _ => unreachable!("checked immediately above"),
            })),
            _ => Err(anyhow!("a ZMAP carrier must be an Orchard-shaped note")),
        }
    };
    let to_enum = |n: ReceivedNote<_, ::orchard::Note>, pool: ::orchard::ValuePool| {
        n.map_note(|note| WalletNote::Orchard { note, pool })
    };

    // Proposal inputs, in enum form: the fee notes plus the pinned carrier.
    let mut proposal_inputs: Vec<ReceivedNote<_, WalletNote>> = Vec::new();
    for n in fee_notes.ironwood().iter().cloned() {
        proposal_inputs.push(to_enum(n, ::orchard::ValuePool::Ironwood));
    }
    for n in fee_notes.orchard().iter().cloned() {
        proposal_inputs.push(to_enum(n, ::orchard::ValuePool::Orchard));
    }
    proposal_inputs.push(carrier_note.clone());

    // Fee views, in typed form. The carrier joins the bundle for its own pool.
    let mut ironwood_in: Vec<ReceivedNote<_, ::orchard::Note>> = fee_notes.ironwood().to_vec();
    let mut orchard_in: Vec<ReceivedNote<_, ::orchard::Note>> = fee_notes.orchard().to_vec();
    let carrier_typed = to_typed(carrier_note)?;
    let carrier_typed_for_nf = carrier_typed.clone();
    match source_pool {
        ShieldedPool::Ironwood => ironwood_in.push(carrier_typed),
        ShieldedPool::Orchard => orchard_in.push(carrier_typed),
        ShieldedPool::Sapling => return Err(anyhow!("Sapling carriers are not supported")),
    }

    let mut ironwood_out = vec![amount];
    ironwood_out.extend(std::iter::repeat(Zatoshis::ZERO).take(record_memos.len()));

    // The final client crate's SingleOutputChangeStrategy reads the account's change receivers
    // (`AccountMetaT = ChangeReceivers`, from its viewing key) to decide where change may go;
    // until the 0.25 pre-release it carried no metadata at all.
    let change_receivers = wallet_db
        .get_change_receivers(account_id)
        .map_err(|e| anyhow!("could not read the account's change receivers: {:?}", e))?;
    let balance = change_strategy
        .compute_balance(
            &network,
            target_height,
            anchor_height,
            &wallet_db.pool_migration_params(&network),
            &[] as &[std::convert::Infallible],
            &[] as &[TxOut],
            &sapling_fees::EmptyBundleView,
            &(BundleVersion::orchard_v2(), &orchard_in[..], &[] as &[Zatoshis]),
            &(BundleVersion::orchard_v2(), &ironwood_in[..], &ironwood_out[..]),
            None,
            &change_receivers,
        )
        .map_err(|e| anyhow!("could not balance the asset transfer: {:?}", e))?;
    // The fee the screen showed is the estimate the caller passes down; the one paid is this.
    // A send that would cost more is not refused for good: it is handed back as a question
    // (`FEE_CHANGED:<fee>`), and the screen shows the real figure and asks again. The estimate
    // counts outputs; the fee counts inputs too, and a fee paid from the other pool or from
    // several small notes costs more (audit 2026-10-08, Zecboat G; review 2026-10-09,
    // regression Finding 5: the refusal used to be final, and no bound at all when the
    // estimate failed).
    {
        let fee = u64::from(balance.fee_required());
        let shown = match max_fee_zat {
            Some(m) => m,
            None => {
                let conn = rusqlite::Connection::open_with_flags(wallet_db_path()?, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                crate::wake_memo::send_estimate(&conn, asset_id, wake.genesis.as_ref(), wake.carrier.as_deref())
                    .map(|e| e.fee_zat)
                    .map_err(|e| anyhow!("the fee could not be estimated, so no bound could be checked: {e}"))?
            }
        };
        if fee > shown {
            return Err(anyhow!(
                "FEE_CHANGED:{fee}:the network fee for this transfer is {fee} zat, not the {shown} zat shown \
                 (the fee counts the notes that pay it as well as the outputs); confirm to send at {fee} zat"
            ));
        }
    }

    // ── 6. Explicit inputs → proposal → signed transaction ─────────────────────────────────
    let shielded_inputs = ShieldedInputs::from_parts(
        NonEmpty::from_vec(proposal_inputs).ok_or_else(|| anyhow!("no inputs selected"))?,
    );

    let proposal = Proposal::single_step(
        request,
        payment_pools,
        vec![],
        Some(shielded_inputs),
        anchor_height,
        balance,
        StandardFeeRule::Zip317,
        target_height,
        ConfirmationsPolicy::MIN,
        false,
        true, // Ironwood is active
    )
    .map_err(|e| anyhow!("the asset transfer proposal is not valid: {:?}", e))?;

    // ── 7. Pair the carrier spend with the carrier output, THEN prove (ZMAP v0.5 §5.5) ──────
    //
    // Consensus binds each output note's rho to the nullifier of the spend in the SAME Action,
    // so the carrier's lineage continues in whichever output shares the carrier spend's Action.
    // The orchard builder pairs spends and outputs at random. A transfer that puts the
    // recipient's carrier output in a different Action delivers the memo and loses the lineage
    // to the sender's change, which cannot be undone.
    //
    // So the transaction is built as a PCZT first (no proving, no signing, no wallet writes),
    // its Actions are inspected, and it is rebuilt until the carrier spend and the carrier output
    // share an Action. Only then is it proved, signed, extracted and stored: the backend does the
    // bookkeeping (`store_transactions_to_be_sent`) exactly as the one-shot path did.
    //
    // Pairing precedes proving, so a rebuild costs milliseconds. Two Actions: even odds per try.
    let fvk = usk.to_unified_full_viewing_key();
    let orchard_fvk = fvk
        .orchard()
        .ok_or_else(|| anyhow!("this wallet has no Orchard viewing key"))?
        .clone();
    let carrier_nf: [u8; 32] = carrier_typed_for_nf.note().nullifier(&orchard_fvk).to_bytes();
    let recipient_raw: [u8; 43] = match zcash_keys::address::Address::decode(&network, recipient) {
        Some(zcash_keys::address::Address::Unified(ua)) => ua
            .orchard()
            .map(|a| a.to_raw_address_bytes())
            .ok_or_else(|| anyhow!("the recipient's unified address has no Orchard receiver"))?,
        _ => return Err(anyhow!("a ZMAP carrier can only be sent to a unified address")),
    };

    // Each try pairs the carrier spend with the carrier output with odds of one in the number
    // of Actions; record outputs add Actions, so the budget grows with them.
    #[allow(non_snake_case)]
    let MAX_PAIRING_ATTEMPTS: usize = 64 + 40 * record_memos.len();
    let mut paired: Option<(pczt::Pczt, usize, [u8; 32])> = None;
    for attempt in 1..=MAX_PAIRING_ATTEMPTS {
        let candidate = create_pczt_from_proposal::<_, _, std::convert::Infallible, _, std::convert::Infallible, _>(
            wallet_db,
            &network,
            &zcash_client_sqlite::util::SystemClock,
            &mut OsRng,
            account_id,
            OvkPolicy::Sender,
            &proposal,
            Some(expiry_height.unwrap_or_else(|| crate::block_time::send_expiry(target_height.into()))),
            zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
        )
        .map_err(|e| anyhow!("could not build the asset transfer: {:?}", e))?;

        match carrier_pairing(&candidate, &carrier_nf, &recipient_raw) {
            Pairing::Paired { action_index, successor_cmx } => {
                println!("[zsa] carrier spend and carrier output share Action {action_index} (attempt {attempt})");
                paired = Some((candidate, action_index, successor_cmx));
                break;
            }
            Pairing::Mispaired { action_index } => {
                println!("[zsa] attempt {attempt}: carrier spend in Action {action_index} was paired with change; rebuilding");
            }
            // An Orchard-pool carrier (pre-NU6.3) is spent in the Orchard bundle and its
            // successor is an Ironwood output, so the one-Action pairing of ZMAP §5.5 cannot
            // hold and WAKE (Ironwood only, WAKE-v1 §2) cannot follow it. It moves, unproven;
            // it used to fail as "internal" (review 2026-10-09, session 4, Issue N).
            Pairing::CarrierSpendMissing if source_pool == ShieldedPool::Orchard => {
                if wake_lading.is_some() {
                    return Err(anyhow!(
                        "an Orchard-pool carrier cannot carry a Wake lineage (WAKE-v1 section 2: Ironwood only); \
                         it can only be sent unproven"
                    ));
                }
                println!("[zsa] Orchard-pool carrier: no Action pairing is possible across bundles; sending unproven (attempt {attempt})");
                paired = Some((candidate, usize::MAX, [0u8; 32]));
                break;
            }
            Pairing::CarrierSpendMissing => {
                return Err(anyhow!(
                    "internal: the built transaction does not spend the asset's carrier"
                ));
            }
        }
    }
    let (pczt, successor_action_index, successor_cmx) = paired.ok_or_else(|| {
        anyhow!(
            "could not pair the carrier spend with the carrier output in {} attempts; \
             refusing to send an asset whose lineage would be lost",
            MAX_PAIRING_ATTEMPTS
        )
    })?;

    // ── 8. Prove, sign, extract, store ─────────────────────────────────────────────────────
    let _ = LocalTxProver::with_default_location()
        .ok_or_else(|| anyhow!("{}", params_not_found()))?;
    let pk = zcash_primitives::transaction::builder::cached_orchard_proving_key(
        ::orchard::circuit::OrchardCircuitVersion::PostNu6_3,
    );
    let mut prover = pczt::roles::prover::Prover::new(pczt);
    if prover.requires_sapling_proofs() {
        return Err(anyhow!("internal: an asset transfer must not spend Sapling notes"));
    }
    if prover.requires_ironwood_proof() {
        prover = prover
            .create_ironwood_proof(OsRng, pk)
            .map_err(|e| anyhow!("could not prove the Ironwood bundle: {:?}", e))?;
    }
    if prover.requires_orchard_proof() {
        prover = prover
            .create_orchard_proof(OsRng, pk)
            .map_err(|e| anyhow!("could not prove the Orchard bundle: {:?}", e))?;
    }
    let pczt = prover.finish();

    let ask = ::orchard::keys::SpendAuthorizingKey::from(usk.orchard());
    // Real spends still lack a signature; protocol padding dummies were signed by the IO
    // Finalizer when the PCZT was created.
    let unsigned = |actions: &[pczt::orchard::Action]| -> Vec<usize> {
        actions
            .iter()
            .enumerate()
            .filter(|(_, a)| a.spend().spend_auth_sig().is_none())
            .map(|(i, _)| i)
            .collect()
    };
    let ironwood_unsigned = unsigned(pczt.ironwood().actions());
    let orchard_unsigned = unsigned(pczt.orchard().actions());
    let mut signer = pczt::roles::signer::Signer::new(pczt)
        .map_err(|e| anyhow!("could not start signing the asset transfer: {:?}", e))?;
    for i in ironwood_unsigned {
        signer.sign_ironwood(OsRng, i, &ask).map_err(|e| anyhow!("could not sign Ironwood spend {i}: {:?}", e))?;
    }
    for i in orchard_unsigned {
        signer.sign_orchard(OsRng, i, &ask).map_err(|e| anyhow!("could not sign Orchard spend {i}: {:?}", e))?;
    }
    let pczt = signer.finish();

    let vk = orchard_verifying_key();
    let txid = extract_and_store_transaction_from_pczt::<_, std::convert::Infallible>(
        wallet_db,
        &zcash_client_sqlite::util::SystemClock,
        &mut OsRng,
        pczt,
        None,
        Some(vk),
    )
    .map_err(|e| anyhow!("could not finalize the asset transfer: {:?}", e))?;

    // ── 9. Record where the lineage went, so a lost lading can be re-issued by the sender ──
    //
    // From here on the signed transaction is in the wallet's database, and the wallet will
    // broadcast anything stored there on its next send. So nothing below may fail the send:
    // a "failed" after this point used to leave a transaction that went out later anyway, and
    // a retry in between double-spent the carrier (audit 2026-10-08, Zecboat F). A failure
    // here is reported and the send goes on; the lading itself travels in the transaction.
    // A record that is not in the transfer exists nowhere but here, and a fresh proof would
    // hash differently: it is written as a sealed file for the recipient first, from memory,
    // before any database write that could fail (gate sixth pass, Finding 3). The finished
    // send names the file.
    let saved_as: Option<String> = match (&wake_lading, record_memos.is_empty(), successor_action_index != usize::MAX) {
        (Some(l), true, true) => match crate::wake::save_sealed_for(recipient, &l.bytes, &l.hash_hex) {
            Ok(path) => {
                println!("[wake] the lineage record is not in the transfer; sealed to the recipient and saved as {path}");
                Some(format!("saved as {path}; send that file to the recipient"))
            }
            Err(e) => {
                eprintln!("[wake] WARNING: the lineage record is not in the transfer and could not be saved as a file ({e}); it is kept in this wallet under sha256 {}", l.hash_hex);
                Some(format!("could not be saved as a file ({e}); use Save file"))
            }
        },
        _ => None,
    };
    let after_store = (|| -> Result<()> {
        let conn = rusqlite::Connection::open(wallet_db_path()?)
            .map_err(|e| anyhow!("could not open the wallet to record the lineage: {}", e))?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        if successor_action_index == usize::MAX {
            // An Orchard-pool carrier: no successor Action to record (see the pairing above).
            return Ok(());
        }
        let mut successor_txid = [0u8; 32];
        successor_txid.copy_from_slice(txid.as_ref());
        let spent_index = u32::try_from(plan.carrier.output_index())
            .map_err(|_| anyhow!("internal: carrier output index out of range"))?;
        // The sender's copy of the lading first (gate sixth pass, Finding 3): with the
        // Knotline the record is in the transaction itself; otherwise the file above and this
        // row are its only copies.
        let stored = match &wake_lading {
            Some(l) => {
                let stored = crate::zmap::store_consignment(&conn, asset_id, None, None, &l.bytes, Some(&successor_txid));
                if let Ok(hh) = &stored {
                    let _ = crate::zmap::mark_consignment_source(&conn, hh, "sent");
                    if !record_memos.is_empty() {
                        let _ = crate::zmap::mark_consignment_carried(&conn, &l.hash_hex);
                        println!("[wake] lading carried in the transfer");
                    } else {
                        // The outcome of the file write, so the finished send can show it
                        // (gate seventh pass, Finding D).
                        let note = saved_as.clone().unwrap_or_else(|| "not in the transfer: use Save file".into());
                        let _ = crate::zmap::mark_consignment_delivery(&conn, &l.hash_hex, Err(note.as_str()));
                    }
                }
                stored.map(|_| ()).map_err(|e| anyhow!("could not keep a copy of the lading: {}", e))
            }
            None => Ok(()),
        };
        crate::zmap::record_lineage_out(
            &conn,
            &crate::zmap::LineageOut {
                asset_id: asset_id.to_string(),
                spent_txid: *plan.carrier.txid().as_ref(),
                spent_action_index: spent_index,
                spent_nf: carrier_nf,
                successor_txid,
                successor_action_index: successor_action_index as u32,
                successor_cmx,
                recipient: recipient.to_string(),
            },
        )
        .map_err(|e| anyhow!("could not record the lineage of the sent asset: {}", e))?;
        stored
    })();
    if let Err(e) = after_store {
        eprintln!("[wake] WARNING: the transfer is signed and will be sent, but its lineage record could not be written: {e}");
    }

    // Read the signed transaction back and return its **wire encoding**, which every caller
    // hands straight to `rpc::broadcast_raw_tx` (see the P1-10 note in the git history: this
    // once returned the txid, and no asset transfer was ever broadcast).
    // The transaction is stored at this point and will be broadcast by the next send whatever
    // this read-back does, so a failure here says so instead of "failed" (gate eighth pass,
    // Issue E; the class of audit 2026-10-08, Zecboat F). Read three times before giving up.
    let mut last: Option<anyhow::Error> = None;
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        match wallet_db.get_transaction(txid) {
            Ok(Some(tx)) => {
                let mut raw = Vec::new();
                match tx.write(&mut raw) {
                    Ok(()) => return Ok(hex::encode(raw)),
                    Err(e) => last = Some(anyhow!("could not serialize the asset transfer: {:?}", e)),
                }
            }
            Ok(None) => last = Some(anyhow!("signed asset transfer {} is missing from the wallet database", txid)),
            Err(e) => last = Some(anyhow!("could not read back the signed asset transfer: {:?}", e)),
        }
    }
    Err(anyhow!(
        "{}{}: the transfer is signed and stored in this wallet, and will be broadcast with the next send; it could not be read back now ({})",
        STORED_NOT_BROADCAST_PREFIX,
        txid,
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// What inspecting a built-but-unproven asset transfer found (ZMAP v0.5 §5.5).
enum Pairing {
    /// The carrier spend's Action produces the recipient's carrier output.
    Paired { action_index: usize, successor_cmx: [u8; 32] },
    /// The carrier spend's Action produces some other output (the sender's change).
    Mispaired { action_index: usize },
    /// No Action spends the carrier at all.
    CarrierSpendMissing,
}

/// Find the Action spending `carrier_nf` in the Ironwood bundle and say what its output is.
fn carrier_pairing(pczt: &pczt::Pczt, carrier_nf: &[u8; 32], recipient_raw: &[u8; 43]) -> Pairing {
    for (i, action) in pczt.ironwood().actions().iter().enumerate() {
        if action.spend().nullifier() != carrier_nf {
            continue;
        }
        let out = action.output();
        let to_recipient = out.recipient().as_ref() == Some(recipient_raw);
        let carrier_value = *out.value() == Some(crate::zmap::CARRIER_ZAT);
        return if to_recipient && carrier_value {
            let mut cmx = [0u8; 32];
            if let Some(c) = out.cmx() {
                cmx.copy_from_slice(c);
            }
            Pairing::Paired { action_index: i, successor_cmx: cmx }
        } else {
            Pairing::Mispaired { action_index: i }
        };
    }
    Pairing::CarrierSpendMissing
}

/// The Orchard/Ironwood verifying key for the post-NU6.3 circuit, built once per process.
fn orchard_verifying_key() -> &'static ::orchard::circuit::VerifyingKey {
    static VK: std::sync::OnceLock<::orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    VK.get_or_init(|| {
        ::orchard::circuit::VerifyingKey::build(::orchard::circuit::OrchardCircuitVersion::PostNu6_3)
    })
}

/// The carrier the plan spends, as the wallet lists it (pool included).
fn holdings_carrier(plan: &crate::zmap::AssetSendPlan) -> Option<crate::zmap::CarrierRef> {
    let conn = rusqlite::Connection::open_with_flags(wallet_db_path().ok()?, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn).ok()?)
        .into_iter()
        .flat_map(|h| h.carriers)
        .find(|c| c.txid_bytes[..] == plan.carrier.txid().as_ref()[..] && c.output_index as u32 == plan.carrier.output_index())
}

/// Whether two encoded unified full viewing keys hold the same shielded account: equal as
/// strings, or equal in their Orchard full viewing key once decoded. A key that does not decode
/// is compared as a string only (gate second pass, Issue G).
pub(crate) fn same_viewing_key(published: &str, mine: &str) -> bool {
    let (published, mine) = (published.trim(), mine.trim());
    if published == mine {
        return true;
    }
    let decode = |s: &str| zcash_keys::keys::UnifiedFullViewingKey::decode(&zcash_protocol::consensus::MainNetwork, s).ok();
    match (decode(published), decode(mine)) {
        (Some(a), Some(b)) => match (a.orchard(), b.orchard()) {
            (Some(x), Some(y)) => x.to_bytes() == y.to_bytes(),
            _ => false,
        },
        _ => false,
    }
}
