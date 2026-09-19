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

use rand::rngs::OsRng;

use zcash_client_backend::data_api::wallet::input_selection::GreedyInputSelector;
use zcash_client_backend::data_api::wallet::{
    create_proposed_transactions, propose_transfer, ConfirmationsPolicy, SpendingKeys,
};
use zcash_client_backend::data_api::{WalletRead, WalletWrite};
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
    let expiry = target_height + CARRIER_LOCK_BLOCKS;

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

    Ok(locked)
}

/// How far ahead carrier locks are set. ~35 days at 75-second blocks.
const CARRIER_LOCK_BLOCKS: u32 = 40_000;

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
        &prover,
        &prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        None, // default expiry
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
/// # Who pays the fee
///
/// The sender, from separate notes. Fees are inputs minus outputs, so taking it from the carrier
/// would leave the recipient a sub-carrier note and destroy the asset. The recipient receives
/// exactly [`crate::zmap::CARRIER_ZAT`]. **A wallet holding only carriers cannot send them.**
pub fn send_zmap_asset(
    wallet_db: &mut Db,
    usk: &UnifiedSpendingKey,
    asset_id: &str,
    recipient: &str,
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
    let holdings = {
        let conn = rusqlite::Connection::open_with_flags(
            wallet_db_path()?,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        crate::zmap::holdings_from_rows(crate::zmap::read_carrier_rows(&conn)?)
    };
    let plan = crate::zmap::plan_asset_send(&holdings, asset_id)?;

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
    let fee_headroom = Zatoshis::from_u64(crate::zmap::CARRIER_ZAT * 6)
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
    let memo = MemoBytes::from_bytes(&plan.memo)
        .map_err(|e| anyhow!("the carrier's memo will not fit a memo field: {:?}", e))?;
    let payment = Payment::new(recipient_addr, Some(amount), Some(memo), None, None, vec![])
        .map_err(|e| anyhow!("could not construct the asset payment: {:?}", e))?;
    let request = TransactionRequest::new(vec![payment])
        .map_err(|e| anyhow!("could not construct the transfer request: {:?}", e))?;
    let mut payment_pools = std::collections::BTreeMap::new();
    payment_pools.insert(0usize, zcash_protocol::PoolType::IRONWOOD);

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
    match source_pool {
        ShieldedPool::Ironwood => ironwood_in.push(carrier_typed),
        ShieldedPool::Orchard => orchard_in.push(carrier_typed),
        ShieldedPool::Sapling => return Err(anyhow!("Sapling carriers are not supported")),
    }

    let ironwood_out = vec![amount];

    // SingleOutputChangeStrategy carries no account metadata (`AccountMetaT = ()`), so there is
    // nothing to fetch here — a metadata query would be work whose result is discarded.
    let balance = change_strategy
        .compute_balance(
            &network,
            target_height,
            &[] as &[std::convert::Infallible],
            &[] as &[TxOut],
            &sapling_fees::EmptyBundleView,
            &(BundleVersion::orchard_v2(), &orchard_in[..], &[] as &[Zatoshis]),
            &(BundleVersion::orchard_v2(), &ironwood_in[..], &ironwood_out[..]),
            None,
            &(),
        )
        .map_err(|e| anyhow!("could not balance the asset transfer: {:?}", e))?;

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

    let prover = LocalTxProver::with_default_location()
        .ok_or_else(|| anyhow!("{}", params_not_found()))?;
    let spending_keys = SpendingKeys::from_unified_spending_key(usk.clone());

    let txids = create_proposed_transactions::<_, _, std::convert::Infallible, _, std::convert::Infallible, _>(
        wallet_db,
        &network,
        &prover,
        &prover,
        &spending_keys,
        OvkPolicy::Sender,
        &proposal,
        None,
    )
    .map_err(|e| anyhow!("could not create the asset transfer: {:?}", e))?;

    // Read the signed transaction back and return its **wire encoding**.
    //
    // This line used to be `Ok(hex::encode(txids.first().as_ref()))` — the txid,
    // 32 bytes — while every caller treats the return value as the raw
    // transaction and hands it straight to `rpc::broadcast_raw_tx`. So no ZSA
    // transfer was ever broadcast: the node received 32 bytes of txid where a
    // transaction should be.
    //
    // That is the whole of "P1-10". Three occurrences, on local zaino and on
    // Port, all reported as
    //
    //     InternalServerError: error receiving data from backing node
    //
    // which is only zaino's unhelpful reaction to being handed 32 bytes that are
    // not a transaction; zebrad says "parse error: bad tx header", which is what
    // finally identified it. The transaction itself was always fine — built,
    // signed, 9,166 bytes, sitting in `transactions.raw` with its inputs already
    // marked spent. Both delivered HBD assets got there by a hand-run
    // `sendrawtransaction` of exactly those stored bytes.
    //
    // `build_and_sign_transaction` above has always done this correctly. This is
    // the same three lines.
    let txid = txids.first();
    let tx = wallet_db
        .get_transaction(*txid)
        .map_err(|e| anyhow!("could not read back the signed asset transfer: {:?}", e))?
        .ok_or_else(|| {
            anyhow!("signed asset transfer {} is missing from the wallet database", txid)
        })?;

    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| anyhow!("could not serialize the asset transfer: {:?}", e))?;

    Ok(hex::encode(raw))
}
