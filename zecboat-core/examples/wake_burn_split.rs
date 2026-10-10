//! v0.7.0 build box, lines B6 and B7, on COPIES of wallets in scratch HOMEs. Nothing broadcasts.
//!
//!   cargo build --release --example wake_burn_split
//!
//!   B6  env HOME=<scratch copy> target/release/examples/wake_burn_split burn <seed words file> <recipient UA>
//!       A plain ZEC send that can only be funded by consuming a carrier must be refused, and
//!       the carrier must still be unspent afterwards. Three layers are exercised: the
//!       `validate_anti_burn` hook, the carrier locks that exclude carriers from selection,
//!       and the asset-send path's refusal of a non-unified recipient.
//!
//!   B7  env HOME=<scratch copy> target/release/examples/wake_burn_split split <seed words file> <asset_id> \
//!           <recipient UA> <own UA> <lading.json>
//!       Builds a SPLIT: spends one carrier and writes its memo on TWO 10,000-zat outputs, one to
//!       each address. Then shows what the chain and Wake make of it: exactly one output's ρ is
//!       the spent carrier's nullifier (consensus), the lading extended by the sender's hop
//!       verifies for that ρ and is refused (`RhoMismatch`) for the other. The signed
//!       transaction is written to `$HOME/split_tx.hex` and NOT broadcast.
use std::env;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::{BlockHeight, MainNetwork};

type Db = zcash_client_sqlite::WalletDb<rusqlite::Connection, MainNetwork, zcash_client_sqlite::util::SystemClock, rand::rngs::OsRng>;

fn guard_home() -> anyhow::Result<String> {
    let home = env::var("HOME")?;
    if home.contains("captain") || home.contains("user2") || !home.contains("scratch") {
        anyhow::bail!("refusing: HOME must be a scratch directory holding a wallet COPY (got {home})");
    }
    Ok(home)
}

fn usk_from(words_path: &str) -> anyhow::Result<UnifiedSpendingKey> {
    let words: Vec<String> = std::fs::read_to_string(words_path)?
        .split_whitespace()
        .filter(|t| !t.trim_end_matches('.').chars().all(|c| c.is_ascii_digit()))
        .map(str::to_lowercase)
        .collect();
    let mnemonic = bip0039::Mnemonic::<bip0039::English>::from_phrase(&words.join(" "))
        .map_err(|e| anyhow::anyhow!("seed words: {:?}", e))?;
    UnifiedSpendingKey::from_seed(&MainNetwork, &mnemonic.to_seed(""), zip32::AccountId::ZERO)
        .map_err(|e| anyhow::anyhow!("usk: {:?}", e))
}

fn open_db() -> anyhow::Result<(Db, String)> {
    let db_path = zecboat_core::paths::as_string::wallet_db_path()?;
    let db = zcash_client_sqlite::WalletDb::for_path(&db_path, MainNetwork, zcash_client_sqlite::util::SystemClock, rand::rngs::OsRng)?;
    Ok((db, db_path))
}

fn tip() -> anyhow::Result<u32> {
    let url = env::var("WAKE_ZEBRAD").unwrap_or_else(|_| "http://127.0.0.1:8232".into());
    let out = std::process::Command::new("curl")
        .args(["-s", "--max-time", "10", "-u", "x:x", "-H", "content-type: application/json",
               "--data", r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#, &url])
        .output()?;
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(v["result"].as_u64().ok_or_else(|| anyhow::anyhow!("no tip from zebrad"))? as u32)
}

fn carrier_state(db_path: &str) -> anyhow::Result<(usize, usize, usize)> {
    let conn = rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let unspent: usize = conn.query_row(
        "SELECT COUNT(*) FROM ironwood_received_notes n WHERE n.value = 10000 AND n.memo IS NOT NULL AND substr(n.memo,1,1) = X'7B' \
         AND n.id NOT IN (SELECT ironwood_received_note_id FROM ironwood_received_note_spends)", [], |r| r.get::<_, i64>(0))? as usize;
    let spent: usize = conn.query_row(
        "SELECT COUNT(*) FROM ironwood_received_notes n WHERE n.value = 10000 AND n.memo IS NOT NULL AND substr(n.memo,1,1) = X'7B' \
         AND n.id IN (SELECT ironwood_received_note_id FROM ironwood_received_note_spends)", [], |r| r.get::<_, i64>(0))? as usize;
    let txs: usize = conn.query_row("SELECT COUNT(*) FROM transactions", [], |r| r.get::<_, i64>(0))? as usize;
    Ok((unspent, spent, txs))
}

fn burn(words: &str, recipient: &str) -> anyhow::Result<()> {
    let usk = usk_from(words)?;
    let (db, db_path) = open_db()?;
    let before = carrier_state(&db_path)?;
    println!("before: {} carrier(s) unspent, {} spent, {} transactions", before.0, before.1, before.2);

    // Layer 1: the hook itself, fed a carrier-shaped input that nobody selected as an asset.
    let hook = zecboat_core::wallet::validate_anti_burn(&[zecboat_core::wallet::ProposedInput {
        txid: "db85e27e".into(), pool: "ironwood".into(), value_zat: 10_000, outindex: 0, is_explicitly_selected_asset: false,
    }]);
    println!("B6.1 validate_anti_burn on a 10,000-zat input not selected as an asset: {}",
        match &hook { Ok(()) => "ACCEPTED (wrong)".to_string(), Err(e) => format!("REFUSED: {}", e.to_string().lines().next().unwrap_or("")) });

    // Layer 2: the real build path. The copy holds 15,000 zat of plain ZEC and one 10,000-zat
    // carrier; 12,000 + a 10,000 fee can only be funded by consuming the carrier.
    let height = tip()?;
    let r = zecboat_core::native_builder::build_and_sign_transaction(db, &usk, &[], recipient, 12_000, b"", height);
    match &r {
        Ok(hex) => println!("B6.2 build_and_sign_transaction(12,000 zat): BUILT {} bytes — check below whether it consumed the carrier", hex.len() / 2),
        Err(e) => println!("B6.2 build_and_sign_transaction(12,000 zat): REFUSED: {}", e.to_string().replace('\n', " ").chars().take(220).collect::<String>()),
    }
    let after = carrier_state(&db_path)?;
    println!("after:  {} carrier(s) unspent, {} spent, {} transactions", after.0, after.1, after.2);
    if after.0 == before.0 && after.2 == before.2 {
        println!("B6 RESULT: the carrier is untouched and no transaction was built");
    } else {
        println!("B6 RESULT: STATE CHANGED — investigate");
    }

    // Layer 3: the asset path refuses a destination that cannot carry a memo.
    let (mut db2, _) = open_db()?;
    let r3 = zecboat_core::native_builder::send_zmap_asset(&mut db2, &usk, "a21c64a9012d95a0b923f825f3d16b483a76804393948ff085715509f278c837",
        "t1Hsc1LR8yKnbbe3twRp88p6vFfC5t7DLbs", None, &zecboat_core::wake::SendOptions { genesis: None, acknowledge_unproven: true, abandon_lineage: None, carrier: None }, None);
    println!("B6.3 send_zmap_asset to a transparent address: {}",
        match &r3 { Ok(_) => "BUILT (wrong)".to_string(), Err(e) => format!("REFUSED: {}", e.to_string().lines().next().unwrap_or("")) });
    Ok(())
}

fn split(words: &str, asset_id: &str, to_other: &str, to_self: &str, lading_path: &str, second_zat: u64) -> anyhow::Result<()> {
    use zcash_client_backend::data_api::wallet::input_selection::{LockFilter, LockedInputPolicy, NonEmptyBTreeSet, SpendPolicy};
    use zcash_client_backend::data_api::wallet::{create_pczt_from_proposal, extract_and_store_transaction_from_pczt, ConfirmationsPolicy};
    use zcash_client_backend::data_api::{InputSource, TargetValue, WalletRead};
    use zcash_client_backend::fees::standard::SingleOutputChangeStrategy;
    use zcash_client_backend::fees::{sapling as sapling_fees, ChangeStrategy, DustOutputPolicy, StandardFeeRule};
    use zcash_client_backend::proposal::{Proposal, ShieldedInputs};
    use zcash_client_backend::wallet::{Note as WalletNote, OvkPolicy, ReceivedNote};
    use zcash_client_backend::zip321::{Payment, TransactionRequest};
    use zcash_address::ZcashAddress;
    use zcash_protocol::memo::MemoBytes;
    use zcash_protocol::value::Zatoshis;
    use zcash_protocol::ShieldedPool;
    use ::orchard::bundle::BundleVersion;
    use zcash_transparent::bundle::TxOut;
    use nonempty::NonEmpty;

    let usk = usk_from(words)?;
    let (mut wallet_db, db_path) = open_db()?;
    let network = MainNetwork;

    // The carrier to split, chosen exactly as a real send would choose it.
    let holdings = {
        let conn = rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        zecboat_core::zmap::holdings_from_rows(zecboat_core::zmap::read_carrier_rows(&conn)?)
    };
    let plan = zecboat_core::zmap::plan_asset_send(&holdings, asset_id)?;
    let account_id = wallet_db.get_account_ids().map_err(|e| anyhow::anyhow!("{e:?}"))?.into_iter().next().ok_or_else(|| anyhow::anyhow!("no account"))?;
    let (target_height, anchor_height) = wallet_db
        .get_target_and_anchor_heights(ConfirmationsPolicy::MIN.trusted())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .ok_or_else(|| anyhow::anyhow!("not synced"))?;
    let source_pool = match plan.source_pool {
        zcash_protocol::PoolType::Shielded(p) => p,
        _ => anyhow::bail!("carrier is not shielded"),
    };
    let unlock = SpendPolicy::default().with_locked_input_policy(LockedInputPolicy::PreferLocked(NonEmptyBTreeSet::singleton(plan.lock_owner)));
    let carrier_note = wallet_db
        .get_spendable_note(plan.carrier.txid(), source_pool, plan.carrier.output_index(), target_height, LockFilter::Policy(unlock.locked_input_policy()))
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
        .ok_or_else(|| anyhow::anyhow!("carrier not spendable"))?;
    let fee_notes = wallet_db
        .select_spendable_notes(account_id, TargetValue::AtLeast(Zatoshis::from_u64(20_000)?), &[ShieldedPool::Ironwood], target_height,
            ConfirmationsPolicy::MIN, &[], LockFilter::Policy(&LockedInputPolicy::Exclude))
        .map_err(|e| anyhow::anyhow!("fee notes: {e:?}"))?;
    println!("split: spending carrier {}… out {} plus {} plain Ironwood note(s)", &plan.carrier.txid().to_string()[..12], plan.carrier.output_index(), fee_notes.ironwood().len());

    // TWO payments, both carrying the carrier's memo. This is the split.
    let amount = Zatoshis::from_u64(zecboat_core::zmap::CARRIER_ZAT)?;
    let second = Zatoshis::from_u64(second_zat)?;
    let memo = MemoBytes::from_bytes(&plan.memo)?;
    let mut payments = Vec::new();
    for (to, v) in [(to_other, amount), (to_self, second)] {
        let addr = ZcashAddress::try_from_encoded(to)?;
        payments.push(Payment::new(addr, Some(v), Some(memo.clone()), None, None, vec![]).map_err(|e| anyhow::anyhow!("{e:?}"))?);
    }
    println!("split shape: {} zat to the recipient and {} zat to self, both with the carrier's memo", u64::from(amount), second_zat);
    let request = TransactionRequest::new(payments).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let mut payment_pools = std::collections::BTreeMap::new();
    payment_pools.insert(0usize, zcash_protocol::PoolType::IRONWOOD);
    payment_pools.insert(1usize, zcash_protocol::PoolType::IRONWOOD);

    let change_strategy = SingleOutputChangeStrategy::<Db>::new(StandardFeeRule::Zip317, None, ShieldedPool::Ironwood, DustOutputPolicy::default());
    let to_typed = |n: ReceivedNote<_, WalletNote>| -> anyhow::Result<ReceivedNote<_, ::orchard::Note>> {
        match n.note() {
            WalletNote::Orchard { .. } => Ok(n.map_note(|note| match note { WalletNote::Orchard { note, .. } => note, _ => unreachable!() })),
            _ => anyhow::bail!("not an Orchard-shaped note"),
        }
    };
    let to_enum = |n: ReceivedNote<_, ::orchard::Note>, pool: ::orchard::ValuePool| n.map_note(|note| WalletNote::Orchard { note, pool });

    let mut proposal_inputs: Vec<ReceivedNote<_, WalletNote>> = Vec::new();
    for n in fee_notes.ironwood().iter().cloned() { proposal_inputs.push(to_enum(n, ::orchard::ValuePool::Ironwood)); }
    proposal_inputs.push(carrier_note.clone());
    let mut ironwood_in: Vec<ReceivedNote<_, ::orchard::Note>> = fee_notes.ironwood().to_vec();
    let orchard_in: Vec<ReceivedNote<_, ::orchard::Note>> = fee_notes.orchard().to_vec(); // empty; typed for the balance call
    let carrier_typed = to_typed(carrier_note)?;
    let fvk = usk.to_unified_full_viewing_key();
    let orchard_fvk = fvk.orchard().ok_or_else(|| anyhow::anyhow!("no orchard fvk"))?.clone();
    let carrier_nf: [u8; 32] = carrier_typed.note().nullifier(&orchard_fvk).to_bytes();
    ironwood_in.push(carrier_typed);
    let ironwood_out = vec![amount, second];
    let balance = change_strategy
        .compute_balance(&network, target_height, &[] as &[std::convert::Infallible], &[] as &[TxOut], &sapling_fees::EmptyBundleView,
            &(BundleVersion::orchard_v2(), &orchard_in[..], &[] as &[Zatoshis]),
            &(BundleVersion::orchard_v2(), &ironwood_in[..], &ironwood_out[..]), None, &())
        .map_err(|e| anyhow::anyhow!("balance: {e:?}"))?;
    let proposal = Proposal::single_step(request, payment_pools, vec![],
        Some(ShieldedInputs::from_parts(NonEmpty::from_vec(proposal_inputs).unwrap())),
        anchor_height, balance, StandardFeeRule::Zip317, target_height, ConfirmationsPolicy::MIN, false, true)
        .map_err(|e| anyhow::anyhow!("proposal: {e:?}"))?;
    let expiry = Some(BlockHeight::from_u32(tip()? + 40));
    let pczt = create_pczt_from_proposal::<_, _, std::convert::Infallible, _, std::convert::Infallible, _>(
        &mut wallet_db, &network, account_id, OvkPolicy::Sender, &proposal, expiry,
        zcash_primitives::transaction::builder::BundlePadding::DEFAULT)
        .map_err(|e| anyhow::anyhow!("build: {e:?}"))?;

    // What consensus decided: each output's ρ is the nullifier of the spend in ITS Action.
    let raw_other = ua_raw(to_other)?; let raw_self = ua_raw(to_self)?;
    let mut rho_of: Vec<(String, [u8; 32], bool)> = Vec::new();
    for (i, action) in pczt.ironwood().actions().iter().enumerate() {
        let out = action.output();
        let who = if out.recipient().as_ref() == Some(&raw_other) { "recipient" } else if out.recipient().as_ref() == Some(&raw_self) { "self" } else { "change/dummy" };
        let value = out.value().unwrap_or(0);
        let paired = action.spend().nullifier() == &carrier_nf;
        println!("  Action {i}: spend nf {}… -> output {who:>12} {value:>6} zat  rho = that nf  {}", hex::encode(&action.spend().nullifier()[..6]), if paired { "<= the carrier's lineage lands here" } else { "" });
        if value > 0 && who != "change/dummy" { rho_of.push((format!("{who} ({value} zat)"), *action.spend().nullifier(), paired)); }
    }

    // Prove, sign, extract: a real transaction, not broadcast.
    let pk = zcash_primitives::transaction::builder::cached_orchard_proving_key(::orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let mut prover = pczt::roles::prover::Prover::new(pczt);
    if prover.requires_ironwood_proof() { prover = prover.create_ironwood_proof(pk).map_err(|e| anyhow::anyhow!("{e:?}"))?; }
    let pczt = prover.finish();
    let ask = ::orchard::keys::SpendAuthorizingKey::from(usk.orchard());
    let unsigned: Vec<usize> = pczt.ironwood().actions().iter().enumerate().filter(|(_, a)| a.spend().spend_auth_sig().is_none()).map(|(i, _)| i).collect();
    let mut signer = pczt::roles::signer::Signer::new(pczt).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    for i in unsigned { signer.sign_ironwood(i, &ask).map_err(|e| anyhow::anyhow!("{e:?}"))?; }
    let pczt = signer.finish();
    let vk = ::orchard::circuit::VerifyingKey::build(::orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let txid = extract_and_store_transaction_from_pczt::<_, std::convert::Infallible>(&mut wallet_db, pczt, None, Some(&vk)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let tx = wallet_db.get_transaction(txid).map_err(|e| anyhow::anyhow!("{e:?}"))?.ok_or_else(|| anyhow::anyhow!("missing"))?;
    let mut raw = Vec::new(); tx.write(&mut raw)?;
    let out = format!("{}/split_tx.hex", env::var("HOME")?);
    std::fs::write(&out, hex::encode(&raw))?;
    println!("split BUILT: txid {txid}, {} bytes, written to {out}, NOT broadcast", raw.len());

    // What Wake makes of it: the sender's hop on top of the delivered lading, then W5 per output.
    let lading_bytes = std::fs::read(lading_path)?;
    let mut lading = zmap_wake::lading::Lading::parse(&lading_bytes)?;
    let conn = rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let note = zecboat_core::wake::carrier_note(&conn, plan.carrier.txid().as_ref(), plan.carrier.output_index())?;
    let oracle = zecboat_core::wake::chain(); // 0.7.1: own node, else the provider (the trait is the same)
    let ts = oracle.ironwood_tree_state(note.mined_height)?;
    let w = zmap_wake::wallet_notes::witness_at(&wallet_db, &note, &ts)?;
    let proof = zmap_wake::prove_hop(&w).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    lading.hops.push(zmap_wake::lading::ProofEntry::from_proof(&proof, note.mined_height));
    let bytes = lading.to_bytes();
    println!("lading extended by the sender's hop: {} proofs", lading.hops.len());
    let mut verified = 0;
    for (who, rho_bytes, paired) in &rho_of {
        let rho = Option::<::orchard::note::Rho>::from(::orchard::note::Rho::from_bytes(rho_bytes)).ok_or_else(|| anyhow::anyhow!("rho"))?;
        match zmap_wake::verify_chain(&bytes, None, &rho, &oracle, zmap_wake::oracle::MIN_DEPTH) {
            Ok(v) => { verified += 1; println!("  output to {who}: lineage VERIFIED ({} proofs, anchor {} deep){}{}", v.hops, v.min_anchor_depth, if who.contains("10000 zat") { "" } else { "  BUT not carrier-valued: not a unit (value rule)" }, if *paired { "" } else { "  <- UNEXPECTED" }); }
            Err(e) => println!("  output to {who}: lineage REFUSED — {e}{}", if *paired { "  <- UNEXPECTED" } else { "" }),
        }
    }
    let units = rho_of.iter().filter(|(who, _, paired)| *paired && who.contains("10000 zat")).count();
    println!("B7 RESULT: {} of {} memo-carrying outputs has the lineage; {} of them is a carrier-valued unit with lineage. The split yields at most one unit.", verified, rho_of.len(), units);
    Ok(())
}

fn ua_raw(ua: &str) -> anyhow::Result<[u8; 43]> {
    match zcash_keys::address::Address::decode(&MainNetwork, ua) {
        Some(zcash_keys::address::Address::Unified(u)) => u.orchard().map(|a| a.to_raw_address_bytes()).ok_or_else(|| anyhow::anyhow!("no orchard receiver")),
        _ => anyhow::bail!("not a unified address: {ua}"),
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let home = guard_home()?;
    println!("wallet copy under {home}");
    match args.get(1).map(String::as_str) {
        Some("burn") if args.len() == 4 => burn(&args[2], &args[3]),
        Some("split") if args.len() >= 7 => split(&args[2], &args[3], &args[4], &args[5], &args[6], args.get(7).and_then(|a| a.parse().ok()).unwrap_or(zecboat_core::zmap::CARRIER_ZAT)),
        _ => anyhow::bail!("usage: wake_burn_split burn <words> <recipient UA> | split <words> <asset_id> <recipient UA> <own UA> <lading.json> [second output zat]"),
    }
}
