use anyhow::{anyhow, Result};
use zcash_protocol::value::ZatBalance;

/// Represents a selected unspent note proposed for a transaction.
#[derive(Debug, Clone)]
pub struct ProposedInput {
    pub txid: String,
    pub pool: String,
    pub value_zat: u64,
    pub outindex: u32,
    pub is_explicitly_selected_asset: bool,
}

/// The spending key this wallet signs with, from its stored seed phrase.
///
/// ONE derivation for every spend path. Batch, ordinary and asset sends each carried
/// their own copy of the same three lines; one place means the parameters cannot drift
/// between them, `tests/recovery_roundtrip.rs` can call the exact function a send calls
/// rather than re-deriving beside it, and F5 (zeroising the 64-byte seed) becomes a
/// change to one function instead of three.
///
/// The error never names a word of the phrase: `phrase_to_mnemonic` reports a count and
/// nothing else, and this only wraps the derivation error, which carries no phrase.
pub fn spending_key_from_phrase(phrase: &str) -> Result<zcash_keys::keys::UnifiedSpendingKey> {
    let mnemonic = crate::rpc::phrase_to_mnemonic(phrase.trim())?;
    // F5. The array is wiped when it drops. The Mnemonic wipes itself (bip0039 impls
    // Zeroize). Best effort by nature: Rust does not promise the compiler made no copy.
    let seed_bytes = zeroize::Zeroizing::new(mnemonic.to_seed(""));
    zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &zcash_protocol::consensus::MainNetwork,
        &*seed_bytes,
        zip32::AccountId::ZERO,
    )
    .map_err(|e| anyhow!("Invalid seed: {:?}", e))
}

/// The Anti-Burn Safety Hook
/// Iterates over all proposed inputs. If any input is exactly 10,000 Zats (the NFT standard)
/// and was not explicitly selected by the user to be transferred, we abort.
pub fn validate_anti_burn(inputs: &[ProposedInput]) -> Result<()> {
    for input in inputs {
        if input.value_zat == 10_000 && !input.is_explicitly_selected_asset {
            return Err(anyhow!(
                "ANTI-BURN TRIGGERED: Attempted to consume a 10,000 Zat note (potential ZSA/Cyber-Nomad) \
                as a miner fee or generic ZEC spend. TxID: {}",
                input.txid
            ));
        }
    }
    Ok(())
}

/// Prepares and sends a batched transaction with multiple outputs.
pub fn batch_send_transaction(
    outputs: Vec<(String, u64, String)>,
    target_height_u32: u32,
) -> Result<(String, Vec<ProposedInput>)> {
    if outputs.is_empty() {
        return Err(anyhow!("Cannot send an empty batch transaction"));
    }
    if outputs.len() > 50 {
        return Err(anyhow!("Batch transaction exceeds maximum of 50 outputs for safety"));
    }

    // 1. Calculate total amount
    let total_amount_zat: u64 = outputs.iter().map(|(_, amount, _)| *amount).sum();
    let _tx_amount = ZatBalance::from_u64(total_amount_zat)
        .map_err(|_| anyhow!("Invalid total transaction amount"))?;

    // 2. Validate all memos
    for (_, _, memo) in &outputs {
        if memo.as_bytes().len() > 512 {
            return Err(anyhow!("One of the memos exceeds the maximum 512 bytes allowed by Zcash consensus."));
        }
    }
    
    // 3. Key Extraction: Read and decrypt the spending key using `age`
    let identity_path = crate::paths::as_string::identity_path()?;
    
    let encrypted_data = std::fs::read(&identity_path)
        .map_err(|e| anyhow!("could not read the encryption identity file at {}: {}", identity_path, e))?;
        
    let password_str = crate::rpc::WALLET_PASSWORD.lock().unwrap().clone()
        .ok_or_else(|| anyhow!("Wallet is locked. Password required to decrypt identity file"))?;

    let decryptor = match age::Decryptor::new(&encrypted_data[..]) {
        Ok(age::Decryptor::Passphrase(d)) => d,
        _ => return Err(anyhow!("Expected passphrase-based age encryption")),
    };

    let mut decrypted_identity = vec![];
    let mut reader = decryptor.decrypt(&age::secrecy::Secret::new(password_str.to_string()), Some(22))
        .map_err(|e| anyhow!("Decryption failed: Invalid password or corrupted file ({:?})", e))?;
    
    std::io::Read::read_to_end(&mut reader, &mut decrypted_identity)
        .map_err(|e| anyhow!("could not read the decrypted data: {e}"))?;
        
    let identity_str = String::from_utf8(decrypted_identity)
        .map_err(|e| anyhow!("decrypted data is not valid UTF-8: {e}"))?;

    let identity_key = identity_str.lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .ok_or_else(|| anyhow!("No AGE-SECRET-KEY found in decrypted identity"))?;

    let identity: age::x25519::Identity = std::str::FromStr::from_str(identity_key)
        .map_err(|e| anyhow!("Invalid identity format: {:?}", e))?;

    // 4. Initialize WalletDb
    use zcash_client_sqlite::WalletDb;
    use zcash_client_sqlite::util::SystemClock;
    use zcash_protocol::consensus::MainNetwork;
    use rand::rngs::OsRng;
    use zcash_client_backend::data_api::{WalletRead, InputSource};
    use zcash_client_backend::data_api::wallet::TargetHeight;
    use zcash_protocol::ShieldedPool;
    
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let mut wallet_db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, OsRng)
        .map_err(|e| anyhow!("Failed to open wallet DB: {:?}", e))?;

    zcash_client_sqlite::wallet::init::init_wallet_db(&mut wallet_db, None)
        .map_err(|e| anyhow!("Failed to init wallet DB: {:?}", e))?;

    // 4.5 Fetch and decrypt the Mnemonic
    let encrypted_mnemonic_bytes: Vec<u8> = {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| anyhow!("Failed to open DB for mnemonic: {:?}", e))?;
        let mut stmt = conn.prepare("SELECT encrypted_mnemonic FROM ext_zecboat_keystore_mnemonics LIMIT 1")
            .map_err(|e| anyhow!("Failed to prepare mnemonic query: {:?}", e))?;
        let mut rows = stmt.query([])
            .map_err(|e| anyhow!("Failed to execute mnemonic query: {:?}", e))?;
        let row = rows.next().map_err(|e| anyhow!("DB error: {:?}", e))?
            .ok_or_else(|| anyhow!("No encrypted mnemonic found in database"))?;
        row.get(0).map_err(|e| anyhow!("Failed to read blob: {:?}", e))?
    };

    let mnemonic_decryptor = match age::Decryptor::new(&encrypted_mnemonic_bytes[..]) {
        Ok(age::Decryptor::Recipients(d)) => d,
        // A malformed blob previously panicked the whole backend here via `.unwrap()`,
        // taking the application down with no message. The wallet database holds this
        // blob, so corruption on disk — a truncated write, a bad restore — reached the
        // user as a crash rather than an explanation.
        Ok(_) => return Err(anyhow!(
            "the encrypted seed phrase in this wallet is not in the expected format. \
             The wallet database may be damaged; restore from a backup."
        )),
        Err(e) => return Err(anyhow!(
            "could not read the encrypted seed phrase from this wallet ({e}). The wallet \
             database may be damaged or truncated; restore from a backup — remember it is \
             two files, the database and the encryption identity, and you need both."
        )),
    };

    let mut mnemonic_reader = mnemonic_decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow!("Failed to decrypt mnemonic: {:?}", e))?;
    let mut decrypted_mnemonic = vec![];
    std::io::Read::read_to_end(&mut mnemonic_reader, &mut decrypted_mnemonic).unwrap();

    // F5. from_utf8 reuses the Vec's allocation, so wrapping the String wipes the only
    // copy of the decrypted phrase when it drops.
    let _spending_key = zeroize::Zeroizing::new(
        String::from_utf8(decrypted_mnemonic)
            .map_err(|e| anyhow!("decrypted seed phrase is not valid UTF-8: {e}"))?,
    );
        
    // 5. Dynamic Note Selection
    let mut proposed_inputs = Vec::new();
    let mut accumulated_value = 0;
    
    let network_fee = 50_000 * outputs.len() as u64; // rough over-estimate
    let target_value = total_amount_zat + network_fee;
    
    let accounts = wallet_db.get_account_ids().map_err(|e| anyhow!("could not read the wallet accounts: {e:?}"))?;
    let account = *accounts.first().ok_or_else(|| anyhow!("No accounts found"))?;
    
    let height = wallet_db.chain_height().map_err(|e| anyhow!("could not read the wallet chain height: {e:?}"))?.unwrap_or(zcash_protocol::consensus::BlockHeight::from_u32(0));
    // For batching, we also bypass strict confirmation minimums 
    let effective_target_height = std::cmp::max(target_height_u32, u32::from(height) + 20);
    
    let unspent = wallet_db.select_unspent_notes(account, &[ShieldedPool::Orchard, ShieldedPool::Sapling, ShieldedPool::Ironwood], TargetHeight::from(effective_target_height), &[], zcash_client_backend::data_api::wallet::input_selection::LockFilter::Unfiltered)
        .map_err(|e| anyhow!("Failed to select unspent notes: {:?}", e))?;
        
    // Orchard AND Ironwood. Iterating only `.orchard()` was a live bug after the
    // NU6.3 port: post-Ironwood funds land in the Ironwood pool, so a wallet whose
    // whole balance sits there would accumulate 0 and report "Insufficient funds"
    // while holding plenty — failing here, before native_builder.rs ever gets the
    // chance to select those notes correctly.
    //
    // Both pools carry `orchard::note::Note`, so the loop body is identical.
    let candidates = unspent
        .orchard()
        .iter()
        .map(|n| (n, "Orchard"))
        .chain(unspent.ironwood().iter().map(|n| (n, "Ironwood")));

    for (note, pool) in candidates {
        let value = note.note_value().map_err(|e| anyhow!("could not read a note value: {e:?}"))?;
        let value_u64 = u64::from(value);

        // Skip ZSA notes for generic batch spending to prevent burn
        if value_u64 == 10_000 { continue; }

        if accumulated_value < target_value {
            let mut txid_bytes = note.txid().as_ref().to_vec();
            txid_bytes.reverse();
            proposed_inputs.push(ProposedInput {
                txid: hex::encode(txid_bytes),
                pool: pool.to_string(),
                value_zat: value_u64,
                outindex: note.output_index() as u32,
                is_explicitly_selected_asset: false,
            });
            accumulated_value += value_u64;
        }
    }
    
    let final_inputs_count = proposed_inputs.len();
    let final_fee = (std::cmp::max(final_inputs_count, 2) as u64 + outputs.len() as u64) * 5_000;
    let final_target_value = total_amount_zat + final_fee;

    if accumulated_value < final_target_value {
        let stranded = unspendable_sapling_zat(&unspent);
        return Err(anyhow!(
            "Insufficient funds for batch. Found {} Zats, need {} Zats.{}",
            accumulated_value, final_target_value,
            sapling_hint(stranded, final_target_value.saturating_sub(accumulated_value))
        ));
    }
    
    validate_anti_burn(&proposed_inputs)?;

    let usk = spending_key_from_phrase(&_spending_key)?;

    let tx_hex = crate::native_builder::build_and_sign_batch_transaction(
        wallet_db,
        &usk,
        &proposed_inputs,
        outputs,
        target_height_u32,
    )?;

    Ok((tx_hex, proposed_inputs))
}

/// Prepares and sends a transaction, enforcing the Anti-Burn mechanism.
/// How much value is sitting in Sapling notes that this build cannot spend.
///
/// Selection iterates `.orchard()` and `.ironwood()` only — Sapling notes are requested from the
/// backend and then never looked at. They are scanned, and `get_balance` counts them, so a wallet
/// paid in Sapling **shows the funds and then refuses to spend them**.
///
/// Reporting that plainly turns a confusing apparent loss into a stated limitation. Without it the
/// user sees "Insufficient funds" quoting a number that contradicts their own balance, which reads
/// like the wallet lost the money.
fn unspendable_sapling_zat<NoteRef>(
    unspent: &zcash_client_backend::data_api::ReceivedNotes<NoteRef>,
) -> u64 {
    unspent
        .sapling()
        .iter()
        .filter_map(|n| n.note_value().ok())
        .map(u64::from)
        .sum()
}

/// Append an explanation when the shortfall is explained by unspendable Sapling value.
fn sapling_hint(stranded: u64, short_by: u64) -> String {
    if stranded == 0 {
        return String::new();
    }
    let covers = if stranded >= short_by { "which would cover it" } else { "which is not enough on its own" };
    format!(
        "\n\nThis wallet also holds {} zatoshi in **Sapling** notes, {}. \
         Sapling funds are received and counted in your balance but this build cannot spend them \
         yet — note selection covers Orchard and Ironwood only. Move value into Ironwood, or wait \
         for Sapling spending support.",
        stranded, covers
    )
}

pub fn send_transaction(
    address: &str,
    amount_zat: u64,
    memo: &str,
    asset_id: Option<&str>,
    target_height_u32: u32,
) -> Result<(String, Vec<ProposedInput>)> {
    // 1. Validate Amount
    let _tx_amount = ZatBalance::from_u64(amount_zat)
        .map_err(|_| anyhow!("Invalid transaction amount"))?;

    // 2. Process the Memo (512-byte padding limit)
    let mut memo_bytes = memo.as_bytes().to_vec();
    if memo_bytes.len() > 512 {
        return Err(anyhow!("Memo exceeds the maximum 512 bytes allowed by Zcash consensus."));
    }
    // Pad memo to exactly 512 bytes with nulls
    memo_bytes.resize(512, 0);
    
    // 3. Key Extraction: Read and decrypt the spending key using `age`
    let identity_path = crate::paths::as_string::identity_path()?;
    
    let encrypted_data = std::fs::read(&identity_path)
        .map_err(|e| anyhow!("could not read the encryption identity file at {}: {}", identity_path, e))?;
        
    let password_str = crate::rpc::WALLET_PASSWORD.lock().unwrap().clone()
        .ok_or_else(|| anyhow!("Wallet is locked. Password required to decrypt identity file"))?;

    let decryptor = match age::Decryptor::new(&encrypted_data[..]) {
        Ok(age::Decryptor::Passphrase(d)) => d,
        _ => return Err(anyhow!("Expected passphrase-based age encryption")),
    };

    let mut decrypted_identity = vec![];
    let mut reader = decryptor.decrypt(&age::secrecy::Secret::new(password_str.to_string()), Some(22))
        .map_err(|e| anyhow!("Decryption failed: Invalid password or corrupted file ({:?})", e))?;
    
    std::io::Read::read_to_end(&mut reader, &mut decrypted_identity)
        .map_err(|e| anyhow!("could not read the decrypted data: {e}"))?;
        
    let identity_str = String::from_utf8(decrypted_identity)
        .map_err(|e| anyhow!("decrypted data is not valid UTF-8: {e}"))?;

    let identity_key = identity_str.lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .ok_or_else(|| anyhow!("No AGE-SECRET-KEY found in decrypted identity"))?;

    let identity: age::x25519::Identity = std::str::FromStr::from_str(identity_key)
        .map_err(|e| anyhow!("Invalid identity format: {:?}", e))?;

    // 4. Initialize WalletDb
    use zcash_client_sqlite::WalletDb;
    use zcash_client_sqlite::util::SystemClock;
    use zcash_protocol::consensus::MainNetwork;
    use rand::rngs::OsRng;
    use zcash_client_backend::data_api::{WalletRead, InputSource};
    use zcash_client_backend::data_api::wallet::TargetHeight;
    use zcash_protocol::ShieldedPool;
    
    let db_path = crate::paths::as_string::wallet_db_path()?;
    let mut wallet_db = WalletDb::for_path(&db_path, MainNetwork, SystemClock, OsRng)
        .map_err(|e| anyhow!("Failed to open wallet DB: {:?}", e))?;

    zcash_client_sqlite::wallet::init::init_wallet_db(&mut wallet_db, None)
        .map_err(|e| anyhow!("Failed to init wallet DB: {:?}", e))?;

    // 4.5 Fetch and decrypt the Mnemonic
    let encrypted_mnemonic_bytes: Vec<u8> = {
        let conn = rusqlite::Connection::open(&db_path)
            .map_err(|e| anyhow!("Failed to open DB for mnemonic: {:?}", e))?;
        let mut stmt = conn.prepare("SELECT encrypted_mnemonic FROM ext_zecboat_keystore_mnemonics LIMIT 1")
            .map_err(|e| anyhow!("Failed to prepare mnemonic query: {:?}", e))?;
        let mut rows = stmt.query([])
            .map_err(|e| anyhow!("Failed to execute mnemonic query: {:?}", e))?;
        let row = rows.next().map_err(|e| anyhow!("DB error: {:?}", e))?
            .ok_or_else(|| anyhow!("No encrypted mnemonic found in database"))?;
        row.get(0).map_err(|e| anyhow!("Failed to read blob: {:?}", e))?
    };

    let mnemonic_decryptor = match age::Decryptor::new(&encrypted_mnemonic_bytes[..]) {
        Ok(age::Decryptor::Recipients(d)) => d,
        // A malformed blob previously panicked the whole backend here via `.unwrap()`,
        // taking the application down with no message. The wallet database holds this
        // blob, so corruption on disk — a truncated write, a bad restore — reached the
        // user as a crash rather than an explanation.
        Ok(_) => return Err(anyhow!(
            "the encrypted seed phrase in this wallet is not in the expected format. \
             The wallet database may be damaged; restore from a backup."
        )),
        Err(e) => return Err(anyhow!(
            "could not read the encrypted seed phrase from this wallet ({e}). The wallet \
             database may be damaged or truncated; restore from a backup — remember it is \
             two files, the database and the encryption identity, and you need both."
        )),
    };

    let mut mnemonic_reader = mnemonic_decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow!("Failed to decrypt mnemonic: {:?}", e))?;
    let mut decrypted_mnemonic = vec![];
    std::io::Read::read_to_end(&mut mnemonic_reader, &mut decrypted_mnemonic).unwrap();

    // F5. from_utf8 reuses the Vec's allocation, so wrapping the String wipes the only
    // copy of the decrypted phrase when it drops.
    let _spending_key = zeroize::Zeroizing::new(
        String::from_utf8(decrypted_mnemonic)
            .map_err(|e| anyhow!("decrypted seed phrase is not valid UTF-8: {e}"))?,
    );
        
    // ── ZMAP asset transfer ────────────────────────────────────────────────────────────────────
    //
    // Placed before ordinary note selection: this branch owns the whole operation and returns.
    //
    // A ZMAP transfer is not a payment that happens to carry a memo. It spends *the asset's own
    // carrier note* and re-issues that note's memo byte for byte on a fresh Ironwood output, so the
    // old carrier is provably consumed. Every "send" in this project's history did the opposite —
    // spending an ordinary ZEC change note and writing a new memo — which is issuance wearing a
    // transfer's name, and why supply on Layer 2 has never meant anything.
    //
    // Detection and selection are `zmap`'s, which is unit-tested; nothing here re-implements them.
    // The amount and memo arguments are ignored: both are fixed by the carrier being moved, and
    // honouring a caller's version of either would let the UI change an asset's identity in flight.
    if let Some(id) = asset_id.map(str::trim).filter(|s| !s.is_empty()) {
        let usk = spending_key_from_phrase(&_spending_key)?;
        let hex = crate::native_builder::send_zmap_asset(&mut wallet_db, &usk, id, address)?;
        return Ok((hex, Vec::new()));
    }

    // 5. Dynamic Note Selection
    let mut proposed_inputs = Vec::new();
    let mut accumulated_value = 0;
    
    // Over-provision the network fee in note selection to ensure we pull enough Zats 
    // to cover any dynamically calculated ZIP-317 fee based on logical actions.
    let network_fee = 50_000;
    // Retained for readability; input selection is performed by propose_transfer in
    // native_builder.rs, not here.
    let _target_value = amount_zat + network_fee;
    
    // Get account zero
    let accounts = wallet_db.get_account_ids().map_err(|e| anyhow!("could not read the wallet accounts: {e:?}"))?;
    let account = *accounts.first().ok_or_else(|| anyhow!("No accounts found"))?;
    
    // Fetch unspent notes
    let height = wallet_db.chain_height().map_err(|e| anyhow!("could not read the wallet chain height: {e:?}"))?.unwrap_or(zcash_protocol::consensus::BlockHeight::from_u32(0));
    // Artificially increase target height by 20 to bypass strict confirmation minimums (since we know blocks are synced in background DB)
    let effective_target_height = std::cmp::max(target_height_u32, u32::from(height) + 20);
    println!("DEBUG: wallet_db.chain_height() = {:?}, provider_target_height = {}, effective_target_height = {}", height, target_height_u32, effective_target_height);
    let unspent = wallet_db.select_unspent_notes(account, &[ShieldedPool::Orchard, ShieldedPool::Sapling, ShieldedPool::Ironwood], TargetHeight::from(effective_target_height), &[], zcash_client_backend::data_api::wallet::input_selection::LockFilter::Unfiltered)
        .map_err(|e| anyhow!("Failed to select unspent notes: {:?}", e))?;
        
    // Orchard AND Ironwood — see the note on the batch path above. Post-NU6.3
    // funds live in Ironwood, and iterating only `.orchard()` made them
    // invisible to this selection, producing a false "Insufficient funds".
    let candidates = unspent
        .orchard()
        .iter()
        .map(|n| (n, "Orchard"))
        .chain(unspent.ironwood().iter().map(|n| (n, "Ironwood")));

    for (note, pool) in candidates {
        let value = note.note_value().map_err(|e| anyhow!("could not read a note value: {e:?}"))?;
        let value_u64 = u64::from(value);
        
        // Never spend a carrier here. Asset transfers take the ZMAP branch at the top of this
        // function, which selects the specific carrier through `zmap`; this path only ever moves
        // ordinary value, so a 10,000-zat note reaching it would be a burn.
        //
        // Removed 2026-08-17 (P1-11): a pre-Ironwood block used to try selecting an asset here by
        // hand-scanning memos. It read `orchard_received_notes` **only**, so an Ironwood carrier was
        // invisible to it, and it aborted with "No 10,000 Zatoshi Cyber-Nomad asset notes found to
        // transfer." — naming a collection the user does not hold, for a reason that was not the
        // real one. It also carried its own fee arithmetic, which could disagree with the builder.
        if value_u64 == 10_000 {
            continue;
        }

        // Standard ZEC note collection for fees or value transfer
        let current_inputs_count = proposed_inputs.len() + 1;
        let dynamic_fee = (std::cmp::max(current_inputs_count, 2) as u64) * 5_000;
        let target_value = amount_zat + dynamic_fee;

        if accumulated_value < target_value {
            let mut txid_bytes = note.txid().as_ref().to_vec();
            txid_bytes.reverse();
            proposed_inputs.push(ProposedInput {
                txid: hex::encode(txid_bytes),
                pool: pool.to_string(),
                value_zat: value_u64,
                outindex: note.output_index() as u32,
                is_explicitly_selected_asset: false,
            });
            accumulated_value += value_u64;
        }
    }
    
    let final_inputs_count = proposed_inputs.len();
    let final_fee = (std::cmp::max(final_inputs_count, 2) as u64) * 5_000;
    let final_target_value = amount_zat + final_fee;

    if accumulated_value < final_target_value {
        let stranded = unspendable_sapling_zat(&unspent);
        return Err(anyhow!(
            "Insufficient funds. Found {} Zats, need {} Zats (including dynamic ZIP-317 fee of {}).{}",
            accumulated_value, final_target_value, final_fee,
            sapling_hint(stranded, final_target_value.saturating_sub(accumulated_value))
        ));
    }
    
    // 6. Mandatory Pre-flight Safety Check
    validate_anti_burn(&proposed_inputs)?;

    // 7. Execute builder
    // Convert string seed to usk
    let usk = spending_key_from_phrase(&_spending_key)?;

    let tx_hex = crate::native_builder::build_and_sign_transaction(
        wallet_db,
        &usk,
        &proposed_inputs,
        address,
        amount_zat,
        &memo_bytes,
        effective_target_height
    )?;

    Ok((tx_hex, proposed_inputs))
}