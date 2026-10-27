// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

#[tauri::command]
fn registry_base() -> String {
    zecboat_core::registry_base()
}

#[tauri::command]
async fn sync_status() -> Result<String, String> {
    zecboat_core::sync_status().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_balance() -> Result<f64, String> {
    zecboat_core::get_balance().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_balance_breakdown() -> Result<zecboat_core::BalanceBreakdown, String> {
    zecboat_core::get_balance_breakdown().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_transparent_balance() -> Result<f64, String> {
    zecboat_core::get_transparent_balance().await.map_err(|e| e.to_string())
}

#[tauri::command]
// `acknowledge_unproven` (Wake, chapter 8): an asset send whose unit has no lineage proof is
// refused with a `WAKE_UNPROVEN:` error unless the user has acknowledged that the recipient
// receives it unproven. Absent means not acknowledged.
// `max_fee_zat`: the fee the screen showed. A send whose real fee is higher comes back as a
// `FEE_CHANGED:<fee>:` error for the screen to show and ask again (review 2026-10-09).
// `abandon_lineage`: the user chose, under its own warning, to send a unit whose memo commits
// to a lineage this wallet never collected (`WAKE_UNCOLLECTED:` error otherwise).
// `abandon_lineage` is the HASH the user chose to abandon, bound to that record (final gate,
// Issue A), never a bare yes.
async fn send_transaction(address: String, amount: f64, memo: String, asset_id: Option<String>, acknowledge_unproven: Option<bool>, max_fee_zat: Option<u64>, abandon_lineage: Option<String>, carrier: Option<String>) -> Result<String, String> {
    zecboat_core::send_transaction_with_wake(&address, amount, &memo, asset_id.as_deref(), acknowledge_unproven.unwrap_or(false), max_fee_zat, abandon_lineage.as_deref(), carrier.as_deref())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
// Wake lineage badge (ZMAP v0.5 §9 check 7): the lading held for this asset, verified against
// the node named by ZECBOAT_ZEBRAD_RPC. Four states; see zecboat_core::WakeState.
async fn verify_lineage(asset_id: String) -> Result<serde_json::Value, String> {
    let state = zecboat_core::verify_lineage(asset_id).await.map_err(|e| e.to_string())?;
    serde_json::to_value(state).map_err(|e| e.to_string())
}

#[tauri::command]
// Collect any lading a held carrier's memo commits to that this wallet does not hold.
async fn fetch_consignments() -> Result<serde_json::Value, String> {
    let r = zecboat_core::fetch_consignments().await.map_err(|e| e.to_string())?;
    serde_json::to_value(r).map_err(|e| e.to_string())
}

// ── lineage records (0.7.1) ──────────────────────────────────────────────────────────────
// A sent record travels in the transfer; one that does not is saved as a sealed file and can be
// saved again here, and a file received by any channel can be opened.

#[tauri::command]
// Every lading this wallet made for a send, with whether it travelled in the transfer.
async fn lineage_outgoing() -> Result<serde_json::Value, String> {
    let r = zecboat_core::lineage_outgoing().await.map_err(|e| e.to_string())?;
    serde_json::to_value(r).map_err(|e| e.to_string())
}

#[tauri::command]
// Write a sent lading, sealed to its recipient, into Downloads; returns the file's path.
async fn lineage_export(consignment_hash: String) -> Result<String, String> {
    zecboat_core::lineage_export(consignment_hash).await.map_err(|e| e.to_string())
}

#[tauri::command]
// Take a lineage file handed over by a sender. `sealed` is the file's text.
async fn lineage_import(sealed: String) -> Result<serde_json::Value, String> {
    let r = zecboat_core::lineage_import(sealed.into_bytes()).await.map_err(|e| e.to_string())?;
    serde_json::to_value(r).map_err(|e| e.to_string())
}

#[tauri::command]
// What sending this item now would carry and cost: the real fee for the confirmation screen.
/// The user asks for one asset's lineage to be collected now, whatever its collection.
async fn collect_lineage(asset_id: String) -> Result<serde_json::Value, String> {
    let db = zecboat_core::paths::as_string::wallet_db_path().map_err(|e| e.to_string())?;
    let r = tauri::async_runtime::spawn_blocking(move || zecboat_core::wake::collect_lineage(&db, &asset_id))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    serde_json::to_value(r).map_err(|e| e.to_string())
}

#[tauri::command]
/// Every copy of an asset this wallet holds, each with its own lineage state (review 2026-10-09).
async fn asset_carrier_states(asset_id: String) -> Result<serde_json::Value, String> {
    let genesis = zecboat_core::wake::genesis_outpoint(&asset_id).await;
    let db = zecboat_core::paths::as_string::wallet_db_path().map_err(|e| e.to_string())?;
    let states = tauri::async_runtime::spawn_blocking(move || zecboat_core::wake::holding_carrier_states(&db, &asset_id, genesis.as_ref()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    serde_json::to_value(states).map_err(|e| e.to_string())
}

#[tauri::command]
async fn asset_send_estimate(asset_id: String, carrier: Option<String>) -> Result<serde_json::Value, String> {
    let r = zecboat_core::asset_send_estimate(asset_id, carrier).await.map_err(|e| e.to_string())?;
    serde_json::to_value(r).map_err(|e| e.to_string())
}

#[tauri::command]
// How lineage travels with a sent item: `route` is `knotline`, `whole` or `off`; `source` says
// who decided it (`settings`, `default`, or `environment` for a test override).
async fn get_lineage_route() -> Result<serde_json::Value, String> {
    let (route, source) = zecboat_core::lineage_route();
    Ok(serde_json::json!({ "route": route, "source": source }))
}

#[tauri::command]
async fn set_lineage_route(route: String) -> Result<(), String> {
    zecboat_core::set_send_mode_choice(&route).map_err(|e| e.to_string())
}

// Who answers questions about the chain for lineage and issuance checks: `auto`, `node` or
// `provider`; `source` is `settings` or `default`. A node user who chooses `node` is never
// switched to the provider without a word (audit 2026-10-08).
#[tauri::command]
async fn get_chain_source() -> Result<serde_json::Value, String> {
    let (choice, source) = zecboat_core::chain_choice_with_source();
    Ok(serde_json::json!({ "choice": choice, "source": source }))
}

#[tauri::command]
async fn set_chain_source(choice: String) -> Result<(), String> {
    zecboat_core::set_chain_choice(&choice).map_err(|e| e.to_string())
}

/// Transactions the wallet built and signed but never saw confirmed.
///
/// Call this on startup. A lost broadcast response leaves a fully signed
/// transaction in the database with its inputs already spent; until something
/// looks for it, the funds appear destroyed. Returns an empty list in the normal
/// case, so the UI can show nothing at all.
#[tauri::command]
async fn check_pending_broadcasts() -> Result<Vec<zecboat_core::PendingBroadcast>, String> {
    zecboat_core::check_pending_broadcasts().await.map_err(|e| e.to_string())
}

/// Confirms with a node that each expired transaction really is absent from the chain,
/// then releases its inputs. Without this, a transaction that expired unmined left its
/// notes marked spent locally and the only recovery was a full rescan.
#[tauri::command]
async fn release_expired_transactions() -> Result<String, String> {
    zecboat_core::release_expired_transactions().await.map_err(|e| e.to_string())
}

/// Rebroadcast every stored transaction that has not expired. Safe to repeat.
#[tauri::command]
async fn resend_pending_broadcasts() -> Result<String, String> {
    zecboat_core::resend_pending_broadcasts().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_addresses() -> Result<Vec<serde_json::Value>, String> {
    let res = zecboat_core::get_addresses().await;
    res.map_err(|e| e.to_string())
}

use serde_json::Value;

#[tauri::command]
async fn initialize_new_wallet(password: String, use_yubikey: bool, birthday: Option<u32>) -> Result<String, String> {
    zecboat_core::initialize_new_wallet(password, use_yubikey, birthday).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn generate_new_address() -> Result<String, String> {
    zecboat_core::generate_new_address().await.map_err(|e| e.to_string())
}

/// Rebuild this wallet from its seed phrase, with a NEW password.
///
/// Unlike `import_wallet`, this needs nothing unlocked — it is the path back in
/// when the password is lost. Returns the birthday height it will scan from.
#[tauri::command]
async fn recover_wallet_from_seed(
    seed: String,
    password: String,
    birthday: Option<u32>,
) -> Result<u32, String> {
    zecboat_core::recover_wallet_from_seed(&seed, password, birthday)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn import_wallet(seed: String, birthday: Option<u32>) -> Result<(), String> {
    zecboat_core::import_wallet(&seed, birthday).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_transactions() -> Result<Vec<Value>, String> {
    zecboat_core::get_transactions().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_invoices() -> Result<Vec<Value>, String> {
    zecboat_core::get_invoices().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_invoice(invoice_id: String, date: String, items: String, total_zec: f64, total_fiat_value: f64, txid: String) -> Result<(), String> {
    zecboat_core::add_invoice(invoice_id, date, items, total_zec, total_fiat_value, txid).await.map_err(|e| e.to_string())
}

/// The wallet's bare `t1…` address, for senders that cannot parse a unified address.
/// Publicly visible on chain — a funding on-ramp, not a place to hold value.
#[tauri::command]
async fn get_transparent_address() -> Result<Vec<serde_json::Value>, String> {
    zecboat_core::get_transparent_address().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_znfts() -> Result<Vec<serde_json::Value>, String> {
    zecboat_core::get_znfts().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn view_asset(asset_id: String) -> Result<String, String> {
    zecboat_core::view_asset(asset_id).await.map_err(|e| e.to_string())
}

/// Fetch an asset's artwork and check it against the hash its memo commits to.
///
/// Returns the verified bytes as a `data:` URI so the UI renders exactly what was checked.
/// `image` is null when verification fails — there is deliberately no way to obtain
/// unverified artwork through this command.
#[tauri::command]
// What the wallet can honestly say about itself: which build is running, which keys it trusts,
// where its data lives, and what it does NOT do.
async fn wallet_about() -> Result<serde_json::Value, String> {
    zecboat_core::wallet_about().await.map_err(|e| e.to_string())
}

/// The signed release note, if it names a newer version; `None` (silence) otherwise. Any
/// error is also silence in the UI: the wallet never depends on the site (update.rs).
#[tauri::command]
async fn check_update() -> Result<Option<zecboat_core::update::UpdateInfo>, String> {
    zecboat_core::update::check_update().await.map_err(|e| e.to_string())
}

/// Download, verify against the signed note, and hand to the system installer under the
/// user's own authentication. The version is re-read from the note, not trusted from the UI.
#[tauri::command]
async fn install_update(version: String) -> Result<String, String> {
    zecboat_core::update::install_update(&version).await.map_err(|e| e.to_string())
}

#[tauri::command]
// Asked BEFORE a send, so the constraint can be explained rather than hit. A carrier is
// exactly CARRIER_ZAT and cannot pay its own fee -- a wallet holding only carriers cannot
// send them, and the raw backend error for that is unreadable.
async fn fee_readiness() -> Result<serde_json::Value, String> {
    zecboat_core::fee_readiness().await.map_err(|e| e.to_string())
}

#[tauri::command]
// Issuance verification -- ZMAP-v0.3 §9 checks 1, 3, 4 and 5, against a PINNED issuer key.
// Distinct from verify_asset_image, which is check 6 alone. §12.1 forbids presenting 1-4 and 6
// as "genuine" without 5, so the two are separate commands returning separate states.
async fn verify_issuance(asset_id: String) -> Result<serde_json::Value, String> {
    let state = zecboat_core::verify_issuance(asset_id)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(state).map_err(|e| e.to_string())
}

#[tauri::command]
async fn verify_asset_image(asset_id: String) -> Result<serde_json::Value, String> {
    zecboat_core::verify_asset_image(asset_id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn shield_transparent() -> Result<String, String> {
    zecboat_core::shield_transparent().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn sign_transaction_with_hardware(tx_data: String) -> Result<String, String> {
    zecboat_core::sign_transaction_with_hardware(&tx_data).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn unlock_wallet(password: String, use_yubikey: bool) -> Result<String, String> {
    zecboat_core::unlock_wallet(password, use_yubikey).await.map(|_| "Unlocked".to_string()).map_err(|e| e.to_string())
}

#[tauri::command]
fn check_yubikey() -> bool {
    zecboat_core::check_yubikey()
}

/// The plugin's current status line during a YubiKey decrypt ("touch the key"), else null.
#[tauri::command]
fn yubikey_message() -> Option<String> {
    zecboat_core::yubikey_message()
}

#[tauri::command]
fn lock_wallet() {
    zecboat_core::lock_wallet();
}

#[tauri::command]
async fn create_new_account() -> Result<String, String> {
    zecboat_core::create_new_account().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn backup_wallet() -> Result<String, String> {
    zecboat_core::backup_wallet().await.map_err(|e| e.to_string())
}

#[tauri::command]
// B8 (v0.7.0): rescan from a height the user chooses. Rewinds through the backend's own
// truncation and lets the sync engine scan forward; see zecboat_core::rescan_from_height.
async fn rescan_from_height(height: u32) -> Result<String, String> {
    zecboat_core::rescan_from_height(height).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_backups() -> Result<Vec<String>, String> {
    zecboat_core::list_backups().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn restore_backup(backup_name: String) -> Result<String, String> {
    zecboat_core::restore_backup(backup_name).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn export_keys(passphrase: String) -> Result<String, String> {
    zecboat_core::export_keys(passphrase).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_viewkey(passphrase: String) -> Result<String, String> {
    zecboat_core::get_viewkey(passphrase).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_initialization_status() -> Result<bool, String> {
    zecboat_core::check_initialization_status().map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_roster() -> Result<Vec<Value>, String> {
    zecboat_core::get_roster().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn add_roster_contact(name: String, address: String, notes: String) -> Result<String, String> {
    zecboat_core::add_roster_contact(name, address, notes).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn delete_roster_contact(id: i64) -> Result<String, String> {
    zecboat_core::delete_roster_contact(id).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn validate_address(address: String) -> Result<Value, String> {
    zecboat_core::validate_address(address).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_provider_url(url: String) -> Result<(), String> {
    zecboat_core::set_provider_url(url).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_provider_url() -> Result<String, String> {
    zecboat_core::get_provider_url().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn wallet_uses_yubikey() -> Result<bool, String> {
    zecboat_core::wallet_uses_yubikey().await.map_err(|e| e.to_string())
}

/// A3b: the Zecboat Registry as last scanned. Reads registry.db only; no network.
#[tauri::command]
fn get_collections() -> Result<zecboat_core::collections::RegistryView, String> {
    zecboat_core::collections::registry_view().map_err(|e| e.to_string())
}

/// A3b phase 2: audit one registered collection with the wallet's own implementation.
#[tauri::command]
async fn audit_collection(ik: String, registration_txid: String) -> Result<zecboat_core::collection_audit::AuditReport, String> {
    zecboat_core::collection_audit::audit_registered(&ik, &registration_txid).await.map_err(|e| e.to_string())
}

/// The Checks running right now, keyed "registration_txid:ik".
#[tauri::command]
fn audits_running() -> Vec<String> {
    zecboat_core::collection_audit::audits_running()
}

/// Where a running Check has got to: `[scanned_to, from]`, or null.
#[tauri::command]
fn audit_progress(ik: String, registration_txid: String) -> Option<(u32, u32)> {
    zecboat_core::collection_audit::audit_progress(&ik, &registration_txid)
}

/// A3b phase 3: units this wallet holds, per collection key. Reads wallet.db read-only.
#[tauri::command]
fn get_collection_holdings() -> Result<std::collections::HashMap<String, zecboat_core::collections::Held>, String> {
    zecboat_core::collections::holdings_by_ik().map_err(|e| e.to_string())
}

/// A3b phase 2: every cached audit, keyed "registration_txid:ik". No network.
#[tauri::command]
fn get_collection_audits() -> Result<std::collections::HashMap<String, zecboat_core::collection_audit::AuditReport>, String> {
    zecboat_core::collection_audit::cached_audits().map(|v| v.into_iter().collect()).map_err(|e| e.to_string())
}

/// Verified artwork from the local cache, no network: `{asset_id, image}` or null.
#[tauri::command]
async fn cached_artwork(asset_id: String) -> Result<Option<serde_json::Value>, String> {
    zecboat_core::cached_artwork(asset_id).await.map_err(|e| e.to_string())
}

/// Whether a registry scan is running in the backend right now.
#[tauri::command]
fn registry_scan_running() -> bool {
    zecboat_core::collections::scan_in_progress()
}

/// A3b: bring the registry level with the chain (the wallet's node), then list it.
#[tauri::command]
async fn scan_collections() -> Result<zecboat_core::collections::RegistryView, String> {
    zecboat_core::collections::scan_registry().await.map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            sync_status, yubikey_message, set_provider_url, get_provider_url, get_balance, get_balance_breakdown, get_transparent_balance, send_transaction, get_addresses,
            check_pending_broadcasts, resend_pending_broadcasts, release_expired_transactions, 
            registry_base, get_lineage_route, set_lineage_route, get_chain_source, set_chain_source, asset_send_estimate, asset_carrier_states, collect_lineage, lineage_outgoing, lineage_export, lineage_import, check_initialization_status, initialize_new_wallet, generate_new_address, import_wallet, recover_wallet_from_seed, get_collections, scan_collections, registry_scan_running, cached_artwork, audit_progress, audits_running, audit_collection, get_collection_audits, get_collection_holdings, get_transactions, get_transparent_address, get_invoices, add_invoice, get_znfts, view_asset, verify_asset_image, verify_issuance, verify_lineage, fetch_consignments, fee_readiness, wallet_about,
            sign_transaction_with_hardware, shield_transparent, unlock_wallet, wallet_uses_yubikey, lock_wallet,
            create_new_account, backup_wallet, list_backups, restore_backup, rescan_from_height, export_keys, get_viewkey, check_yubikey,
            get_roster, add_roster_contact, delete_roster_contact, validate_address,
            check_update, install_update
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
