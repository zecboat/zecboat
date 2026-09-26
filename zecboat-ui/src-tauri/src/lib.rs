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
async fn send_transaction(address: String, amount: f64, memo: String, asset_id: Option<String>, acknowledge_unproven: Option<bool>) -> Result<String, String> {
    zecboat_core::send_transaction_with_wake(&address, amount, &memo, asset_id.as_deref(), acknowledge_unproven.unwrap_or(false))
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
// Fetch any lading the drop-box holds for a carrier whose memo commits to one.
async fn fetch_consignments() -> Result<serde_json::Value, String> {
    let r = zecboat_core::fetch_consignments().await.map_err(|e| e.to_string())?;
    serde_json::to_value(r).map_err(|e| e.to_string())
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
async fn get_zsas() -> Result<Vec<serde_json::Value>, String> {
    zecboat_core::get_zsas().await.map_err(|e| e.to_string())
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
async fn list_backups() -> Result<Vec<String>, String> {
    zecboat_core::list_backups().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn restore_backup(backup_name: String) -> Result<String, String> {
    zecboat_core::restore_backup(backup_name).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn export_keys() -> Result<String, String> {
    zecboat_core::export_keys().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_viewkey() -> Result<String, String> {
    zecboat_core::get_viewkey().await.map_err(|e| e.to_string())
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|_app| {
            tauri::async_runtime::spawn(async move {
                zecboat_core::local_rpc::start_server().await;
            });
            Ok(())
        })
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            sync_status, set_provider_url, get_provider_url, get_balance, get_balance_breakdown, get_transparent_balance, send_transaction, get_addresses,
            check_pending_broadcasts, resend_pending_broadcasts, release_expired_transactions, 
            registry_base, check_initialization_status, initialize_new_wallet, generate_new_address, import_wallet, recover_wallet_from_seed, get_transactions, get_transparent_address, get_invoices, add_invoice, get_zsas, view_asset, verify_asset_image, verify_issuance, verify_lineage, fetch_consignments, fee_readiness, wallet_about,
            sign_transaction_with_hardware, shield_transparent, unlock_wallet, wallet_uses_yubikey, lock_wallet,
            create_new_account, backup_wallet, list_backups, restore_backup, export_keys, get_viewkey, check_yubikey,
            get_roster, add_roster_contact, delete_roster_contact, validate_address
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
