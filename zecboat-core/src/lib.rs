pub mod addr;
pub mod block_time;
pub mod issuance;

/// A test-only environment override (`ZECBOAT_WAKE_MANIFEST`, `ZECBOAT_PINNED_V1`). Read only
/// in builds made with `--features test-overrides` (and in this crate's own tests); any other
/// build ignores it and says so once on stderr, so a test run against a release binary fails
/// visibly instead of quietly verifying nothing (audit 2026-10-08, Zecboat O).
pub fn test_override(name: &str) -> Option<String> {
    let value = std::env::var(name).ok()?;
    if cfg!(any(test, feature = "test-overrides")) {
        return Some(value);
    }
    static WARNED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    if let Ok(mut w) = WARNED.lock() {
        if !w.iter().any(|n| n == name) {
            eprintln!("[zecboat] {name} is set but ignored: this build was made without test-overrides");
            w.push(name.to_string());
        }
    }
    None
}
pub mod issuance_v1;
pub mod paths;
pub mod db;
pub mod wallet;
pub mod rpc;
pub mod native_builder;
pub mod yubi;
pub mod zmap;
pub mod wake;
pub mod wake_memo;
pub mod collections;
pub mod collection_audit;
pub mod update;

pub use issuance::{verify_issuance, BadgeState};
pub use rpc::{cached_artwork, wallet_about, fee_readiness, registry_base, sync_status, set_provider_url, get_provider_url, wallet_uses_yubikey, get_balance, get_balance_breakdown, BalanceBreakdown, get_transparent_balance, get_transparent_address, send_transaction, get_addresses, check_initialization_status, initialize_new_wallet, generate_new_address, import_wallet, recover_wallet_from_seed, get_transactions, get_invoices, add_invoice, get_znfts, view_asset, verify_asset_image, shield_transparent, sign_transaction_with_hardware, unlock_wallet, lock_wallet, create_new_account, backup_wallet, restore_backup, list_backups, export_keys, get_viewkey, get_roster, add_roster_contact, delete_roster_contact, validate_address,
    check_pending_broadcasts, resend_pending_broadcasts, release_expired_transactions, PendingBroadcast};
pub use wake::{verify_lineage, fetch_consignments, WakeState, set_chain_choice, chain_choice_with_source, lineage_outgoing, lineage_export, lineage_import, asset_send_estimate};
pub use rpc::send_transaction_with_wake;
pub use rpc::rescan_from_height;
pub use yubi::is_yubikey_connected as check_yubikey;
pub use yubi::yubikey_message;
pub use wallet::ProposedInput;
pub use wake_memo::{lineage_route, set_send_mode_choice};
