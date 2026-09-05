use anyhow::Result;
use sha2::{Digest, Sha256};

pub fn is_yubikey_connected() -> bool {
    // Mock: We pretend a YubiKey is connected for the UI test
    true
}

/// Uses the YubiKey's HMAC-SHA1 Challenge-Response.
/// (Mock implementation for server-side testing)
pub fn get_yubikey_derived_key(password: &str) -> Result<String> {
    // In a real environment with ykman or a lower-level HID crate,
    // we would send `challenge` to the physical key over USB/NFC.
    // For this sandbox, we simulate the hardware HMAC response.
    
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(b"Simulated_Hardware_HMAC_Secret");
    let response = hasher.finalize();

    // The response is combined with the original password to form the final encryption key
    let final_key = format!("{}-{}", password, hex::encode(response));
    Ok(final_key)
}
