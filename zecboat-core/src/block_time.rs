//! Block spacing, and the wallet's block counts that are really time (NU7, ZIP 218).
//!
//! NU7 cuts the block target spacing from 75 to 25 seconds. A count written in blocks then
//! means a third of the time it did: a 40-block send expiry becomes 17 minutes, a 10,000-block
//! audit re-check cadence becomes three days. Every such count in this crate is stated here in
//! **seconds** and converted at the height it is used, so it means the same thing on both sides
//! of the activation block. The activation height comes from `zcash_protocol`; while it is
//! unset for mainnet (before the final NU7 crates), every height counts as pre-NU7.

use zcash_protocol::consensus::{BlockHeight, MainNetwork, NetworkUpgrade, Parameters};

/// Block target spacing before NU7.
pub const PRE_NU7_SPACING_SECS: u32 = 75;
/// Block target spacing from NU7 (ZIP 218).
pub const NU7_SPACING_SECS: u32 = 25;

/// A send expires 50 minutes after its target height: 40 blocks today, 120 after NU7. The
/// library default is a fixed 40 blocks, which after NU7 is short enough for a wallet a few
/// blocks behind the tip to expire its own transaction.
pub const SEND_EXPIRY_SECS: u32 = 40 * PRE_NU7_SPACING_SECS;
/// An asset carrier stays locked against value-driven selection for about 35 days.
pub const CARRIER_LOCK_SECS: u32 = 40_000 * PRE_NU7_SPACING_SECS;
/// A passed collection audit is due for a re-check after about 8.7 days.
pub const AUDIT_STALE_SECS: u32 = 10_000 * PRE_NU7_SPACING_SECS;

/// Mainnet block spacing in force at `height`.
pub fn spacing_at(height: BlockHeight) -> u32 {
    match MainNetwork.activation_height(NetworkUpgrade::Nu7) {
        Some(nu7) if height >= nu7 => NU7_SPACING_SECS,
        _ => PRE_NU7_SPACING_SECS,
    }
}

/// How many blocks `seconds` is at the given spacing, rounded up.
pub fn blocks_for_spacing(seconds: u32, spacing_secs: u32) -> u32 {
    seconds.div_ceil(spacing_secs.max(1))
}

/// How many blocks `seconds` is at `height`.
pub fn blocks_for(seconds: u32, height: BlockHeight) -> u32 {
    blocks_for_spacing(seconds, spacing_at(height))
}

pub fn send_expiry(target: BlockHeight) -> BlockHeight {
    target + blocks_for(SEND_EXPIRY_SECS, target)
}

pub fn carrier_lock_blocks(at: BlockHeight) -> u32 {
    blocks_for(CARRIER_LOCK_SECS, at)
}

pub fn audit_stale_blocks(at: BlockHeight) -> u32 {
    blocks_for(AUDIT_STALE_SECS, at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seconds_are_three_times_the_blocks_after_nu7() {
        assert_eq!(blocks_for_spacing(SEND_EXPIRY_SECS, PRE_NU7_SPACING_SECS), 40);
        assert_eq!(blocks_for_spacing(SEND_EXPIRY_SECS, NU7_SPACING_SECS), 120);
        assert_eq!(blocks_for_spacing(CARRIER_LOCK_SECS, PRE_NU7_SPACING_SECS), 40_000);
        assert_eq!(blocks_for_spacing(CARRIER_LOCK_SECS, NU7_SPACING_SECS), 120_000);
        assert_eq!(blocks_for_spacing(AUDIT_STALE_SECS, PRE_NU7_SPACING_SECS), 10_000);
        assert_eq!(blocks_for_spacing(AUDIT_STALE_SECS, NU7_SPACING_SECS), 30_000);
    }

    /// The final 0.11 protocol crate carries the mainnet height Zebra 7.0.0 published
    /// (3,543,405); the `-pre.0` line did not, and left `spacing_at` on 75 s for ever.
    #[test]
    fn nu7_mainnet_height_is_the_published_one() {
        use zcash_protocol::consensus::BranchId;
        let nu7 = BlockHeight::from_u32(3_543_405);
        assert_eq!(MainNetwork.activation_height(NetworkUpgrade::Nu7), Some(nu7));
        assert_eq!(BranchId::for_height(&MainNetwork, nu7), BranchId::Nu7);
        assert_ne!(BranchId::for_height(&MainNetwork, nu7 - 1), BranchId::Nu7);
        assert_eq!(spacing_at(nu7 - 1), PRE_NU7_SPACING_SECS);
        assert_eq!(spacing_at(nu7), NU7_SPACING_SECS);
    }

    #[test]
    fn today_is_pre_nu7_until_the_crates_carry_a_mainnet_height() {
        let h = BlockHeight::from_u32(3_504_000);
        match MainNetwork.activation_height(NetworkUpgrade::Nu7) {
            None => assert_eq!(spacing_at(h), PRE_NU7_SPACING_SECS),
            Some(nu7) => {
                assert_eq!(spacing_at(nu7 - 1), PRE_NU7_SPACING_SECS);
                assert_eq!(spacing_at(nu7), NU7_SPACING_SECS);
            }
        }
    }
}
