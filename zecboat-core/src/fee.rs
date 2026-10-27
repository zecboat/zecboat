//! ZIP 317 fees, with the one change draft ZIP 2009 makes: the marginal fee per logical
//! action falls from 5,000 to 1,000 zatoshis at mainnet height 3,590,000 (expected
//! mid-December 2026). Built 2026-10-27 for 0.7.3.
//!
//! The rule is a wallet convention, not consensus ("wallet convention, no network upgrade",
//! as ZIP 313 was): nodes ship the relay policy first (Zebra 7.0.0's `getstandardfee` already
//! answers 5,000 below the height and 1,000 from it), wallets adopt the lower fee at the
//! height. The zcash crates this build uses (`zcash_primitives` 0.31) carry only the 5,000
//! standard rule, so the height-aware rule lives here: one constant, one function that picks
//! the rule for a target height, and the arithmetic the screen's estimates use. When the
//! crates learn the height themselves this module shrinks to the constant.
//!
//! Every fee the wallet quotes or pays goes through this module: the change strategies of the
//! three builders, the carrier-transfer headroom, the Send screen's readiness line and the
//! lineage estimate. One place, one height, one answer.

use zcash_primitives::transaction::fees::zip317 as prim;
use zcash_protocol::value::Zatoshis;

/// Mainnet height at which the marginal fee becomes 1,000 zatoshis (draft ZIP 2009).
pub const ZIP2009_HEIGHT: u32 = 3_590_000;
/// ZIP 317 as of NU7: 5,000 zatoshis per logical action.
pub const MARGINAL_FEE_BEFORE_ZAT: u64 = 5_000;
/// Draft ZIP 2009: 1,000 zatoshis per logical action from [`ZIP2009_HEIGHT`].
pub const MARGINAL_FEE_FROM_ZAT: u64 = 1_000;
/// Unchanged by ZIP 2009: a transaction pays for at least this many actions.
pub const GRACE_ACTIONS: u64 = prim::GRACE_ACTIONS as u64;

/// The marginal fee that applies to a transaction targeted at `height`.
pub fn marginal_fee_zat(height: u32) -> u64 {
    if height >= ZIP2009_HEIGHT {
        MARGINAL_FEE_FROM_ZAT
    } else {
        MARGINAL_FEE_BEFORE_ZAT
    }
}

/// The conventional fee for `logical_actions` actions at `height`:
/// `marginal_fee × max(grace_actions, logical_actions)`. Shielded-only transactions, which is
/// every transaction this wallet builds, have no transparent size terms.
pub fn conventional_fee_zat(height: u32, logical_actions: u64) -> u64 {
    marginal_fee_zat(height) * logical_actions.max(GRACE_ACTIONS)
}

/// The fee rule the builders hand to the library's change strategies and proposals for a
/// transaction targeted at `height`. Below the height this is exactly the library's standard
/// rule; from it, the same rule with the marginal fee replaced and nothing else touched.
pub fn fee_rule(height: u32) -> prim::FeeRule {
    if height >= ZIP2009_HEIGHT {
        prim::FeeRule::non_standard(
            Zatoshis::const_from_u64(MARGINAL_FEE_FROM_ZAT),
            prim::GRACE_ACTIONS,
            prim::P2PKH_STANDARD_INPUT_SIZE,
            prim::P2PKH_STANDARD_OUTPUT_SIZE,
        )
        .expect("the standard P2PKH sizes are non-zero")
    } else {
        prim::FeeRule::standard()
    }
}

/// The height the wallet's estimates use before a transaction has a target: the highest block
/// this wallet has scanned, or 0 when it has none, which picks the higher fee and so errs
/// toward "you need a little more", never toward a surprise at send time.
pub fn scanned_height(conn: &rusqlite::Connection) -> u32 {
    conn.query_row("SELECT COALESCE(MAX(height), 0) FROM blocks", [], |r| r.get::<_, i64>(0))
        .ok()
        .and_then(|h| u32::try_from(h).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marginal_fee_changes_at_the_height_and_nowhere_else() {
        assert_eq!(marginal_fee_zat(0), 5_000);
        assert_eq!(marginal_fee_zat(3_543_405), 5_000, "NU7 activation does not change the fee");
        assert_eq!(marginal_fee_zat(ZIP2009_HEIGHT - 1), 5_000);
        assert_eq!(marginal_fee_zat(ZIP2009_HEIGHT), 1_000);
        assert_eq!(marginal_fee_zat(u32::MAX), 1_000);
    }

    #[test]
    fn conventional_fees_before_and_after() {
        // The minimum: two grace actions.
        assert_eq!(conventional_fee_zat(ZIP2009_HEIGHT - 1, 1), 10_000);
        assert_eq!(conventional_fee_zat(ZIP2009_HEIGHT, 1), 2_000);
        assert_eq!(conventional_fee_zat(ZIP2009_HEIGHT, 2), 2_000);
        // A carrier transfer with change: four actions.
        assert_eq!(conventional_fee_zat(ZIP2009_HEIGHT - 1, 4), 20_000);
        assert_eq!(conventional_fee_zat(ZIP2009_HEIGHT, 4), 4_000);
        // A Knotline send: fourteen actions.
        assert_eq!(conventional_fee_zat(ZIP2009_HEIGHT - 1, 14), 70_000);
        assert_eq!(conventional_fee_zat(ZIP2009_HEIGHT, 14), 14_000);
    }

    #[test]
    fn the_builders_rule_matches_the_arithmetic_and_the_library() {
        let before = fee_rule(ZIP2009_HEIGHT - 1);
        let standard = prim::FeeRule::standard();
        assert_eq!(u64::from(before.marginal_fee()), u64::from(standard.marginal_fee()));
        assert_eq!(before.grace_actions(), standard.grace_actions());
        assert_eq!(u64::from(before.marginal_fee()), MARGINAL_FEE_BEFORE_ZAT);

        let after = fee_rule(ZIP2009_HEIGHT);
        assert_eq!(u64::from(after.marginal_fee()), MARGINAL_FEE_FROM_ZAT);
        assert_eq!(after.grace_actions(), standard.grace_actions(), "ZIP 2009 leaves grace actions alone");
        assert_eq!(after.p2pkh_standard_input_size(), standard.p2pkh_standard_input_size());
        assert_eq!(after.p2pkh_standard_output_size(), standard.p2pkh_standard_output_size());
        assert_eq!(GRACE_ACTIONS, 2);
    }

    #[test]
    fn the_scanned_height_is_the_highest_block_or_zero() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        assert_eq!(scanned_height(&conn), 0, "no blocks table at all: the higher fee");
        conn.execute_batch("CREATE TABLE blocks (height INTEGER)").unwrap();
        assert_eq!(scanned_height(&conn), 0);
        conn.execute_batch("INSERT INTO blocks VALUES (3589999), (3590000)").unwrap();
        assert_eq!(scanned_height(&conn), ZIP2009_HEIGHT);
        assert_eq!(conventional_fee_zat(scanned_height(&conn), 4), 4_000);
    }
}
