//! Verify one stored lading of a wallet COPY against a server with a chosen minimum anchor depth,
//! to tell "a proof is wrong" apart from "the newest anchor is not 100 blocks deep yet".
//!   verify_at_depth <wallet-copy.db> <server-url> <lading sha256 prefix> <min depth>
use anyhow::{anyhow, Context, Result};
use orchard::note::Rho;
use zcash_protocol::consensus::Network;
use zmap_wake::oracle::MIN_DEPTH;
use zmap_wake::oracle_lightwalletd::LightwalletdOracle;
use zmap_wake::verify_chain;
use zmap_wake::wallet_path::open_wallet_copy_sql;

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() != 5 {
        return Err(anyhow!("usage: verify_at_depth <wallet-copy.db> <server-url> <sha256 prefix> <min depth>"));
    }
    let conn = open_wallet_copy_sql(&a[1])?;
    let oracle = LightwalletdOracle::new(a[2].clone(), Network::MainNetwork)?;
    let (json, sha, rho): (Vec<u8>, Vec<u8>, Vec<u8>) = conn.query_row(
        "SELECT c.json, c.sha256, n.rho FROM ext_zecboat_zmap_consignments c JOIN ironwood_received_notes n ON n.id = c.received_note_id \
         WHERE lower(hex(c.sha256)) LIKE ?1 || '%'",
        [a[3].to_lowercase()],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let expected: [u8; 32] = sha.as_slice().try_into()?;
    let rho: Rho = Option::from(Rho::from_bytes(&<[u8; 32]>::try_from(rho.as_slice())?)).context("rho")?;
    let depth: u32 = a[4].parse()?;
    println!("server {} tip {}", a[2], oracle.tip_height()?);
    for d in [MIN_DEPTH, depth] {
        match verify_chain(&json, Some(expected), &rho, &oracle, d) {
            Ok(v) => println!("minimum depth {d:>3}: all checks pass, {} proofs, shallowest anchor {} blocks deep, trust {:?}", v.hops, v.min_anchor_depth, v.trust),
            Err(e) => println!("minimum depth {d:>3}: {e:?}"),
        }
    }
    Ok(())
}
