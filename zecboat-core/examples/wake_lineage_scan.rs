//! Chapter 2 / M1b evidence: list every lineage note (ZMAP v0.5 §5.4) in a wallet COPY.
//!   cargo run --example wake_lineage_scan -- <copy.db>
fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).ok_or_else(|| anyhow::anyhow!("usage: wake_lineage_scan <wallet copy>"))?;
    if path.contains(".AppVault") {
        anyhow::bail!("refusing a live wallet path; copy it first");
    }
    let conn = rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let rows = zecboat_core::zmap::read_lineage_rows(&conn)?;
    println!("{}: {} lineage note(s)", path, rows.len());
    for r in &rows {
        println!(
            "  {} tx {}… action {} asset {}… carrier={} spent={}",
            r.pool_name, &r.txid[..12], r.output_index, &r.asset_id[..12], r.is_carrier, r.spent
        );
    }
    let locks = zecboat_core::zmap::lineage_locks(&rows);
    println!("  -> {} note(s) would be lineage-locked", locks.iter().map(|(_, v)| v.len()).sum::<usize>());
    Ok(())
}
