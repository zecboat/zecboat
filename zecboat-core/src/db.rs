use deadpool_sqlite::{Config, Pool, Runtime};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct InvoiceInfo {
    pub id: String,
    pub invoice_id: String,
    pub date: String,
    pub items: String,
    pub total_zec: f64,
    pub total_fiat_value: f64,
    pub txid: String,
}

pub struct WalletPool {
    pub pool: Pool,
}

impl WalletPool {
    pub fn new(db_path: &str) -> Result<Self> {
        let cfg = Config::new(db_path);
        let pool = cfg.create_pool(Runtime::Tokio1)?;
        Ok(Self { pool })
    }
    
    /// Detect ZMAP Layer-2 assets held in this wallet.
    ///
    /// Replaces the previous `get_assets`, which had three defects this fixes:
    ///
    /// 1. **It never checked the carrier value.** Any unspent note whose memo parsed as JSON with an
    ///    `asset_id`, or began with `ZecBoat Cyber-Nomad`, was reported as an asset — so an ordinary
    ///    payment carrying such a memo counted as one. The ZMAP carrier rule is an *exact* 10,000
    ///    zatoshi and is now enforced both in `zmap::CARRIER_SQL` and in
    ///    [`crate::zmap::holdings_from_rows`].
    /// 2. **It hardcoded `amount: 1`.** Semi-fungible editions — many carriers, one identical memo —
    ///    were silently under-reported. Holdings are grouped by `asset_id` and counted.
    /// 3. **It mixed identifier schemes**, taking the image hash for legacy memos and `asset_id` for
    ///    JSON ones without normalising. See `zmap.rs` for why the image hash is canonical.
    ///
    /// Parsing lives in [`crate::zmap`] so it is unit-tested without a database.
    pub async fn get_zmap_holdings(&self) -> Result<Vec<crate::zmap::ZmapHolding>> {
        let conn = self.pool.get().await?;
        conn.interact(|conn| {
            let rows = crate::zmap::read_carrier_rows(conn)?;
            Ok(crate::zmap::holdings_from_rows(rows))
        })
        .await
        .map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))?
    }

    /// Can this wallet pay a network fee? See `zmap::fee_readiness` for why this needs asking.
    pub async fn fee_readiness(&self) -> Result<crate::zmap::FeeReadiness> {
        let conn = self.pool.get().await?;
        conn.interact(|conn| crate::zmap::fee_readiness(conn).map_err(anyhow::Error::from))
            .await
            .map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))?
    }

    pub async fn get_real_balance(&self) -> Result<f64> {
        let conn = self.pool.get().await?;
        conn.interact(|conn| {
            let mut stmt = conn.prepare(
                "SELECT SUM(v.value) 
                 FROM v_received_outputs v
                 LEFT JOIN v_received_output_spends s 
                    ON v.id_within_pool_table = s.received_output_id 
                    AND v.pool = s.pool
                 WHERE s.transaction_id IS NULL AND v.value > 10000"
            )?;
            let balance_zats: i64 = stmt.query_row([], |row| row.get(0)).unwrap_or(0);
            Ok(balance_zats as f64 / 100_000_000.0)
        }).await.map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))?
    }

    /// Transaction history, with enough detail to be searchable and explainable.
    ///
    /// # What was wrong before
    ///
    /// The previous version returned five fields — a truncated id, type, amount, a
    /// date string and the literal `"ZEC"`. Two of those were actively broken:
    ///
    /// **The txid was byte-reversed.** `hex(txid)` returns SQLite's internal order.
    /// A transaction stored as `703451a8…ea06a457` is `57a406ea…a8513470` on every
    /// block explorer. The string on screen was not a transaction id.
    ///
    /// **And it was truncated** to `8…8` before leaving the backend, so the full id
    /// never reached the UI at all. Copying it and searching could not work, and no
    /// amount of frontend work could have fixed it.
    ///
    /// Both are fixed here: `id` is the full display-order txid.
    ///
    /// # Counterparty
    ///
    /// `to_address` comes from `sent_notes`, which the wallet fills in because it
    /// built the transaction. **It is only ever available for sends.** The sender of
    /// a shielded receive is not recoverable from the chain by anyone, so the UI
    /// must say "received" rather than leave a blank that reads as a defect.
    ///
    /// Change outputs have a NULL `to_address`; they are skipped so a self-send does
    /// not appear to have gone to nobody.
    pub async fn get_transactions(&self, chain_tip: Option<u32>) -> Result<Vec<serde_json::Value>> {
        let conn = self.pool.get().await?;
        let txs = conn.interact(move |conn| {
            let mut stmt = conn.prepare(
                // No LIMIT. "Find a transaction" is unanswerable when the query
                // silently drops everything past the newest 50.
                "SELECT v.txid, v.account_balance_delta, v.block_time, v.mined_height,
                        v.expiry_height, v.fee_paid
                 FROM v_transactions v
                 WHERE v.account_balance_delta != 0
                 ORDER BY v.mined_height IS NULL DESC, v.mined_height DESC"
            )?;
            // Outputs each transaction created, for pool, memo, recipient and ZMAP
            // carrier detection. Change (NULL to_address) is skipped.
            //
            // Prepared ONCE, outside the loop. This sat inside `while let Some(row)`,
            // so a wallet with N transactions compiled the same SQL N times — and two
            // review passes reported it as already hoisted without looking. It is the
            // statement that is reusable; only the bound txid changes per iteration.
            // BOTH sides of the transaction. This read `FROM sent_notes` alone — the outputs
            // this wallet CREATED — so a received transaction matched zero rows and its memo
            // was never shown. **Zecboat could not display a memo anyone sent you**, only
            // ones you sent yourself, which is backwards: the memo that matters is the one
            // addressed to you.
            //
            // Measured on ~/user2 2026-09-23: five transactions, five received memos, two
            // with sent_notes. The wallet held five memos and could display at most two.
            //
            // The gap was half-noticed. The pool label below carried the comment "Receives
            // have no sent_notes rows, so the pool is not knowable from this side" — correct
            // about the symptom, wrong about the conclusion. It is knowable; it is in the
            // other table, and so is the memo.
            //
            // Received CHANGE is excluded: on a send, sent_notes already supplies the memo,
            // and the change note would add an empty one (0xF6) plus a misleading pool.
            let mut out_stmt = conn.prepare(
                "SELECT sn.output_pool AS pool, sn.value, sn.to_address, sn.memo
                   FROM sent_notes sn
                   JOIN transactions t ON t.id_tx = sn.transaction_id
                  WHERE t.txid = ?1
                 UNION ALL
                 SELECT 2, n.value, NULL, n.memo
                   FROM sapling_received_notes n
                   JOIN transactions t ON t.id_tx = n.transaction_id
                  WHERE t.txid = ?1 AND n.is_change = 0
                 UNION ALL
                 SELECT 3, n.value, NULL, n.memo
                   FROM orchard_received_notes n
                   JOIN transactions t ON t.id_tx = n.transaction_id
                  WHERE t.txid = ?1 AND n.is_change = 0
                 UNION ALL
                 SELECT 4, n.value, NULL, n.memo
                   FROM ironwood_received_notes n
                   JOIN transactions t ON t.id_tx = n.transaction_id
                  WHERE t.txid = ?1 AND n.is_change = 0"
            )?;

            let mut rows = stmt.query([])?;
            let mut txs = Vec::new();

            while let Some(row) = rows.next()? {
                let txid_raw: Vec<u8> = row.get(0)?;
                let delta: i64 = row.get(1)?;
                let block_time: Option<i64> = row.get(2).ok().flatten();
                let mined_height: Option<i64> = row.get(3).ok().flatten();
                let expiry_height: Option<i64> = row.get(4).ok().flatten();
                let fee_zat: Option<i64> = row.get(5).ok().flatten();

                // Display order is the reverse of storage order. This is the whole
                // reason copy-and-search never worked.
                let display_txid: String =
                    txid_raw.iter().rev().map(|b| format!("{:02x}", b)).collect();

                let mut out_rows = out_stmt.query(rusqlite::params![txid_raw])?;

                let mut pools: Vec<i64> = Vec::new();
                let mut to_address: Option<String> = None;
                let mut memo_text: Option<String> = None;
                let mut assets: Vec<serde_json::Value> = Vec::new();

                while let Some(o) = out_rows.next()? {
                    let pool: i64 = o.get(0)?;
                    let value: i64 = o.get(1)?;
                    let addr: Option<String> = o.get(2).ok().flatten();
                    let memo: Option<Vec<u8>> = o.get(3).ok().flatten();

                    if !pools.contains(&pool) { pools.push(pool); }
                    if to_address.is_none() && addr.is_some() { to_address = addr; }

                    if let Some(m) = memo.as_deref() {
                        if memo_text.is_none() {
                            memo_text = crate::zmap::memo_text(m);
                        }
                        // A ZMAP carrier is BOTH an exact 10,000 zatoshi note and a
                        // memo naming an asset. Value alone is an ordinary payment;
                        // memo alone is any note with JSON in it. Requiring both is
                        // the rule in zmap.rs and it is enforced here too.
                        if value as u64 == crate::zmap::CARRIER_ZAT {
                            if let Some(rec) = crate::zmap::parse_memo(m) {
                                assets.push(serde_json::json!({
                                    "asset_id": rec.asset_id,
                                    "name": rec.name,
                                }));
                            }
                        }
                    }
                }

                let tx_type = if delta > 0 { "receive" } else { "send" };

                // Confirmations, not just a height. "Mined at 3,446,285" tells a user
                // nothing; "15,012 confirmations" tells them it is settled.
                let confirmations = match (chain_tip, mined_height) {
                    (Some(tip), Some(h)) if tip as i64 >= h => Some(tip as i64 - h + 1),
                    _ => None,
                };

                let pool_label = if pools.is_empty() {
                    // Now genuinely unknowable rather than merely unqueried: the statement
                    // above reads received notes too, so a receive reports its real pool.
                    // Empty here means neither side produced a row — a transparent-only
                    // transaction, or one the wallet has recorded but not yet enhanced.
                    None
                } else {
                    Some(pools.iter().map(|p| crate::zmap::pool_name(*p))
                        .collect::<Vec<_>>().join(" + "))
                };

                txs.push(serde_json::json!({
                    "id": display_txid,
                    "type": tx_type,
                    "amount": (delta.abs() as f64) / 100_000_000.0,
                    "fee": fee_zat.map(|f| f as f64 / 100_000_000.0),
                    // Raw epoch seconds, so the interface can render local time.
                    // The old code returned SQLite's UTC string, which no timezone
                    // could be applied to afterwards.
                    "block_time": block_time,
                    "height": mined_height,
                    "expiry_height": expiry_height,
                    "confirmations": confirmations,
                    "pool": pool_label,
                    "to_address": to_address,
                    "memo": memo_text,
                    "assets": assets,
                    "asset": "ZEC"
                }));
            }
            Ok::<Vec<serde_json::Value>, rusqlite::Error>(txs)
        }).await.map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))??;

        Ok(txs)
    }

    pub async fn get_invoices(&self) -> Result<Vec<InvoiceInfo>> {
        let conn = self.pool.get().await?;
        let invoices = conn.interact(|conn| {
            let mut stmt = conn.prepare(
                "SELECT invoice_id, date, items, total_zec, total_fiat_value, txid 
                 FROM market_invoices 
                 ORDER BY id DESC"
            )?;
            let mut rows = stmt.query([])?;
            let mut invs = Vec::new();
            
            while let Some(row) = rows.next()? {
                let invoice_id: String = row.get(0)?;
                let date: String = row.get(1)?;
                let items: String = row.get(2)?;
                let total_zec: f64 = row.get(3)?;
                let total_fiat_value: f64 = row.get(4)?;
                let txid: String = row.get(5)?;
                
                invs.push(InvoiceInfo {
                    id: invoice_id.clone(),
                    invoice_id,
                    date,
                    items,
                    total_zec,
                    total_fiat_value,
                    txid,
                });
            }
            Ok::<Vec<InvoiceInfo>, rusqlite::Error>(invs)
        }).await.map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))??;
        
        Ok(invoices)
    }

    pub async fn add_invoice(&self, invoice_id: String, date: String, items: String, total_zec: f64, total_fiat_value: f64, txid: String) -> Result<()> {
        let conn = self.pool.get().await?;
        conn.interact(move |conn| {
            conn.execute(
                "INSERT INTO market_invoices (invoice_id, date, items, total_zec, total_fiat_value, txid) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![invoice_id, date, items, total_zec, total_fiat_value, txid],
            )?;
            Ok::<(), rusqlite::Error>(())
        }).await.map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))??;
        Ok(())
    }

    pub async fn get_addresses(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.pool.get().await?;
        let addresses = conn.interact(move |conn| {
            let mut stmt = conn.prepare(
                // `v.pool IN (2, 3, 4)` — Sapling, Orchard AND **Ironwood**. Ironwood (4) was
                // missing, so per-address balances silently ignored the only pool this wallet now
                // receives into: the same defect as the headline balance bug fixed in P1-1.
                //
                // Ordered by id so the account's first-derived address comes first. The rest are
                // the gap the backend pre-derives at account creation so it can recognise a payment
                // to any of them — they are real, seed-derived and must not be deleted, but a fresh
                // wallet showing 25 of them reads as contamination. `is_default` lets the UI lead
                // with one and put the rest behind a disclosure.
                "SELECT a.address,
                   (SELECT IFNULL(SUM(v.value), 0)
                    FROM v_received_outputs v
                    LEFT JOIN v_received_output_spends s ON v.id_within_pool_table = s.received_output_id AND v.pool = s.pool
                    WHERE (v.address_id = a.id OR (v.address_id IS NULL AND v.account_id = a.account_id AND v.is_change = 1)) AND s.transaction_id IS NULL AND v.value > 10000 AND v.pool IN (2, 3, 4)) as balance,
                   (SELECT COUNT(*) FROM v_received_outputs v2 WHERE v2.address_id = a.id) as received_count
                 FROM addresses a WHERE a.address LIKE 'u1%' ORDER BY a.id"
            )?;
            let mut rows = stmt.query([])?;
            let mut addresses = Vec::new();
            
            let mut first = true;
            while let Some(row) = rows.next()? {
                let addr: String = row.get(0)?;
                let balance_zats: i64 = row.get(1)?;
                let received: i64 = row.get(2)?;
                let balance = (balance_zats as f64) / 100_000_000.0;
                addresses.push(serde_json::json!({
                    "address": addr,
                    "balance": balance,
                    "is_default": first,
                    // Whether anything has ever arrived here. An address with no history is
                    // pre-derived, not "unused by mistake".
                    "used": received > 0
                }));
                first = false;
            }
            Ok::<Vec<serde_json::Value>, rusqlite::Error>(addresses)
        }).await.map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))??;
        
        Ok(addresses)
    }
}

pub fn sync_status() -> String {
    let status = serde_json::json!({
        "status": "Syncing",
        "blockHeight": 2500000,
        "targetHeight": 2800000,
        "progress": 89,
        "ipAddress": "127.0.0.1:8232"
    });
    status.to_string()
}

pub fn get_balance() -> f64 {
    0.0
}