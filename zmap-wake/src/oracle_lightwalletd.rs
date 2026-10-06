//! A lightwalletd / Zaino gRPC oracle (`WAKE-v1.md` §8.1, the light-client case).
//!
//! Behind the `lightwalletd` cargo feature. First run against a live endpoint on 2026-10-05
//! (`examples/light_verify.rs`, a public lightwalletd): held ladings verified, tampered ones
//! were refused for the right reason, and a hop was proved from the server's tree state.
//!
//! This oracle relays what the server says. It does not verify tree roots against
//! the block-header chain (ZIP 221), so it reports [`OracleTrust::ServerAsserted`]
//! and a verdict built on it MUST NOT be shown as verified by the holder's own node.
//! A prover who also controls the verifier's server can otherwise supply a fabricated
//! root matching a fabricated proof.
//!
//! Every call runs on a short-lived thread with its own single-threaded runtime, so the
//! oracle can be used from synchronous code, from inside another runtime's blocking section,
//! or from a plain thread, without nesting runtimes.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use orchard::note::ExtractedNoteCommitment;
use orchard::tree::Anchor;
use tonic::transport::{Channel, Endpoint};
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, ChainSpec, TxFilter,
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

use crate::oracle::{reversed, AnchorStatus, ChainOracle, IronwoodAction, IronwoodTreeState, OracleTrust};

/// A lightwalletd-protocol endpoint, e.g. `https://zec.rocks:443` or `http://127.0.0.1:8137`.
pub struct LightwalletdOracle {
    url: String,
    network: Network,
    /// The tip as first seen by this oracle: one verification judges every anchor against
    /// the same height.
    tip: RefCell<Option<u32>>,
    tree_cache: RefCell<HashMap<u32, IronwoodTreeState>>,
}

impl std::fmt::Debug for LightwalletdOracle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LightwalletdOracle")
            .field("url", &self.url)
            .field("network", &self.network)
            .finish()
    }
}

/// Run `make()`'s future to completion on a fresh thread with its own runtime.
fn on_thread<T, Fut>(make: impl FnOnce() -> Fut + Send + 'static) -> Result<T>
where
    T: Send + 'static,
    Fut: Future<Output = Result<T>> + 'static,
{
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("tokio runtime")?;
        rt.block_on(make())
    })
    .join()
    .map_err(|_| anyhow!("the server call panicked"))?
}

async fn connect(url: &str) -> Result<CompactTxStreamerClient<Channel>> {
    let channel = Endpoint::new(url.to_string())
        .with_context(|| format!("{url} is not a server address"))?
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .with_context(|| format!("no answer from the server at {url}"))?;
    Ok(CompactTxStreamerClient::new(channel))
}

impl LightwalletdOracle {
    pub fn new(url: impl Into<String>, network: Network) -> Result<Self> {
        Ok(LightwalletdOracle {
            url: url.into(),
            network,
            tip: RefCell::new(None),
            tree_cache: RefCell::new(HashMap::new()),
        })
    }

    /// The address this oracle asks.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The server's latest block height, as first seen by this oracle.
    pub fn tip_height(&self) -> Result<u32> {
        if let Some(t) = *self.tip.borrow() {
            return Ok(t);
        }
        let url = self.url.clone();
        let height = on_thread(move || async move {
            let mut c = connect(&url).await?;
            let id = c.get_latest_block(ChainSpec {}).await.context("GetLatestBlock")?.into_inner();
            Ok(id.height as u32)
        })?;
        *self.tip.borrow_mut() = Some(height);
        Ok(height)
    }

    /// The Ironwood tree state at the end of block `height` (`GetTreeState`), cached.
    pub fn ironwood_tree_state(&self, height: u32) -> Result<IronwoodTreeState> {
        if let Some(ts) = self.tree_cache.borrow().get(&height) {
            return Ok(ts.clone());
        }
        let url = self.url.clone();
        let ts = on_thread(move || async move {
            let mut c = connect(&url).await?;
            let ts = c
                .get_tree_state(BlockId { height: height as u64, hash: vec![] })
                .await
                .context("GetTreeState")?
                .into_inner();
            let tree = ts.ironwood_tree().context("parse ironwood tree from TreeState")?;
            let root: Anchor = tree.root().into();
            let frontier = tree
                .to_frontier()
                .take()
                .ok_or_else(|| anyhow!("empty ironwood tree at {height}"))?;
            Ok(IronwoodTreeState { height, root, frontier })
        })?;
        self.tree_cache.borrow_mut().insert(height, ts.clone());
        Ok(ts)
    }

    /// Fetch a transaction by id and make sure the bytes returned ARE that transaction: the
    /// id is recomputed from them. A server can therefore withhold a transaction but cannot
    /// substitute another. Returns the height the server reports (0 when it reports none) and
    /// the bytes; `None` when the server does not know the id. `txid` in display order.
    ///
    /// The reported height is not relied on. Some servers return 0 for transactions outside
    /// their recent window even though they are mined (seen 2026-10-06 with zainod 0.10.0 in
    /// pass-through mode: bytes present, height absent, for transactions about 12,000 blocks
    /// old). Treating 0 as "not mined" made a sound lineage look broken.
    fn fetch_checked(&self, txid: &[u8; 32]) -> Result<Option<(u32, Vec<u8>, Transaction)>> {
        let url = self.url.clone();
        let hash = reversed(*txid).to_vec();
        let got = on_thread(move || async move {
            let mut c = connect(&url).await?;
            match c.get_transaction(TxFilter { block: None, index: 0, hash }).await {
                Ok(r) => {
                    let raw = r.into_inner();
                    Ok(Some((raw.height, raw.data)))
                }
                Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
                Err(e) => Err(anyhow!("GetTransaction: {e}")),
            }
        })?;
        let Some((height, data)) = got else { return Ok(None) };
        if data.is_empty() {
            return Ok(None);
        }
        let height = if height == 0 || height > u32::MAX as u64 { 0 } else { height as u32 };
        // Version 5 and later transactions name their own consensus branch, so the height only
        // matters for older ones; without a reported height the tip's branch is used.
        let at = if height > 0 { height } else { self.tip_height()? };
        let branch = BranchId::for_height(&self.network, BlockHeight::from_u32(at));
        let tx = Transaction::read(&data[..], branch).context("parse transaction")?;
        if tx.txid().as_ref() != &reversed(*txid) {
            return Err(anyhow!("the server answered with a different transaction than the one asked for"));
        }
        Ok(Some((height, data, tx)))
    }

    /// The raw bytes of a transaction and the height the server reports for it (the tip's
    /// height when it reports none); `None` if the server does not know it. The bytes are
    /// checked against the id. `txid` in display order.
    pub fn raw_transaction(&self, txid: &[u8; 32]) -> Result<Option<(u32, Vec<u8>)>> {
        match self.fetch_checked(txid)? {
            Some((height, data, _)) => Ok(Some((if height > 0 { height } else { self.tip_height()? }, data))),
            None => Ok(None),
        }
    }

    /// The Ironwood Actions of a transaction (`GetTransaction`, parsed locally, checked against
    /// the id), with the height the server reports (0 when it reports none). `None` if the
    /// server does not know the transaction. `txid` in display order.
    pub fn ironwood_actions(&self, txid: &[u8; 32]) -> Result<Option<(u32, Vec<IronwoodAction>)>> {
        let Some((height, _, tx)) = self.fetch_checked(txid)? else { return Ok(None) };
        let Some(bundle) = tx.ironwood_bundle() else {
            return Ok(Some((height, Vec::new())));
        };
        let actions = bundle
            .actions()
            .iter()
            .map(|a| IronwoodAction { nullifier: a.nullifier().to_bytes(), cmx: a.cmx().to_bytes() })
            .collect();
        Ok(Some((height, actions)))
    }
}

impl ChainOracle for LightwalletdOracle {
    fn trust(&self) -> OracleTrust {
        OracleTrust::ServerAsserted
    }

    fn anchor_at(&self, root: &Anchor, height: u32) -> Result<AnchorStatus> {
        let tip = self.tip_height()?;
        if height > tip {
            return Ok(AnchorStatus::Unknown);
        }
        let ts = self.ironwood_tree_state(height)?;
        if ts.root == *root {
            Ok(AnchorStatus::Known { depth: tip - height })
        } else {
            Ok(AnchorStatus::Unknown)
        }
    }

    /// A server not knowing the transaction is an error here, not `None`: `None` means "this
    /// output does not exist", which a verifier treats as evidence against the lading, and a
    /// server's silence is not evidence. That the output is mined is established separately, by
    /// the genesis proof's anchor.
    fn cmx_at(&self, txid: &[u8; 32], action_index: u32) -> Result<Option<ExtractedNoteCommitment>> {
        let Some((_, actions)) = self.ironwood_actions(txid)? else {
            return Err(anyhow!("the server at {} does not know transaction {}", self.url, crate::oracle::hex(txid)));
        };
        let Some(a) = actions.get(action_index as usize) else {
            return Ok(None);
        };
        let cmx: Option<ExtractedNoteCommitment> = ExtractedNoteCommitment::from_bytes(&a.cmx).into();
        Ok(cmx)
    }
}
