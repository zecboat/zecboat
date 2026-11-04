<script lang="ts">
  import { type Tx, shortId, formatDate, confirmationsLabel, privacyLabel } from "$lib/tx";
  import CopyButton from "./CopyButton.svelte";
  import LineageDelivery from "./LineageDelivery.svelte";

  let { tx, onClose }: { tx: Tx; onClose: () => void } = $props();

  const privacy = $derived(privacyLabel(tx));

  // A transfer that moved an item is named after the item (0.7.1). It used to read "Sent
  // 0.00080000 ZEC": the item's carrier plus the fee, with nothing to say a postcard had moved.
  const items = $derived(tx.assets.map((a) => a.name ?? "Unnamed item"));
  const itemTitle = $derived(items.length === 1 ? items[0] : `${items.length} items`);

  // There is deliberately no "open in explorer" link.
  //
  // Following one would hand this wallet's txid to a third-party server together with
  // the user's IP, at the exact moment they are looking at their own transaction. That
  // is a metadata leak the shielded pool otherwise prevents, performed by the wallet on
  // the user's behalf. Anyone who wants an explorer can copy the id and paste it.
  //
  // Worth keeping: the txid here is in DISPLAY order. Zcash stores txids byte-reversed,
  // and the UI once held a reversed, truncated string -- which is why copying an id and
  // searching for it used to fail twice over.
</script>

<div class="detail-backdrop" role="presentation" onclick={onClose}>
  <div class="detail" role="dialog" aria-modal="true" aria-label="Transaction detail"
       tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>

    <div class="d-head">
      <div>
        {#if items.length}
          <h3>{tx.type === "receive" ? "Received" : "Sent"} {itemTitle}</h3>
          <p class="sub">
            {formatDate(tx.block_time)} · carried by {(0.0001 * items.length).toFixed(4)} ZEC{#if tx.type === "send" && tx.fee != null} · fee {tx.fee.toFixed(8)} ZEC{/if}
          </p>
          {#if tx.type === "send"}<LineageDelivery txid={tx.id} />{/if}
        {:else}
          <h3>{tx.type === "receive" ? "Received" : "Sent"} {tx.amount.toFixed(8)} {tx.asset}</h3>
          <p class="sub">{formatDate(tx.block_time)}</p>
        {/if}
      </div>
      <button class="x" onclick={onClose} aria-label="Close">✕</button>
    </div>

    <div class="d-body">
      <div class="privacy {privacy.level}">{privacy.text}</div>

      <div class="field">
        <span class="k">Transaction ID</span>
        <span class="v mono wrap">{tx.id}</span>
        <CopyButton value={tx.id} label="Copy TxID" title="Copy the transaction id" />
      </div>

      <div class="grid">
        <div><span class="k">Status</span><span class="v">{confirmationsLabel(tx)}</span></div>
        <div><span class="k">Block height</span><span class="v">{tx.height?.toLocaleString() ?? "—"}</span></div>
        <div><span class="k">Fee</span><span class="v">{tx.fee !== null ? `${tx.fee.toFixed(8)} ZEC` : "—"}</span></div>
        <div><span class="k">Pool</span><span class="v">{tx.pool ?? "—"}</span></div>
        <div><span class="k">Direction</span><span class="v">{tx.type}</span></div>
        <div><span class="k">Expires at</span><span class="v">{tx.expiry_height?.toLocaleString() ?? "—"}</span></div>
      </div>

      {#if tx.to_address}
        <div class="field">
          <span class="k">Sent to</span>
          <span class="v mono wrap">{tx.to_address}</span>
          <CopyButton value={tx.to_address ?? ""} label="Copy" compact title="Copy the address" />
        </div>
      {:else if tx.type === "receive"}
        <!-- Not a gap in the data. The sender of a shielded payment is not
             recoverable from the chain by anyone's wallet, and a blank field here
             reads as a defect rather than as the privacy guarantee it is. -->
        <div class="field">
          <span class="k">From</span>
          <span class="v muted">Not knowable — a shielded sender is never revealed on chain</span>
        </div>
      {/if}

      {#if tx.memo}
        <div class="field">
          <span class="k">Memo</span>
          <span class="v memo">{tx.memo}</span>
        </div>
      {/if}

      {#if tx.assets.length}
        <div class="field">
          <span class="k">znft</span>
          <div class="v">
            {#each tx.assets as a}
              <div class="asset">
                <strong>{a.name ?? "Unnamed asset"}</strong>
                <span class="mono small">{shortId(a.asset_id, 10)}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}
    </div>

    <div class="d-foot">
      <button class="btn primary" onclick={onClose}>Close</button>
    </div>
  </div>
</div>

<style>
  .detail-backdrop {
    position: fixed; inset: 0; z-index: 1300;
    background: rgba(0,0,0,.72);
    display: flex; align-items: center; justify-content: center; padding: 1rem;
  }
  .detail {
    background: var(--surface-color, #1e1e1e);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 14px;
    width: 100%; max-width: 560px; max-height: 90vh;
    display: flex; flex-direction: column; text-align: left;
  }
  .d-head { display: flex; justify-content: space-between; align-items: flex-start;
            padding: 1rem 1.15rem .6rem; flex-shrink: 0; }
  .d-head h3 { margin: 0; font-size: 1rem; }
  .sub { margin: .2rem 0 0; font-size: .8rem; opacity: .7; }
  .x { background: transparent; border: none; color: inherit; cursor: pointer; font-size: 1rem; opacity: .6; }
  .x:hover { opacity: 1; }

  /* min-height: 0 — a flex child will not shrink below its content without it,
     and overflow then silently does nothing. */
  .d-body { flex: 1 1 auto; min-height: 0; overflow-y: auto; padding: .3rem 1.15rem 1rem; }

  .privacy { font-size: .78rem; padding: .5rem .6rem; border-radius: 8px; margin-bottom: .9rem;
             border-left: 3px solid currentColor; }
  .privacy.shielded { color: #4ade80; }
  .privacy.mixed    { color: #fbbf24; }
  .privacy.public   { color: #fb923c; }
  .privacy.unknown  { color: #9ca3af; }

  .field { display: flex; flex-direction: column; gap: .2rem; margin-bottom: .8rem; }
  .grid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: .7rem; margin-bottom: .9rem; }
  .grid > div { display: flex; flex-direction: column; gap: .15rem; }
  .k { font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; opacity: .55; }
  .v { font-size: .85rem; }
  .v.muted { opacity: .6; font-style: italic; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .74rem; }
  .wrap { word-break: break-all; }
  .small { opacity: .6; }
  .memo { background: rgba(255,255,255,.04); border-radius: 6px; padding: .5rem .6rem;
          white-space: pre-wrap; word-break: break-word; font-size: .8rem; }
  .asset { display: flex; flex-direction: column; gap: .1rem; padding: .4rem .5rem;
           background: rgba(255,255,255,.04); border-radius: 6px; margin-bottom: .3rem; }

  .d-foot { flex-shrink: 0; display: flex; gap: .5rem; justify-content: flex-end;
            padding: .8rem 1.15rem 1rem; border-top: 1px solid var(--border-color,#2c2c2c); }
  .btn { padding: .45rem .9rem; border-radius: 8px; font-size: .85rem; cursor: pointer;
         font-family: inherit; text-decoration: none; display: inline-block; }
  .btn.secondary { background: transparent; border: 1px solid var(--border-color,#2c2c2c); color: inherit; }
  .btn.primary { background: var(--accent-color,#1D7989); color: #fff; border: none; }
</style>
