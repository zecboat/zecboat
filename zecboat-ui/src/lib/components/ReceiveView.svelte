<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import QRCode from "qrcode";
  import TransactionDetail from "$lib/components/TransactionDetail.svelte";
  import { type Tx, formatDateShort, confirmationsLabel, matchesQuery } from "$lib/tx";

  // The QR button used to be markup only — no handler, and no QR library in the
  // project at all. It rendered a square glyph and did nothing, on every row.
  // Someone showing their phone at a market would have found that out there.
  let qrFor = $state<{ address: string; label: string } | null>(null);
  let qrDataUrl = $state("");
  let qrError = $state("");

  async function showQr(address: string, label: string) {
    qrFor = { address, label };
    qrDataUrl = "";
    qrError = "";
    try {
      // The bare address, not a zcash: URI. Every wallet can scan an address;
      // URI support is uneven, and a code that will not scan is worse than none.
      //
      // errorCorrectionLevel "M" leaves ~15% redundancy, which is what makes a
      // code readable off a screen at an angle. margin 2 is the quiet zone —
      // without it many scanners simply fail.
      qrDataUrl = await QRCode.toDataURL(address, {
        errorCorrectionLevel: "M",
        margin: 2,
        width: 320,
        color: { dark: "#000000", light: "#ffffff" },
      });
    } catch (e) {
      // Say so rather than showing an empty box. A blank QR looks like a slow
      // load, and someone will wait at a counter for it.
      qrError = `Could not generate a QR code: ${e}`;
    }
  }

  function closeQr() {
    qrFor = null;
    qrDataUrl = "";
    qrError = "";
  }

  function onQrKey(e: KeyboardEvent) {
    if (e.key === "Escape") closeQr();
  }

  let searchQuery = $state("");
  type Addr = {
    type: string; address: string; balance: number;
    is_default: boolean; used: boolean;
  };
  let addresses = $state<Addr[]>([]);
  let showAll = $state(false);

  // Bare t1… addresses, for senders that cannot parse a unified address. Kept visually separate
  // from the shielded address because the privacy properties are opposite, not merely different.
  let transparent = $state<{address: string, public: boolean}[]>([]);
  let transparentError = $state<string | null>(null);
  let showTransparent = $state(false);

  // The account's own receiving address — what a person means by "my address".
  let primary = $derived(addresses.find(a => a.is_default) ?? addresses[0]);
  // Everything else the backend pre-derived, plus anything that has actually been used.
  let others  = $derived(addresses.filter(a => a !== primary));
  let usedOthers = $derived(others.filter(a => a.used || a.balance > 0));
  let isGenerating = $state(false);
  
  let allTransactions = $state<Tx[]>([]);
  let selectedTx = $state<Tx | null>(null);

  let filteredTransactions = $derived(
    allTransactions.filter(tx => matchesQuery(tx, searchQuery))
  );

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
  }

  function formatAddress(addr: string) {
    if (!addr) return "";
    if (addr.length <= 24) return addr;
    return `${addr.slice(0, 12)}...${addr.slice(-12)}`;
  }

  async function loadAddresses() {
    try {
      const addrs: {address: string, balance: number, is_default: boolean, used: boolean}[] =
        await invoke("get_addresses");
      addresses = addrs.map(item => {
        let type = 'Unknown';
        if (item.address.startsWith('u1')) type = 'Orchard';
        else if (item.address.startsWith('zs1') || item.address.startsWith('ztestsapling')) type = 'Sapling';
        else if (item.address.startsWith('t1') || item.address.startsWith('tm')) type = 'Transparent';
        
        return {
          type, address: item.address, balance: item.balance,
          is_default: !!item.is_default, used: !!item.used,
        };
      });
    } catch (e) {
      console.error("Failed to load addresses", e);
    }
  }
  
  async function loadTransparent() {
    try {
      transparent = await invoke("get_transparent_address");
    } catch (e: any) {
      transparentError = String(e);
    }
  }

  async function loadTransactions() {
    try {
      allTransactions = await invoke("get_transactions");
    } catch (e) {
      console.error("Failed to load transactions", e);
    }
  }

  async function generateAddress() {
    isGenerating = true;
    try {
      const newAddr: string = await invoke("generate_new_address");
      addresses = [...addresses, { type: 'Orchard', address: newAddr, balance: 0.0, is_default: false, used: false }];
      showAll = true;   // a freshly generated address is useless if it stays hidden
    } catch (e) {
      console.error("Failed to generate address", e);
    } finally {
      isGenerating = false;
    }
  }

  onMount(() => {
    loadAddresses();
    loadTransparent();
    loadTransactions();
  });
</script>

<div class="receive-view">
  
  <div class="addresses-section card">
    <div class="section-header">
      <h3>My Addresses</h3>
      <button class="btn secondary small" onclick={generateAddress} disabled={isGenerating}>
        {isGenerating ? "Generating..." : "+ New Address"}
      </button>
    </div>
    
    <!-- One address, because that is what "my address" means. The rest are a gap the wallet
         pre-derives at account creation so it can recognise a payment to any of them; showing all
         25 in a brand-new wallet reads as contamination. They are real and seed-derived — never
         delete them, or a payment to one becomes invisible. -->
    <div class="address-list">
      {#if primary}
        <div class="address-item primary">
          <div class="addr-info">
            <span class="addr-type badge {primary.type.toLowerCase()}">{primary.type}</span>
            <span class="addr-string full" title={primary.address}>{primary.address}</span>
          </div>
          <div class="addr-actions">
            <span class="addr-balance">{primary.balance.toFixed(4)} ZEC</span>
            <button class="icon-btn" onclick={() => copyToClipboard(primary.address)} title="Copy Address">📋</button>
            <button class="icon-btn" onclick={() => showQr(primary.address, primary.type + " address")} title="Show QR code">🔳</button>
          </div>
        </div>
      {:else}
        <div class="empty-state">No addresses yet.</div>
      {/if}

      {#if others.length}
        <button class="disclosure" onclick={() => (showAll = !showAll)}>
          {showAll ? "▾" : "▸"} {others.length} more derived address{others.length === 1 ? "" : "es"}
          {#if usedOthers.length}<span class="used-hint"> · {usedOthers.length} used</span>{/if}
        </button>
      {/if}

      <!-- Transparent, kept below and behind a disclosure. It is a funding on-ramp, not a place to
           hold value, and presenting it beside the shielded address would invite using it as one. -->
      {#if transparent.length}
        <button class="disclosure" onclick={() => (showTransparent = !showTransparent)}>
          {showTransparent ? "▾" : "▸"} Transparent address (t1…) — for exchanges and legacy senders
        </button>
      {/if}

      {#if showTransparent}
        <div class="transparent-warning">
            <strong>This wallet does not watch transparent addresses by default.</strong>
            Noticing a payment to a t-address means asking the node about that address by name,
            which tells it the address is yours — the one thing shielded scanning never does.
            If you give this address out, restart with <code>ZECBOAT_TRANSPARENT_SCAN=1</code>
            so the payment is seen.
            <br /><br />
          ⚠ <strong>This address is public.</strong> Anything sent here is visible on chain — the
          amount, and who sent it. Use it only to receive funds from a service that cannot send to a
          unified address, then <strong>shield promptly</strong>. Shielding moves the value into
          Ironwood, where it becomes private and spendable.
        </div>
        {#each transparent as t}
          <div class="address-item transparent-item">
            <div class="addr-info">
              <span class="addr-type badge transparent">Transparent</span>
              <span class="addr-string full" title={t.address}>{t.address}</span>
            </div>
            <div class="addr-actions">
              <button class="icon-btn" onclick={() => copyToClipboard(t.address)} title="Copy Address">📋</button>
              <button class="icon-btn" onclick={() => showQr(t.address, "Transparent address")} title="Show QR code">🔳</button>
            </div>
          </div>
        {/each}
      {:else if transparentError && showTransparent}
        <div class="transparent-warning">{transparentError}</div>
      {/if}

      {#if showAll}
        <p class="derived-note">
          Pre-derived from this wallet's seed so it can recognise a payment sent to any of them.
          They are not separate accounts, and deleting them would make funds sent there invisible.
        </p>
        {#each others as addr}
          <div class="address-item derived">
            <div class="addr-info">
              <span class="addr-type badge {addr.type.toLowerCase()}">{addr.type}</span>
              <span class="addr-string" title={addr.address}>{formatAddress(addr.address)}</span>
              {#if addr.used}<span class="used-badge">used</span>{/if}
            </div>
            <div class="addr-actions">
              <span class="addr-balance">{addr.balance.toFixed(4)} ZEC</span>
              <button class="icon-btn" onclick={() => copyToClipboard(addr.address)} title="Copy Address">📋</button>
              <button class="icon-btn" onclick={() => showQr(addr.address, addr.type + " address")} title="Show QR code">🔳</button>
            </div>
          </div>
        {/each}
      {/if}
    </div>
  </div>

  <div class="history-section card">
    <div class="history-header">
      <h3>Transaction History</h3>
      <div class="search-box">
        <span>🔍</span>
        <input type="text" placeholder="Search by TxID..." bind:value={searchQuery} />
      </div>
    </div>

    <div class="tx-list">
      {#each filteredTransactions as tx}
        <div class="tx-row" role="button" tabindex="0"
             onclick={() => (selectedTx = tx)}
             onkeydown={(e) => (e.key === "Enter" || e.key === " ") && (selectedTx = tx)}>
          <div class="tx-icon {tx.type}">
            {tx.type === 'receive' ? '↓' : '↑'}
          </div>
          <div class="tx-details">
            <div class="tx-id-row">
              <span class="tx-id">{tx.id}</span>
              <button class="icon-btn small" onclick={(e) => { e.stopPropagation(); copyToClipboard(tx.id); }} title="Copy TxID">📋</button>
            </div>
            <span class="tx-meta">{formatDateShort(tx.block_time)} • {confirmationsLabel(tx)}</span>
          </div>
          <div class="tx-amount {tx.type}">
            {tx.type === 'receive' ? '+' : '-'}{tx.amount.toFixed(4)} {tx.asset}
          </div>
        </div>
      {:else}
        <div class="no-results">No transactions found matching "{searchQuery}"</div>
      {/each}
    </div>
  </div>
</div>

<svelte:window on:keydown={onQrKey} />

{#if selectedTx}
  <TransactionDetail tx={selectedTx} onClose={() => (selectedTx = null)} />
{/if}

{#if qrFor}
  {@const qr = qrFor}
  <div
    class="qr-backdrop"
    role="button"
    tabindex="-1"
    onclick={closeQr}
    onkeydown={(e) => e.key === "Enter" && closeQr()}
  >
    <div
      class="qr-modal"
      role="dialog"
      aria-modal="true"
      aria-label="Address QR code"
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
    >
      <h3>{qr.label}</h3>

      {#if qrError}
        <p class="qr-error">{qrError}</p>
      {:else if qrDataUrl}
        <!-- White plate behind the code. A dark-themed page renders the quiet zone
             dark and many scanners will not read it. -->
        <div class="qr-plate">
          <img src={qrDataUrl} alt="QR code for this address" />
        </div>
      {:else}
        <p class="qr-loading">Generating…</p>
      {/if}

      <!-- The full address in monospace under the code. Scanning fails often
           enough that a readable fallback is not optional. -->
      <p class="qr-address">{qr.address}</p>

      <div class="qr-actions">
        <button class="btn secondary" onclick={() => copyToClipboard(qr.address)}>Copy address</button>
        <button class="btn primary" onclick={closeQr}>Close</button>
      </div>
    </div>
  </div>
{/if}

<style>
  /* Row is a <button> so the whole thing is clickable and keyboard-reachable;
     strip the chrome so it still reads as a row. */
  .tx-row { width: 100%; text-align: left; font-family: inherit; color: inherit;
            background: transparent; border: none; cursor: pointer; }
  .tx-row:hover { background: rgba(255,255,255,.04); }

  .qr-backdrop {
    position: fixed; inset: 0; z-index: 1000;
    background: rgba(0, 0, 0, 0.65);
    display: flex; align-items: center; justify-content: center;
    padding: 1rem; border: none;
  }
  .qr-modal {
    background: var(--bg-card, #161616);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 14px;
    padding: 1.25rem;
    max-width: 420px; width: 100%;
    text-align: center;
  }
  .qr-modal h3 { margin: 0 0 0.9rem; font-size: 1rem; }
  .qr-plate {
    background: #fff; padding: 12px; border-radius: 10px;
    display: inline-block; line-height: 0;
  }
  .qr-plate img { width: 260px; height: 260px; display: block; }
  .qr-address {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 0.72rem; line-height: 1.45;
    word-break: break-all;
    margin: 0.9rem 0 1rem;
    color: var(--text-secondary, #aaaaaa);
  }
  .qr-error { color: #ff6b6b; font-size: 0.85rem; }
  .qr-loading { font-size: 0.85rem; opacity: 0.7; }
  .qr-actions { display: flex; gap: 0.6rem; justify-content: center; }

  .address-item.primary { border: 1px solid rgba(63, 185, 80, 0.35); background: rgba(63, 185, 80, 0.06); }
  .addr-string.full { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.72rem; word-break: break-all; line-height: 1.4; }
  .disclosure {
    background: none; border: none; color: #8b949e; cursor: pointer;
    font-size: 0.82rem; padding: 8px 2px; text-align: left; width: 100%;
  }
  .disclosure:hover { color: #c9d1d9; }
  .used-hint { color: #d29922; }
  .used-badge {
    font-size: 0.6rem; text-transform: uppercase; letter-spacing: 0.04em;
    color: #d29922; border: 1px solid rgba(210,153,34,0.4); border-radius: 999px; padding: 1px 6px;
  }
  .derived-note { margin: 4px 2px 10px; font-size: 0.76rem; color: #8b949e; line-height: 1.45; }
  .address-item.derived { opacity: 0.75; }
  .receive-view {
    display: flex;
    flex-direction: column;
    gap: 2rem;
  }

  .card {
    background: var(--surface-color, #1e1e1e);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 16px;
    padding: 1.5rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
  }
  
  .section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  h3 {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
  }
  
  .btn.secondary {
    background: var(--surface-hover);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.2s;
  }
  
  .btn.secondary:hover:not(:disabled) {
    background: var(--surface-active);
  }
  
  .btn:disabled {
    opacity: 0.7;
    cursor: not-allowed;
  }

  .address-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .address-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background: var(--surface-hover);
    border-radius: 12px;
    border: 1px solid transparent;
    transition: border-color 0.2s;
  }

  .address-item:hover {
    border-color: var(--border-color);
  }

  .addr-info {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .badge {
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-size: 0.8rem;
    font-weight: 600;
  }

  .badge.orchard { background: rgba(0, 230, 118, 0.15); color: #00e676; }
  .badge.sapling { background: rgba(0, 176, 255, 0.15); color: #00b0ff; }
  .badge.transparent { background: rgba(158, 160, 170, 0.15); color: #9ea0aa; }

  .addr-string {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 1.1rem;
  }

  .addr-actions {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .addr-balance {
    font-weight: 600;
    color: var(--text-secondary);
  }

  .icon-btn {
    background: transparent;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    font-size: 1.2rem;
    padding: 0.25rem;
    border-radius: 6px;
    transition: background 0.2s;
  }

  .icon-btn:hover {
    background: var(--surface-active);
  }

  .icon-btn.small {
    font-size: 0.9rem;
  }

  .history-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
  }

  .history-header h3 {
    margin-bottom: 0;
  }

  .search-box {
    display: flex;
    align-items: center;
    background: var(--surface-hover);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 0.5rem 1rem;
    gap: 0.5rem;
  }

  .search-box input {
    background: transparent;
    border: none;
    color: var(--text-primary);
    outline: none;
    width: 250px;
  }

  .tx-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .tx-row {
    display: flex;
    align-items: center;
    padding: 1rem;
    background: var(--surface-hover);
    border-radius: 12px;
  }

  .tx-icon {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 1.5rem;
    font-size: 1.5rem;
    font-weight: bold;
  }

  .tx-icon.receive { background: rgba(0, 230, 118, 0.1); color: #00e676; }
  .tx-icon.send { background: rgba(255, 61, 0, 0.1); color: #ff3d00; }

  .tx-details {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .tx-id-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .tx-id {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-weight: 500;
  }

  .tx-meta {
    font-size: 0.85rem;
    color: var(--text-secondary);
  }

  .tx-amount {
    font-weight: 600;
    font-size: 1.1rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }

  .tx-amount.receive { color: #00e676; }
  .tx-amount.send { color: var(--text-primary); }

  .no-results {
    text-align: center;
    color: var(--text-secondary);
    padding: 2rem;
  }
</style>