<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import TransactionDetail from "$lib/components/TransactionDetail.svelte";
  import { type Tx, shortId, formatDateShort } from "$lib/tx";

  let { onViewAll }: { onViewAll?: () => void } = $props();

  // Was an inline type with a `date: string` field. C1 replaced `date` with
  // `block_time` (epoch seconds, so the UI can render local time) and this kept
  // reading `tx.date` — rendering "undefined" under every row with no error
  // anywhere. The shared type in $lib/tx makes the next such change a compile
  // failure instead.
  let transactions = $state<Tx[]>([]);
  let selected = $state<Tx | null>(null);

  async function fetchTransactions() {
    try {
      transactions = await invoke("get_transactions");
    } catch (e) {
      console.error("Failed to load transactions:", e);
    }
  }

  onMount(() => {
    fetchTransactions(); // Initial fetch
    const interval = setInterval(fetchTransactions, 5000); // Poll every 5 seconds
    
    return () => clearInterval(interval); // Cleanup on unmount
  });
</script>

<div class="transaction-history card">
  <div class="header">
    <h2>Recent Transactions</h2>
    <button class="view-all" onclick={() => onViewAll?.()}>View All</button>
  </div>
  
  <div class="tx-list">
    {#each transactions.slice(0, 8) as tx}
      <button class="tx-row" onclick={() => (selected = tx)}>
        <div class="tx-icon {tx.type}">
          {#if tx.type === 'receive'}
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><polyline points="19 12 12 19 5 12"></polyline></svg>
          {:else}
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"></line><polyline points="5 12 12 5 19 12"></polyline></svg>
          {/if}
        </div>
        <div class="tx-details">
          <span class="tx-id">{shortId(tx.id)}</span>
          <span class="tx-date">{formatDateShort(tx.block_time)}</span>
        </div>
        <div class="tx-amount {tx.type}">
          {tx.type === 'receive' ? '+' : '-'}{tx.amount.toFixed(4)} {tx.asset}
        </div>
      </button>
    {:else}
      <div class="empty-state">No recent transactions.</div>
    {/each}
  </div>
</div>

{#if selected}
  <TransactionDetail tx={selected} onClose={() => (selected = null)} />
{/if}

<style>
  /* .tx-row became a <button> so a whole row is clickable and keyboard-reachable.
     Strip the button chrome so it still looks like a row. */
  .tx-row {
    width: 100%;
    text-align: left;
    font-family: inherit;
    color: inherit;
    background: transparent;
    border: none;
    cursor: pointer;
  }
  .tx-row:hover { background: rgba(255, 255, 255, 0.04); }

  .card {
    background: var(--surface-color, #1e1e24);
    border: 1px solid var(--border-color, #333);
    border-radius: 16px;
    padding: 1.5rem;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border-color, #333);
    padding-bottom: 0.75rem;
  }

  h2 {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-primary, #fff);
  }

  .view-all {
    background: transparent;
    border: none;
    color: var(--accent-color, #00e676);
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 500;
  }

  .view-all:hover {
    text-decoration: underline;
  }

  .tx-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .tx-row {
    display: flex;
    align-items: center;
    padding: 0.75rem;
    background: var(--surface-hover, #2a2a32);
    border-radius: 12px;
    transition: transform 0.2s, background 0.2s;
  }

  .tx-row:hover {
    transform: translateY(-2px);
    background: var(--surface-active, #32323c);
  }

  .tx-icon {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 1rem;
  }

  .tx-icon.receive {
    background: rgba(0, 230, 118, 0.1);
    color: #00e676;
  }

  .tx-icon.send {
    background: rgba(255, 61, 0, 0.1);
    color: #ff3d00;
  }

  .tx-icon svg {
    width: 18px;
    height: 18px;
  }

  .tx-details {
    display: flex;
    flex-direction: column;
    flex: 1;
  }

  .tx-id {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    color: var(--text-primary, #fff);
    font-weight: 500;
  }

  .tx-date {
    font-size: 0.8rem;
    color: var(--text-secondary, #999);
  }

  .tx-amount {
    font-weight: 600;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }

  .tx-amount.receive {
    color: #00e676;
  }

  .tx-amount.send {
    color: var(--text-primary, #fff);
  }
  
  .empty-state {
    text-align: center;
    color: var(--text-secondary);
    padding: 1.5rem 0;
  }
</style>