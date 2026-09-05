<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import TransactionDetail from "$lib/components/TransactionDetail.svelte";
  import { type Tx, shortId, formatDateShort, confirmationsLabel, matchesQuery } from "$lib/tx";

  let all = $state<Tx[]>([]);
  let query = $state("");
  let selected = $state<Tx | null>(null);
  let loading = $state(true);
  let loadError = $state("");

  // No LIMIT in the backend any more, so this really is everything.
  const shown = $derived(all.filter(tx => matchesQuery(tx, query)));

  async function load() {
    loading = true;
    loadError = "";
    try {
      all = await invoke<Tx[]>("get_transactions");
    } catch (e) {
      // An empty list and a failed query used to look identical. Say which.
      loadError = `Could not load transactions: ${e}`;
    } finally {
      loading = false;
    }
  }

  onMount(load);
</script>

<div class="tx-page">
  <div class="toolbar">
    <div class="search-wrap">
      <span class="search-icon">🔍</span>
      <input
        type="text"
        placeholder="Search by transaction ID, date, address, memo, amount or block…"
        bind:value={query}
        autocomplete="off"
        spellcheck="false"
      />
      {#if query}
        <!-- A clear button, because selecting a pasted 64-character txid to delete
             it is genuinely annoying, and the search is the main way in here. -->
        <button class="clear" onclick={() => (query = "")} aria-label="Clear search">✕</button>
      {/if}
    </div>
    <button class="refresh" onclick={load} disabled={loading}>{loading ? "…" : "Refresh"}</button>
  </div>

  {#if loadError}
    <div class="notice error">{loadError}</div>
  {:else if loading}
    <div class="notice">Loading…</div>
  {:else if all.length === 0}
    <div class="notice">No transactions yet.</div>
  {:else if shown.length === 0}
    <div class="notice">
      Nothing matches “{query}”.
      <button class="link" onclick={() => (query = "")}>Clear search</button>
    </div>
  {:else}
    <p class="count">{shown.length} of {all.length} transaction{all.length === 1 ? "" : "s"}</p>

    <div class="list">
      {#each shown as tx (tx.id)}
        <button class="row" onclick={() => (selected = tx)}>
          <span class="icon {tx.type}">{tx.type === "receive" ? "↓" : "↑"}</span>

          <span class="mid">
            <span class="id mono">{shortId(tx.id)}</span>
            <span class="meta">
              {formatDateShort(tx.block_time)} · {confirmationsLabel(tx)}
              {#if tx.pool} · {tx.pool}{/if}
              {#if tx.assets.length} · {tx.assets.length} asset{tx.assets.length === 1 ? "" : "s"}{/if}
            </span>
            {#if tx.memo}<span class="memo">{tx.memo}</span>{/if}
          </span>

          <span class="amt {tx.type}">
            {tx.type === "receive" ? "+" : "−"}{tx.amount.toFixed(4)} {tx.asset}
          </span>
        </button>
      {/each}
    </div>
  {/if}
</div>

{#if selected}
  <TransactionDetail tx={selected} onClose={() => (selected = null)} />
{/if}

<style>
  .tx-page { display: flex; flex-direction: column; gap: .8rem; }

  .toolbar { display: flex; gap: .6rem; align-items: center; }
  .search-wrap { position: relative; flex: 1; display: flex; align-items: center; }
  .search-icon { position: absolute; left: .7rem; font-size: .85rem; opacity: .5; pointer-events: none; }
  .search-wrap input {
    width: 100%; box-sizing: border-box;
    padding: .55rem .7rem .55rem 2.1rem;
    background: rgba(255,255,255,.04);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 9px; color: inherit; font-family: inherit; font-size: .85rem;
  }
  .clear { position: absolute; right: .5rem; background: transparent; border: none;
           color: inherit; opacity: .55; cursor: pointer; font-size: .8rem; padding: .2rem .35rem; }
  .clear:hover { opacity: 1; }
  .refresh { padding: .55rem .9rem; border-radius: 9px; font-size: .82rem; cursor: pointer;
             background: transparent; color: inherit; font-family: inherit;
             border: 1px solid var(--border-color, #2c2c2c); }

  .count { margin: 0; font-size: .75rem; opacity: .55; }
  .notice { padding: 1.2rem; text-align: center; font-size: .85rem; opacity: .7;
            border: 1px dashed var(--border-color, #2c2c2c); border-radius: 10px; }
  .notice.error { color: #ff6b6b; opacity: 1; border-style: solid; }
  .link { background: none; border: none; color: var(--accent-color, #1D7989);
          cursor: pointer; font: inherit; text-decoration: underline; }

  .list { display: flex; flex-direction: column; gap: .35rem; }
  .row {
    display: flex; align-items: center; gap: .75rem; width: 100%;
    padding: .65rem .8rem; text-align: left; cursor: pointer;
    background: rgba(255,255,255,.03);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 10px; color: inherit; font-family: inherit;
    transition: background .15s, border-color .15s;
  }
  .row:hover { background: rgba(255,255,255,.06); border-color: var(--accent-color, #1D7989); }

  .icon { width: 28px; height: 28px; flex-shrink: 0; border-radius: 50%;
          display: flex; align-items: center; justify-content: center; font-size: .85rem; }
  .icon.receive { background: rgba(74,222,128,.15); color: #4ade80; }
  .icon.send    { background: rgba(251,146,60,.15); color: #fb923c; }

  .mid { display: flex; flex-direction: column; gap: .12rem; min-width: 0; flex: 1; }
  .id { font-size: .8rem; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .meta { font-size: .72rem; opacity: .55; }
  .memo { font-size: .74rem; opacity: .75; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  .amt { font-size: .85rem; font-variant-numeric: tabular-nums; white-space: nowrap; }
  .amt.receive { color: #4ade80; }
  .amt.send    { color: #fb923c; }
</style>
