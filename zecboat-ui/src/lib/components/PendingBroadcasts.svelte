<!--
  Unconfirmed-transaction banner.

  Why this exists: `create_proposed_transactions` marks a transaction's inputs
  spent when it builds and signs, before the broadcast is attempted. If the
  broadcast response is then lost — P1-10, three times, "error receiving data
  from backing node" — the wallet holds a complete, valid, signed transaction
  that never reached the network, with the notes it spends already locked to it.

  Nothing in the UI used to look for that. Both stranded HBD sends were recovered
  by hand: read `transactions.raw` where `mined_height IS NULL`, POST it to
  zebrad over SSH, race `expiry_height`. This banner is that procedure, as a
  button.

  Normal case: the check returns nothing and this component renders nothing at
  all. A transaction is legitimately unconfirmed for roughly a block after any
  send, so the banner deliberately stays quiet unless something is actually at
  risk — see `alarming` below.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  type PendingBroadcast = {
    txid: string;
    expiry_height: number;
    blocks_remaining: number | null;
    expired: boolean;
    size_bytes: number;
    raw_hex: string;
  };

  let pending = $state<PendingBroadcast[]>([]);
  let checking = $state(false);
  let resending = $state(false);
  let report = $state("");
  let error = $state("");
  let dismissed = $state(false);

  // A transaction on its way to the mempool is unconfirmed for about a block,
  // which is normal and not worth interrupting anyone over. Treat it as worth
  // showing only once it is expired or running out of room — under 20 blocks,
  // roughly 25 minutes, which is still ample time to resend.
  const WARN_BELOW_BLOCKS = 20;

  let alarming = $derived(
    pending.filter(
      (p) => p.expired || p.blocks_remaining === null || p.blocks_remaining < WARN_BELOW_BLOCKS,
    ),
  );
  let anyExpired = $derived(pending.some((p) => p.expired));
  let visible = $derived(!dismissed && alarming.length > 0);

  async function check() {
    checking = true;
    error = "";
    try {
      pending = await invoke("check_pending_broadcasts");
      // Something to say again means the banner has earned the right to reappear.
      if (pending.length === 0) dismissed = false;
    } catch (e) {
      // A failed check must not itself become an alarm. Log it and stay quiet;
      // the wallet is no worse off than before this component existed.
      console.error("Could not check for unconfirmed transactions:", e);
      error = String(e);
    } finally {
      checking = false;
    }
  }

  async function resend() {
    resending = true;
    error = "";
    report = "";
    try {
      report = await invoke("resend_pending_broadcasts");
      await check();
    } catch (e) {
      error = String(e);
    } finally {
      resending = false;
    }
  }

  onMount(() => {
    check();
    // Every two minutes. This is not a sync loop — it reads a handful of rows
    // and asks the node for the tip, and it only matters when something is
    // stuck. The 2-second poll that used to live in +page.svelte read a file
    // nothing ever wrote; do not repeat that.
    const interval = setInterval(check, 120_000);
    return () => clearInterval(interval);
  });
</script>

{#if visible}
  <div class="pending-banner {anyExpired ? 'expired' : ''}">
    <div class="banner-head">
      <span class="icon">{anyExpired ? "⚠️" : "📡"}</span>
      <div class="headline">
        <strong>
          {alarming.length}
          {alarming.length === 1 ? "transaction was" : "transactions were"} built but
          {anyExpired ? "never confirmed" : "have not been confirmed"}
        </strong>
        <p>
          {#if anyExpired}
            Some have passed their expiry height and can no longer be broadcast. Their inputs
            are still marked spent locally; a wallet rescan is required to release them.
          {:else}
            The transaction is signed and stored in this wallet — it is <em>not</em> lost. If the
            network never received it, resending delivers it. Resending is safe: a transaction
            already in the mempool is simply ignored as a duplicate.
          {/if}
        </p>
      </div>
      <button class="dismiss" onclick={() => (dismissed = true)} title="Hide until the next check">
        ✕
      </button>
    </div>

    <ul class="tx-list">
      {#each alarming as tx (tx.txid)}
        <li>
          <code>{tx.txid}</code>
          <span class="meta">
            {(tx.size_bytes / 1024).toFixed(1)} kB ·
            {#if tx.expired}
              <span class="dead">expired at {tx.expiry_height.toLocaleString()}</span>
            {:else if tx.blocks_remaining !== null}
              expires in {tx.blocks_remaining} block{tx.blocks_remaining === 1 ? "" : "s"}
            {:else}
              expiry {tx.expiry_height === 0 ? "none" : tx.expiry_height.toLocaleString()}
            {/if}
          </span>
        </li>
      {/each}
    </ul>

    <div class="actions">
      <button class="btn primary" onclick={resend} disabled={resending || checking}>
        {resending ? "Resending…" : "Resend to the network"}
      </button>
      <button class="btn ghost" onclick={check} disabled={resending || checking}>
        {checking ? "Checking…" : "Check again"}
      </button>
    </div>

    {#if report}
      <pre class="report">{report}</pre>
    {/if}
    {#if error}
      <pre class="report error-text">{error}</pre>
    {/if}
  </div>
{/if}

<style>
  .pending-banner {
    background: var(--surface-color, #1e1e1e);
    border: 1px solid #ffd600;
    border-left: 4px solid #ffd600;
    border-radius: 12px;
    padding: 1.25rem;
    margin-bottom: 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    grid-column: 1 / -1;
  }

  .pending-banner.expired {
    border-color: #ff3d00;
    border-left-color: #ff3d00;
  }

  .banner-head {
    display: flex;
    gap: 0.85rem;
    align-items: flex-start;
  }

  .icon {
    font-size: 1.3rem;
    line-height: 1.3;
  }

  .headline {
    flex: 1;
  }

  .headline strong {
    color: var(--text-primary, #fff);
    font-size: 1rem;
    display: block;
    margin-bottom: 0.35rem;
  }

  .headline p {
    margin: 0;
    color: var(--text-secondary, #999);
    font-size: 0.9rem;
    line-height: 1.5;
  }

  .dismiss {
    background: none;
    border: none;
    color: var(--text-secondary, #999);
    cursor: pointer;
    font-size: 0.95rem;
    padding: 0.15rem 0.4rem;
    border-radius: 6px;
  }

  .dismiss:hover {
    background: var(--surface-hover, #2a2a2a);
    color: var(--text-primary, #fff);
  }

  .tx-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .tx-list li {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
    background: var(--bg-color, #171717);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
  }

  .tx-list code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.8rem;
    color: var(--text-primary, #fff);
    word-break: break-all;
  }

  .meta {
    font-size: 0.8rem;
    color: var(--text-secondary, #999);
    white-space: nowrap;
  }

  .dead {
    color: #ff3d00;
    font-weight: 600;
  }

  .actions {
    display: flex;
    gap: 0.75rem;
  }

  .btn {
    padding: 0.55rem 1.1rem;
    border-radius: 8px;
    border: none;
    font-weight: 600;
    cursor: pointer;
    font-size: 0.9rem;
    transition: background 0.2s;
  }

  .btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }

  .btn.primary {
    background: var(--accent-color, #f4b728);
    color: #171717;
  }

  .btn.primary:hover:not(:disabled) {
    background: var(--accent-hover, #ffc94a);
  }

  .btn.ghost {
    background: transparent;
    color: var(--text-secondary, #999);
    border: 1px solid var(--border-color, #2c2c2c);
  }

  .btn.ghost:hover:not(:disabled) {
    color: var(--text-primary, #fff);
    border-color: var(--text-secondary, #999);
  }

  .report {
    margin: 0;
    padding: 0.75rem;
    background: var(--bg-color, #171717);
    border-radius: 8px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.78rem;
    color: var(--text-secondary, #999);
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 220px;
    overflow-y: auto;
  }

  .report.error-text {
    color: #ff8a65;
  }
</style>
