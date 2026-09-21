<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  // Three heights, deliberately kept apart. Collapsing them is how this panel came
  // to display the wallet's scanned height under a "Zebrad Node" label:
  //
  //   chainTip      where the network is
  //   targetHeight  what the provider has indexed and will actually serve
  //   blockHeight   how far this wallet has scanned
  //
  // chainTip > targetHeight  -> the PROVIDER is behind (its indexer trails its node)
  // targetHeight > blockHeight -> the WALLET is behind (ordinary sync)
  // Neither moving while "syncing" -> stalled, which is not the same as either.
  let status = $state("Disconnected");
  let blockHeight = $state(0);
  let targetHeight = $state(0);
  let chainTip = $state(0);
  let progress = $state(0);
  let ipAddress = $state("");
  let vendor = $state("");
  let version = $state("");
  let upgradeName = $state("");
  let latencyMs = $state(0);

  // Derived from successive polls — no backend support needed.
  let lastWalletHeight = 0;
  let lastTargetHeight = 0;
  let lastSampleAt = 0;
  let blocksPerSec = $state(0);

  // Elapsed TIME since each height last moved, not a count of polls.
  //
  // These were poll counters, and the thresholds were chosen for the 15s idle
  // cadence — but the same counters increment at the 2s syncing cadence, where
  // 4 polls is 8 seconds and 20 polls is 40. Zcash blocks arrive about every 75
  // seconds, so a wallet sitting AT THE TIP tripped both alarms before the next
  // block could possibly exist. Reported on a fresh install whose wallet was one
  // block behind the chain: "Provider stalled. No progress in the last 30 checks."
  //
  // A stall is a statement about time passing, so measure time.
  let lastWalletProgressAt = 0;
  let lastTargetProgressAt = 0;
  let nowTick = $state(0);

  // ~3 block intervals. Zcash block times are Poisson, so gaps of two or three
  // intervals happen on a perfectly healthy chain; alarming on those trains people
  // to ignore the warning, which is worse than not having it.
  const QUIET_MS = 240_000;
  const PROVIDER_STALL_MS = 300_000;

  // A quiet gap is not a stall, and conflating them reports a working wallet as broken.
  //
  // Observed 2026-09-20: this panel read "Stalled" while the wallet was scanning at
  // 433 blocks/min and closing a 2,700-block gap — it reached the tip minutes later. The
  // scanner writes in ~200-block batches with pauses between them, and the pauses lengthen
  // under CPU contention (that machine was sharing four cores with a compiler, zebrad and
  // zainod). So "nothing happened for four minutes" was true and "stalled" was false.
  //
  // Elapsed silence alone cannot tell slow from stopped. Distinguish by horizon: quiet for
  // a few minutes is SLOW, quiet for a quarter of an hour is STALLED. A wallet that is
  // merely starved still lands a batch well inside the longer window.
  const STALL_MS = 900_000;

  const POLL_SYNCING = 2000;
  const POLL_IDLE = 15000;
  let timer: ReturnType<typeof setTimeout> | null = null;

  const isSyncing = $derived(status.toLowerCase().includes("syncing"));
  const walletLag = $derived(Math.max(0, targetHeight - blockHeight));
  const providerLag = $derived(Math.max(0, chainTip - targetHeight));

  const stalledMs = $derived(lastWalletProgressAt ? nowTick - lastWalletProgressAt : 0);
  const providerStaleMs = $derived(lastTargetProgressAt ? nowTick - lastTargetProgressAt : 0);

  // A spinner that turns regardless of progress is decoration. But "not advancing"
  // only means something when there is something to advance TO — hence walletLag.
  const scanQuiet = $derived(isSyncing && stalledMs > QUIET_MS && walletLag > 2);
  const stalled = $derived(scanQuiet && stalledMs > STALL_MS);
  const slow = $derived(scanQuiet && !stalled);
  const providerStuck = $derived(providerStaleMs > PROVIDER_STALL_MS && chainTip > 0);

  const eta = $derived(
    blocksPerSec > 0.01 && walletLag > 0 ? Math.round(walletLag / blocksPerSec) : 0
  );

  function fmtEta(secs: number): string {
    if (secs <= 0) return "";
    if (secs < 60) return `~${secs}s`;
    if (secs < 3600) return `~${Math.round(secs / 60)}m`;
    return `~${(secs / 3600).toFixed(1)}h`;
  }

  const cls = $derived(
    status === "Disconnected" || status === "Error"
      ? "disconnected"
      : stalled || providerStuck
        ? "stalled"
        : isSyncing
          ? "syncing"
          : "synced"
  );

  async function updateStatus() {
    try {
      const response: string = await invoke("sync_status");
      const data = JSON.parse(response);

      const now = Date.now();
      if (lastSampleAt > 0 && data.blockHeight > lastWalletHeight) {
        const dt = (now - lastSampleAt) / 1000;
        if (dt > 0) {
          const rate = (data.blockHeight - lastWalletHeight) / dt;
          // Smooth it; a single slow poll should not make the ETA jump around.
          blocksPerSec = blocksPerSec > 0 ? blocksPerSec * 0.6 + rate * 0.4 : rate;
        }
      }
      nowTick = now;
      if (data.blockHeight > lastWalletHeight || !lastWalletProgressAt) lastWalletProgressAt = now;
      if (data.targetHeight > lastTargetHeight || !lastTargetProgressAt) lastTargetProgressAt = now;

      lastWalletHeight = data.blockHeight;
      lastTargetHeight = data.targetHeight;
      lastSampleAt = now;

      status = data.status;
      blockHeight = data.blockHeight;
      targetHeight = data.targetHeight;
      chainTip = data.chainTip ?? data.targetHeight;
      progress = data.progress;
      ipAddress = data.ipAddress || "";
      vendor = data.vendor || "";
      version = data.version || "";
      upgradeName = data.upgradeName || "";
      latencyMs = data.latencyMs ?? 0;
    } catch (e) {
      console.error("Failed to get sync status", e);
      status = "Disconnected";
      blocksPerSec = 0;
    } finally {
      timer = setTimeout(updateStatus, isSyncing ? POLL_SYNCING : POLL_IDLE);
    }
  }

  onMount(() => {
    updateStatus();
    return () => {
      if (timer) clearTimeout(timer);
    };
  });
</script>

<div class="node-status card">
  <div class="header">
    <h2>Network Status</h2>
    <div class="pulse-indicator {cls}"></div>
  </div>

  <div class="status-content">
    <div class="status-row">
      <span class="label">Provider</span>
      <span class="status-text {cls}">
        {#if stalled}Stalled{:else if slow}Syncing slowly{:else if providerStuck}Provider stuck{:else}{status}{/if}
      </span>
    </div>

    {#if status !== 'Disconnected' && status !== 'Error'}
      <div class="status-row">
        <span class="label">Chain tip</span>
        <span class="value">{chainTip.toLocaleString()}</span>
      </div>

      <div class="status-row">
        <span class="label">Provider has</span>
        <span class="value">
          {targetHeight.toLocaleString()}
          {#if providerLag > 0}<em class="lag warn">{providerLag.toLocaleString()} behind chain</em>{/if}
        </span>
      </div>

      <div class="status-row">
        <span class="label">This wallet</span>
        <span class="value">
          {blockHeight.toLocaleString()}
          {#if walletLag > 0}<em class="lag">{walletLag.toLocaleString()} to scan</em>{/if}
        </span>
      </div>

      {#if isSyncing && walletLag > 0}
        <div class="progress-track"><div class="progress-fill" style="width: {progress}%"></div></div>
        <div class="refresh-indicator">
          {#if stalled}
            <span class="warn">No progress for {Math.round(stalledMs / 60000)} min.</span>
          {:else if slow}
            <span class="spinner">↻</span>
            Scanning — last batch {Math.round(stalledMs / 1000)}s ago
          {:else}
            <span class="spinner">↻</span>
            Scanning{#if blocksPerSec > 0.01} · {blocksPerSec.toFixed(1)} blocks/s{/if}{#if eta > 0} · {fmtEta(eta)} left{/if}
          {/if}
        </div>
      {/if}

      {#if providerStuck}
        <div class="refresh-indicator">
          <span class="warn">Provider's height has not advanced. The node it reads from may be stuck.</span>
        </div>
      {/if}
    {:else}
      <button class="btn primary start-btn" onclick={updateStatus}>Reconnect to Provider</button>
    {/if}

    {#if ipAddress}
      <div class="status-row endpoint-row">
        <span class="label">Endpoint</span>
        <span class="value endpoint">{ipAddress}</span>
      </div>
      {#if vendor}
        <div class="status-row">
          <span class="label">Serving</span>
          <span class="value meta">
            {vendor}{#if version} {version}{/if}{#if upgradeName} · {upgradeName}{/if}{#if latencyMs > 0} · {latencyMs}ms{/if}
          </span>
        </div>
      {/if}
    {/if}
  </div>
</div>

<style>
  .lag {
    display: block;
    font-style: normal;
    font-size: 0.75em;
    font-weight: 400;
    color: var(--text-secondary, #9e9e9e);
    margin-top: 0.1rem;
  }
  .lag.warn { color: #ffd600; }
  .warn { color: #ffd600; }
  .status-text.stalled { color: #ffd600; }
  .pulse-indicator.stalled { background: #ffd600; }
  .progress-track {
    height: 4px;
    background: var(--border-color, #2c2c2c);
    border-radius: 2px;
    overflow: hidden;
    margin: 0.6rem 0 0.4rem;
  }
  .progress-fill {
    height: 100%;
    background: #ffd600;
    transition: width 0.4s ease;
  }
  .endpoint-row {
    margin-top: 0.5rem;
    border-top: 1px solid var(--border-color, #333);
    padding-top: 0.75rem;
  }
  .value.endpoint {
    font-size: 0.8em;
    font-weight: 500;
    color: var(--text-secondary);
    word-break: break-all;
    text-align: right;
    max-width: 70%;
  }
  .value.meta {
    font-size: 0.78em;
    font-weight: 400;
    color: var(--text-secondary);
    text-align: right;
  }

  .card {
    background: var(--surface-color, #1e1e1e);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 16px;
    padding: 1.5rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
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

  .pulse-indicator {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: relative;
  }

  .pulse-indicator.synced, .pulse-indicator.synced_to_chain {
    background: #00e676;
    box-shadow: 0 0 8px #00e676;
  }

  .pulse-indicator.syncing {
    background: #ffd600;
    box-shadow: 0 0 8px #ffd600;
  }

  .pulse-indicator.disconnected, .pulse-indicator.error {
    background: #ff3d00;
    box-shadow: 0 0 8px #ff3d00;
  }

  .status-content {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .status-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .label {
    color: var(--text-secondary, #999);
    font-size: 0.95rem;
  }

  .status-text {
    font-weight: 600;
    text-transform: capitalize;
  }

  .status-text.synced, .status-text.synced_to_chain { color: #00e676; }
  .status-text.syncing { color: #ffd600; }
  .status-text.disconnected, .status-text.error { color: #ff3d00; }

  .value {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    color: var(--text-primary, #fff);
    font-weight: 600;
  }

  .progress-bar-container {
    height: 6px;
    background: var(--surface-hover);
    border-radius: 3px;
    overflow: hidden;
    margin-top: 0.5rem;
  }

  .progress-bar {
    height: 100%;
    background: var(--accent-color);
    transition: width 0.3s ease;
  }

  .progress-text {
    font-size: 0.8rem;
    color: var(--text-secondary);
    text-align: right;
    margin-top: -0.25rem;
  }

  .refresh-indicator {
    font-size: 0.85rem;
    color: var(--text-secondary);
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }

  .spinner {
    display: inline-block;
    animation: spin 1s linear infinite;
  }

  @keyframes spin {
    100% { transform: rotate(360deg); }
  }

  .btn.start-btn {
    margin-top: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    border: none;
    background: var(--accent-color);
    color: #fff;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
  }

  .btn.start-btn:hover {
    background: var(--accent-hover);
  }
</style>