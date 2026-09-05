<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  let shieldedBalance = $state(0.00);
  let transparentBalance = $state(0.00);
  let isShielding = $state(false);
  let shieldMsg = $state<{type: 'success'|'error', text: string} | null>(null);

  onMount(() => {
    invoke<number>("get_balance").then(res => {
      shieldedBalance = res;
    }).catch(e => {
      console.error("Failed to get balance", e);
    });

    invoke<number>("get_transparent_balance").then(res => {
      transparentBalance = res;
    }).catch(e => {
      console.error("Failed to get transparent balance", e);
    });
    
    const interval = setInterval(async () => {
      try {
        shieldedBalance = await invoke<number>("get_balance");
        transparentBalance = await invoke<number>("get_transparent_balance");
      } catch (e) {
        console.error("Failed to update balances", e);
      }
    }, 5000);

    return () => clearInterval(interval);
  });

  async function handleShield() {
    isShielding = true;
    shieldMsg = null;
    try {
      const res = await invoke<string>("shield_transparent");
      shieldMsg = { type: 'success', text: res };
    } catch (e: any) {
      shieldMsg = { type: 'error', text: e.toString() };
    } finally {
      isShielding = false;
    }
  }
</script>

<div class="balance-card card gradient-border">
  <div class="header">
    <h2>Total Balance</h2>
    <div class="zcash-icon">ZEC</div>
  </div>
  
  <div class="main-balance">
    <span class="currency">ZEC</span>
    <span class="amount">{(shieldedBalance + transparentBalance).toFixed(4)}</span>
  </div>

  <div class="breakdown">
    <div class="balance-row shielded">
      <div class="label-group">
        <span class="dot shielded-dot"></span>
        <span class="label">Shielded</span>
      </div>
      <span class="value">{shieldedBalance.toFixed(4)}</span>
    </div>
    
    <div class="balance-row transparent">
      <div class="label-group">
        <span class="dot transparent-dot"></span>
        <span class="label">Transparent</span>
      </div>
      <div class="transparent-actions">
        <span class="value">{transparentBalance.toFixed(4)}</span>
        <button class="shield-btn" onclick={handleShield} disabled={isShielding || transparentBalance <= 0}>
          {isShielding ? 'Shielding...' : 'Auto-Shield'}
        </button>
      </div>
    </div>
    
    {#if shieldMsg}
      <div class="msg {shieldMsg.type}">{shieldMsg.text}</div>
    {/if}
  </div>
</div>

<style>
  .card {
    background: var(--surface-color, #1e1e24);
    border-radius: 16px;
    padding: 1.5rem;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
    position: relative;
    overflow: hidden;
  }

  .card::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 4px;
    background: linear-gradient(90deg, #00e676, #00b0ff);
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  h2 {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-secondary, #999);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .zcash-icon {
    background: rgba(255, 255, 255, 0.1);
    color: var(--text-primary, #fff);
    padding: 0.25rem 0.5rem;
    border-radius: 8px;
    font-weight: 700;
    font-size: 0.8rem;
    letter-spacing: 0.1em;
  }

  .main-balance {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
  }

  .currency {
    color: var(--text-secondary, #999);
    font-weight: 600;
    font-size: 1.5rem;
  }

  .amount {
    font-size: 3rem;
    font-weight: 700;
    color: var(--text-primary, #fff);
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    letter-spacing: -0.02em;
  }

  .breakdown {
    background: var(--surface-hover, #2a2a32);
    border-radius: 12px;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .balance-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 1rem;
  }

  .label-group {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }

  .shielded-dot { background: #00e676; box-shadow: 0 0 8px #00e676; }
  .transparent-dot { background: #00b0ff; }

  .transparent-actions {
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .shield-btn {
    background: transparent;
    border: 1px solid #00b0ff;
    color: #00b0ff;
    padding: 0.25rem 0.75rem;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 600;
    cursor: pointer;
    text-transform: uppercase;
    transition: all 0.2s ease;
  }

  .shield-btn:hover:not(:disabled) {
    background: #00b0ff;
    color: #fff;
  }

  .shield-btn:disabled {
    opacity: 0.3;
    cursor: not-allowed;
    border-color: var(--text-secondary, #999);
    color: var(--text-secondary, #999);
  }

  .msg {
    margin-top: 0.5rem;
    padding: 0.75rem;
    border-radius: 8px;
    font-size: 0.85rem;
    font-weight: 500;
    word-break: break-all;
  }

  .msg.success {
    background: rgba(0, 230, 118, 0.1);
    color: #00e676;
    border: 1px solid rgba(0, 230, 118, 0.2);
  }

  .msg.error {
    background: rgba(255, 85, 85, 0.1);
    color: #ff5555;
    border: 1px solid rgba(255, 85, 85, 0.2);
  }

  .label {
    color: var(--text-primary, #fff);
    font-weight: 500;
  }

  .value {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-weight: 600;
    color: var(--text-primary, #fff);
  }
</style>