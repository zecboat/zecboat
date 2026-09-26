<script lang="ts">
  import CopyButton from "./CopyButton.svelte";
  import { invoke } from "@tauri-apps/api/core";
  
  let { 
    initialAssetType = "ZEC", 
    initialToAddress = "", 
    initialAmount = "", 
    initialMemo = ""
  } = $props<{
    initialAssetType?: string,
    initialToAddress?: string,
    initialAmount?: string,
    initialMemo?: string
  }>();

  let assetType = $state(initialAssetType);
  let fromAddress = $state("");
  let toAddress = $state(initialToAddress);
  let amount = $state(initialAmount);
  let memo = $state(initialMemo);

  // Roster contacts, so a saved address can be chosen instead of retyped.
  // Without this the Roster stores addresses the Send form cannot reach, which
  // leaves the user copy-pasting a 100+ character UA by hand.
  interface Contact { id: number; name: string; address: string; notes: string; }
  let roster = $state<Contact[]>([]);
  let selectedContactId = $state<string>("");

  $effect(() => {
    invoke<Contact[]>("get_roster")
      .then((r) => { roster = r; })
      .catch((e) => { console.error("Failed to load roster:", e); });
  });

  function pickContact(e: Event) {
    const id = (e.target as HTMLSelectElement).value;
    selectedContactId = id;
    if (!id) return;
    const c = roster.find((x) => String(x.id) === id);
    if (c) toAddress = c.address;
  }

  // Typing over a chosen address should clear the selection, so the dropdown
  // never claims to describe an address that is no longer in the field.
  $effect(() => {
    if (selectedContactId) {
      const c = roster.find((x) => String(x.id) === selectedContactId);
      if (c && c.address !== toAddress) selectedContactId = "";
    }
  });

  $effect(() => {
    assetType = initialAssetType;
    toAddress = initialToAddress;
    amount = initialAmount;
    memo = initialMemo;
  });

  let isSending = $state(false);
  let showConfirmation = $state(false);

  // Wake (chapter 8). An asset send is refused when this wallet holds no lineage proof for
  // the unit and no trusted manifest names its carrier as the issuance output: the recipient
  // would receive it unproven. The backend says so with a WAKE_UNPROVEN: error; the user can
  // acknowledge that and send anyway. Nothing is sent until they do.
  let unprovenNotice = $state<string | null>(null);
  let acknowledgeUnproven = $state(false);

  // Fee readiness -- asked before a send, not discovered during one.
  //
  // A carrier is exactly CARRIER_ZAT = 10,000 zat and the fee cannot come out of it: shaving
  // the carrier would hand the recipient a sub-carrier note and destroy the asset. So the fee
  // must come from ordinary notes, and a wallet holding only carriers cannot send anything.
  //
  // Without this the user meets the backend's raw error --
  //   InsufficientFunds { available: Zatoshis(10000), required: Zatoshis(20000) }
  // -- against a balance this screen is showing as healthy. Unactionable.
  type Fee = {
    spendable_zat: number; carrier_count: number; carrier_zat: number;
    fee_zat: number; can_pay_fee: boolean;
  };
  let fee = $state<Fee | null>(null);
  invoke<Fee>("fee_readiness").then((f) => { fee = f; }).catch(() => { fee = null; });
  const zec = (z: number) => (z / 100_000_000).toFixed(8);
  let useHardwareWallet = $state(false);
  let isWaitingForHardware = $state(false);
  let txResult = $state<{success: boolean, message: string, txid?: string} | null>(null);

  /**
   * The backend returns a human sentence like
   *   Success! Operation ID: Transaction broadcasted successfully! TxID: "4de944..."
   * A copy button should hand over the bare 64-hex txid, not the sentence around it --
   * that is the part someone pastes into an explorer or a forum post.
   */
  function extractTxid(msg: string): string | undefined {
    return msg.match(/\b[0-9a-fA-F]{64}\b/)?.[0];
  }
  let paymentUri = $state("");

  const MAX_MEMO_CHARS = 512;
  let remainingChars = $derived(MAX_MEMO_CHARS - memo.length);

  function handleUriChange() {
    if (paymentUri && paymentUri.toLowerCase().startsWith("zcash:")) {
      try {
        const uriStr = paymentUri.replace(/^zcash:/i, "");
        const [addressPart, queryPart] = uriStr.split("?");
        
        if (addressPart) {
          toAddress = addressPart;
        }

        if (queryPart) {
          const params = new URLSearchParams(queryPart);
          if (params.has("amount")) {
            amount = params.get("amount") || "";
          }
          if (params.has("memo")) {
            const m = params.get("memo") || "";
            try {
              let b64 = m.replace(/-/g, '+').replace(/_/g, '/');
              while (b64.length % 4) b64 += '=';
              memo = decodeURIComponent(escape(atob(b64)));
            } catch {
              memo = m;
            }
          }
          if (params.has("message")) {
            memo = params.get("message") || "";
          }
        }
      } catch (e) {
        console.error("Failed to parse Zcash URI", e);
      }
    }
  }

  function handleReview(e: Event) {
    e.preventDefault();
    if (remainingChars < 0) return;
    showConfirmation = true;
    txResult = null;
  }

  function cancelSend() {
    showConfirmation = false;
    unprovenNotice = null;
    acknowledgeUnproven = false;
  }

  async function confirmAndSend() {
    isSending = true;
    txResult = null;
    
    try {
      if (useHardwareWallet) {
        isWaitingForHardware = true;
        const txData = `amount=${amount}&to=${toAddress}&memo=${memo}`;
        const signature: string = await invoke("sign_transaction_with_hardware", {
          txData: txData
        });
        isWaitingForHardware = false;
        
        txResult = {
          success: true,
          message: `Success! Hardware Signature: ${signature}`
        };
      } else {
        let assetId = assetType === "ZSA" ? fromAddress.trim() : null;
        const opid: string = await invoke("send_transaction", {
          address: toAddress,
          amount: parseFloat(amount),
          memo: memo,
          assetId: assetId || undefined,
          acknowledgeUnproven: assetId ? acknowledgeUnproven : undefined
        });
        
        txResult = {
          success: true,
          message: `Success! Operation ID: ${opid}`,
          txid: extractTxid(opid)
        };
      }
      
      toAddress = "";
      amount = "";
      memo = "";
      showConfirmation = false;
      unprovenNotice = null;
      acknowledgeUnproven = false;
    } catch (err: any) {
      const raw = String(err);
      // Wake: not a failure, a question. Keep the confirmation open with the acknowledgement
      // control so the same review can be resent with it ticked.
      if (raw.includes("WAKE_UNPROVEN:")) {
        unprovenNotice = raw.split("WAKE_UNPROVEN:")[1]?.trim() || raw;
        isSending = false;
        return;
      }
      // Translate the one error users actually hit. The backend message is correct and
      // unreadable; leaving it raw is how "InsufficientFunds" gets reported against a healthy
      // balance with no explanation of why.
      const insufficient = raw.includes("InsufficientFunds");
      txResult = {
        success: false,
        message: insufficient
          ? `Not enough ordinary ZEC to pay the network fee. Shielded assets are carried by ` +
            `notes of exactly 0.00010000 ZEC, and the fee cannot be taken from one without ` +
            `destroying the asset — so it must come from other funds. Add a small amount of ` +
            `ZEC and try again.  (${raw})`
          : `Error: ${raw}`
      };
      showConfirmation = false;
      isWaitingForHardware = false;
    } finally {
      isSending = false;
      isWaitingForHardware = false;
    }
  }
</script>

<div class="send-view card">
  <!-- Stated up front, before anything is typed. Discovering this after composing a
       transaction is the experience this replaces. Shown only when it is actually a
       problem: a wallet with ordinary ZEC never sees it. -->
  {#if fee && !fee.can_pay_fee}
    <div class="fee-warning">
      <strong>Not enough ordinary ZEC to pay a network fee.</strong>
      <span>
        You hold {zec(fee.spendable_zat)} ZEC that can pay a fee, and a fee costs about
        {zec(fee.fee_zat)} ZEC.
        {#if fee.carrier_count > 0}
          Your {fee.carrier_count} shielded asset{fee.carrier_count === 1 ? '' : 's'}
          ({zec(fee.carrier_zat)} ZEC) cannot pay it: each is carried by a note of exactly
          0.00010000 ZEC, and taking the fee from one would destroy the asset.
        {/if}
        Add a small amount of ZEC to send anything from this wallet.
      </span>
    </div>
  {/if}

  {#if !showConfirmation}
    <form onsubmit={handleReview}>
      <div class="form-group slide-in">
        <label for="payment-uri">Zcash Payment URI</label>
        <input id="payment-uri" type="text" placeholder="zcash:zs1..." bind:value={paymentUri} oninput={handleUriChange} />
        <p class="hint" style="color: var(--text-secondary);">Paste a payment URI here to auto-fill the form.</p>
      </div>

      <div class="form-group">
        <label for="asset-type">Asset Type</label>
        <select id="asset-type" bind:value={assetType}>
          <option value="ZEC">ZEC</option>
          <option value="ZSA">ZSA (Shielded Asset)</option>
        </select>
      </div>

      <div class="form-group slide-in">
        <label for="from-address">Sending Address (Source)</label>
        <input id="from-address" type="text" placeholder="Select your source address..." bind:value={fromAddress} required={assetType === "ZSA"} />
        {#if assetType === "ZSA"}
          <p class="hint">ZSA transfers require specifying the exact source address or asset ID.</p>
        {/if}
      </div>
      
      <div class="form-group">
        <div class="label-row">
          <label for="to-address">Recipient Address</label>
          {#if roster.length > 0}
            <select class="roster-picker" value={selectedContactId} onchange={pickContact} aria-label="Choose from Roster">
              <option value="">Choose from Roster…</option>
              {#each roster as c (c.id)}
                <option value={String(c.id)}>{c.name}</option>
              {/each}
            </select>
          {/if}
        </div>
        <input id="to-address" type="text" placeholder="u1… / zs… / t1…" bind:value={toAddress} required />
        {#if selectedContactId}
          {@const c = roster.find((x) => String(x.id) === selectedContactId)}
          {#if c}
            <p class="hint">Sending to <strong>{c.name}</strong>{c.notes ? ` — ${c.notes}` : ""}</p>
          {/if}
        {/if}
      </div>
      
      <div class="form-group">
        <label for="amount">Amount</label>
        <div class="amount-input-wrapper">
          <input id="amount" type="number" step="0.00000001" placeholder="0.00" bind:value={amount} required />
          <span class="currency-tag">{assetType}</span>
        </div>
      </div>

      <div class="form-group slide-in">
        <div class="label-row">
          <label for="memo">Message (Memo)</label>
          <span class="char-counter {remainingChars < 50 ? 'warning' : ''} {remainingChars < 0 ? 'error' : ''}">
            {remainingChars} characters left
          </span>
        </div>
        <textarea id="memo" rows="3" placeholder="Optional shielded memo..." bind:value={memo}></textarea>
      </div>
      
      <button type="submit" class="btn primary" disabled={remainingChars < 0}>
        Review Transaction
      </button>
    </form>
  {:else}
    <div class="confirmation-screen slide-in">
      <h3>Confirm Transaction</h3>
      {#if fee && assetType === "ZSA"}
        <!-- The fee source, on the confirmation screen, because this is the moment someone
             asks "where does the fee come from?" The recipient gets exactly the carrier;
             the fee comes from elsewhere or the asset would be destroyed. -->
        <p class="fee-note">
          The recipient receives the asset's carrier note of exactly 0.00010000 ZEC. The
          network fee of about {zec(fee.fee_zat)} ZEC is paid from your other funds — never
          from the carrier, which would destroy the asset.
        </p>
      {/if}
      
      <div class="confirm-details">
        <div class="detail-row">
          <span class="label">From:</span>
          <span class="value">{fromAddress}</span>
        </div>
        <div class="detail-row">
          <span class="label">To:</span>
          <span class="value">{toAddress}</span>
        </div>
        <div class="detail-row amount-row">
          <span class="label">Amount:</span>
          <span class="value amount-value">{amount} {assetType}</span>
        </div>
        {#if memo}
          <div class="detail-row memo-row">
            <span class="label">Message:</span>
            <span class="value memo-value">{memo}</span>
          </div>
        {/if}
      </div>
      
      <div class="action-buttons">
        <!-- Hidden 2026-09-01: the YubiKey integration is a MOCK — is_yubikey_connected()
             returns true unconditionally and the "hardware" response is a static software
             hash. No key is ever contacted. See zecboat-core/src/yubi.rs. -->
        <!--
        <div class="hardware-toggle">
          <input type="checkbox" id="hardware-wallet" bind:checked={useHardwareWallet} disabled={isSending} />
          <label for="hardware-wallet">Sign with YubiKey</label>
        </div>
        -->
        {#if unprovenNotice}
          <!-- Chapter 8: "send flow refuses a unit with no lading unless the user acknowledges
               'arrives unproven'". The refusal is the default; this is the acknowledgement. -->
          <div class="fee-warning" style="margin-top: 0.75rem;">
            <strong>This unit would arrive unproven.</strong>
            <span>{unprovenNotice}</span>
            <label style="display: flex; gap: 0.5rem; align-items: center; margin-top: 0.5rem; cursor: pointer;">
              <input type="checkbox" bind:checked={acknowledgeUnproven} />
              I understand the recipient receives it without a lineage proof. Send anyway.
            </label>
          </div>
        {/if}
        <button class="btn secondary" onclick={cancelSend} disabled={isSending}>Cancel</button>
        <button class="btn primary" onclick={confirmAndSend} disabled={isSending || (!!unprovenNotice && !acknowledgeUnproven)}>
          {#if isSending}
            <span>Processing...</span>
          {:else}
            <span>Confirm & Send</span>
          {/if}
        </button>
      </div>
    </div>
  {/if}

  {#if txResult}
    <div class="result-message {txResult.success ? 'success' : 'error'}">
      <div>{txResult.message}</div>
      {#if txResult.txid}
        <div class="result-actions">
          <CopyButton value={txResult.txid} label="Copy TxID" title="Copy the transaction id" />
          <CopyButton value={txResult.message} label="Copy full output" compact title="Copy the whole message" />
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .fee-warning {
    display: flex;
    flex-direction: column;
    gap: 0.4rem;
    margin-bottom: 1.25rem;
    padding: 0.85rem 1rem;
    border-radius: 10px;
    border: 1px solid #ffd60055;
    background: #ffd6000f;
    color: var(--text-primary, #fff);
    font-size: 0.9rem;
    line-height: 1.5;
  }
  .fee-warning span { color: var(--text-secondary, #bbb); }
  .fee-note {
    margin: 0 0 1rem;
    font-size: 0.85rem;
    line-height: 1.5;
    color: var(--text-secondary, #999);
  }

  .card {
    background: var(--surface-color, #1e1e1e);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 16px;
    padding: 2rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
    max-width: 600px;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  
  .label-row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
  }

  label, .confirm-details .label {
    font-size: 0.9rem;
    font-weight: 500;
    color: var(--text-secondary);
  }
  
  .char-counter {
    font-size: 0.8rem;
    color: var(--text-secondary);
  }
  
  .char-counter.warning {
    color: #ffd600;
  }

  .char-counter.error {
    color: #ff3d00;
    font-weight: bold;
  }

  .hint {
    font-size: 0.8rem;
    color: var(--accent-color);
    margin: 0;
  }

  /* Sits inline with the "Recipient Address" label, so it reads as an optional
     shortcut rather than a second required field. */
  .roster-picker {
    font-size: 0.8rem;
    padding: 0.2rem 0.4rem;
    width: auto;
    max-width: 45%;
  }

  input, select, textarea {
    background: var(--surface-hover);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    padding: 0.75rem 1rem;
    border-radius: 8px;
    font-size: 1rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    outline: none;
    transition: border-color 0.2s;
    width: 100%;
    box-sizing: border-box;
    resize: vertical;
  }
  
  select {
    appearance: none;
    -webkit-appearance: none;
    -moz-appearance: none;
    background-color: var(--surface-hover);
    color: var(--text-primary);
  }

  input:focus, select:focus, textarea:focus {
    border-color: var(--accent-color);
  }

  select option {
    background-color: #2c2c2c !important;
    color: #ffffff !important;
  }

  .amount-input-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  .amount-input-wrapper input {
    padding-right: 4rem;
  }

  .currency-tag {
    position: absolute;
    right: 1rem;
    color: var(--text-secondary);
    font-weight: 600;
  }

  .btn {
    padding: 1rem 1.5rem;
    border-radius: 8px;
    font-weight: 600;
    font-size: 1.1rem;
    cursor: pointer;
    border: none;
    transition: all 0.2s;
    margin-top: 1rem;
    flex: 1;
  }

  .btn:disabled {
    opacity: 0.7;
    cursor: not-allowed;
  }

  .btn.primary {
    background: var(--accent-color);
    color: #fff;
  }

  .btn.primary:not(:disabled):hover {
    background: var(--accent-hover);
  }

  .btn.secondary {
    background: var(--surface-hover);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
  }

  .btn.secondary:not(:disabled):hover {
    background: var(--surface-active);
  }

  .confirmation-screen {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .confirmation-screen h3 {
    margin: 0;
    font-size: 1.5rem;
    text-align: center;
    color: var(--text-primary);
  }

  .confirm-details {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    background: var(--surface-hover);
    padding: 1.5rem;
    border-radius: 12px;
    border: 1px solid var(--border-color);
  }

  .detail-row {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .detail-row .value {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 1.05rem;
    word-break: break-all;
  }

  .amount-row {
    margin-top: 0.5rem;
    padding-top: 1rem;
    border-top: 1px dashed var(--border-color);
  }

  .amount-value {
    font-size: 1.5rem !important;
    font-weight: bold;
    color: var(--accent-color);
  }

  .memo-row {
    margin-top: 0.5rem;
    padding-top: 1rem;
    border-top: 1px dashed var(--border-color);
  }

  .memo-value {
    font-style: italic;
    color: var(--text-secondary);
  }

  .action-buttons {
    display: flex;
    gap: 1rem;
    align-items: center;
    flex-wrap: wrap;
  }

  .hardware-toggle {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex: 1 1 100%;
    margin-bottom: 0.5rem;
  }

  .hardware-toggle input[type="checkbox"] {
    width: auto;
  }

  .hardware-toggle label {
    cursor: pointer;
    font-size: 1rem;
    color: var(--accent-color);
  }

  .blinking-text {
    animation: blinker 1.5s linear infinite;
  }

  @keyframes blinker {
    50% { opacity: 0.5; }
  }

  .result-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.75rem;
    flex-wrap: wrap;
  }
  .result-message {
    margin-top: 1.5rem;
    padding: 1rem;
    border-radius: 8px;
    font-weight: 500;
    text-align: center;
  }

  .result-message.success {
    background: rgba(0, 230, 118, 0.1);
    color: #00e676;
    border: 1px solid rgba(0, 230, 118, 0.3);
  }

  .result-message.error {
    background: rgba(255, 61, 0, 0.1);
    color: #ff3d00;
    border: 1px solid rgba(255, 61, 0, 0.3);
  }

  .slide-in {
    animation: slideDown 0.3s ease-out forwards;
  }

  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }
</style>