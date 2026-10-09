<script lang="ts">
  import LineageDelivery from "./LineageDelivery.svelte";
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
  // The YubiKey plugin's status line while a send decrypts the identity (null unless a
  // sealed wallet is waiting for a touch). See UnlockWallet.
  let yubiMsg = $state<string | null>(null);
  let yubiPoll: ReturnType<typeof setInterval> | null = null;
  $effect(() => {
    if (isSending && !yubiPoll) {
      yubiPoll = setInterval(async () => {
        try { yubiMsg = await invoke<string | null>("yubikey_message"); } catch { yubiMsg = null; }
      }, 250);
    } else if (!isSending && yubiPoll) {
      clearInterval(yubiPoll); yubiPoll = null; yubiMsg = null;
    }
  });
  let showConfirmation = $state(false);

  // A sealed wallet needs the key for every send, not only for unlocking (the identity is
  // opened again on each send). So the review step says "insert the key" while it is out and
  // keeps Confirm disabled until it is in; the button then says "touch" when the plugin asks.
  let yubikeyWallet = $state(false);
  let yubikeyPresent = $state(false);
  let keyPoll: ReturnType<typeof setInterval> | null = null;
  $effect(() => {
    if (showConfirmation && !keyPoll) {
      invoke<boolean>("wallet_uses_yubikey").then(v => { yubikeyWallet = v; }).catch(() => { yubikeyWallet = false; });
      const check = async () => { try { yubikeyPresent = await invoke<boolean>("check_yubikey"); } catch { yubikeyPresent = false; } };
      check();
      keyPoll = setInterval(check, 1000);
    } else if (!showConfirmation && keyPoll) {
      clearInterval(keyPoll); keyPoll = null;
    }
  });

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
  // A send whose real fee came out above the estimate shown: the figure to confirm.
  let feeNotice = $state<{ fee_zat: number; text: string } | null>(null);
  // Who answers the chain questions a lineage proof needs, shown on the confirmation.
  let chainSource = $state<string | null>(null);
  invoke<{ choice: string; source: string }>("get_chain_source")
    .then((c) => { chainSource = c.choice === "node" ? "your own node" : c.choice === "provider" ? "your provider" : "your node when it answers, else your provider"; })
    .catch(() => { chainSource = null; });
  let acceptedFeeZat = $state<number | null>(null);
  // A send refused because the unit's memo commits to a lading not collected yet.
  let uncollectedNotice = $state<{ hash: string; text: string } | null>(null);
  let abandonLineage = $state(false);
  invoke<Fee>("fee_readiness").then((f) => { fee = f; }).catch(() => { fee = null; });
  // What this particular item's send will carry and cost (0.7.1). The flat figure above is the
  // fee of a plain two-output transfer; a transfer that carries lineage has more outputs, and
  // the confirmation screen quoted 0.0002 while the wallet went on to pay 0.0007 or 0.0017.
  type SendEstimate = { lineage: "none" | "knot" | "start" | "whole"; proofs: number; extra_outputs: number; outputs: number; fee_zat: number; carrier: string; copies: number };
  let estimate = $state<SendEstimate | null>(null);
  // Why no estimate could be made (the send would refuse for the same reason), or null.
  let estimateError = $state<string | null>(null);
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
          // ZIP 321: `message` is a label for the payer, `memo` is what is sent. Until
          // 2026-10-09 a `message` silently replaced the memo, and unknown required
          // parameters were ignored (review, session 4, Issue H).
          if (params.has("message") && !params.has("memo")) {
            memo = params.get("message") || "";
          }
          for (const k of params.keys()) {
            if (k.startsWith("req-")) {
              throw new Error(`this payment request needs "${k}", which Zecboat does not support`);
            }
          }
        }
      } catch (e) {
        // A request this wallet cannot honour is said, not logged: a required parameter it
        // does not support, or a malformed address part.
        txResult = { success: false, message: `Payment request not accepted: ${String((e as any)?.message ?? e)}` };
      }
    }
  }

  function handleReview(e: Event) {
    e.preventDefault();
    if (remainingChars < 0) return;
    estimate = null;
    estimateError = null;
    if (assetType === "ZSA" && fromAddress.trim()) {
      invoke<SendEstimate>("asset_send_estimate", { assetId: fromAddress.trim() })
        .then((e) => { estimate = e; estimateError = null; })
        .catch((e) => { estimate = null; estimateError = String((e as any)?.message ?? e); });
    }
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
          acknowledgeUnproven: assetId ? acknowledgeUnproven : undefined,
          // The fee this screen showed; a higher real fee comes back as a question, below.
          maxFeeZat: assetId ? (acceptedFeeZat ?? estimate?.fee_zat ?? undefined) : undefined,
          abandonLineage: assetId ? abandonLineage : undefined
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
      feeNotice = null;
      acceptedFeeZat = null;
      uncollectedNotice = null;
      abandonLineage = false;
    } catch (err: any) {
      const raw = String(err);
      // Wake: not a failure, a question. Keep the confirmation open with the acknowledgement
      // control so the same review can be resent with it ticked.
      if (raw.includes("WAKE_UNPROVEN:")) {
        unprovenNotice = raw.split("WAKE_UNPROVEN:")[1]?.trim() || raw;
        isSending = false;
        return;
      }
      // The real fee is above the one shown: not a failure, a question. Show the real figure
      // on the same confirmation and send again with it accepted (review 2026-10-09).
      // The memo commits to a lineage this wallet never collected. Not "no lineage": it exists.
      // The default is to collect it; abandoning is a separate choice under its own warning.
      if (raw.includes("WAKE_UNCOLLECTED:")) {
        const h = raw.split("WAKE_UNCOLLECTED:")[1]?.slice(0, 64) ?? "";
        uncollectedNotice = { hash: h, text: raw.split(`${h}:`)[1]?.trim() || raw };
        isSending = false;
        return;
      }
      const feeChanged = raw.match(/FEE_CHANGED:(\d+):/);
      if (feeChanged) {
        feeNotice = { fee_zat: Number(feeChanged[1]), text: raw.split(feeChanged[0])[1]?.trim() || raw };
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
          network fee of {estimate ? zec(estimate.fee_zat) : `about ${zec(fee.fee_zat)}`} ZEC is paid from your other funds — never
          from the carrier, which would destroy the asset.
        </p>
        {#if estimateError}
          <p class="fee-note">✗ {estimateError}</p>
        {/if}
        {#if estimate && estimate.lineage !== "none"}
          <!-- One line: what travels with the item, so the higher fee has its reason beside it. -->
          <p class="fee-note">
            {#if estimate.lineage === "knot"}
              ⛓ Its lineage travels in this transfer: one knot, proof {estimate.proofs}.
            {:else if estimate.lineage === "start"}
              ⛓ Its lineage travels in this transfer: this item starts its Knotline with {estimate.proofs} proof{estimate.proofs === 1 ? "" : "s"}, once.
            {:else}
              ⛓ Its lineage travels in this transfer: {estimate.proofs} proof{estimate.proofs === 1 ? "" : "s"}.
            {/if}
            <span class="fee-note" style="display:block; opacity: 0.8;">Written to the chain for good, under a key the new owner receives; the Knotline and Wake are awaiting external review (KNOTLINE-v1 §12).</span>
          </p>
        {/if}
        {#if estimate && fee.spendable_zat < estimate.fee_zat}
          <p class="fee-note" style="color: #fbbf24;">
            ⚠ Spendable ZEC {zec(fee.spendable_zat)} is less than this fee.
          </p>
        {/if}
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
        {#if assetType === "ZSA"}
          <!-- Exactly one unit moves, carried by its 0.0001 ZEC note, with its own memo; the
               amount and message fields do not apply and are not sent (review 2026-10-09). -->
          <div class="detail-row amount-row">
            <span class="label">Sends:</span>
            <span class="value amount-value">1 unit (its 0.00010000 ZEC carrier note and its memo){#if estimate && estimate.copies > 1}: copy {estimate.carrier} of the {estimate.copies} this wallet holds, the one whose lineage checks out best{/if}</span>
          </div>
          {#if chainSource}
            <div class="detail-row">
              <span class="label">Chain answers from:</span>
              <span class="value">{chainSource}</span>
            </div>
          {/if}
        {:else}
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
        {/if}
      </div>
      
      {#if yubikeyWallet}
        <div class="yubikey-gate" class:ready={yubikeyPresent}>
          {#if yubikeyPresent}
            🔑 YubiKey in · after Confirm, touch it when the button says so
          {:else}
            🔑 Insert your YubiKey to send · this wallet is sealed to it
          {/if}
        </div>
      {/if}

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
        {#if uncollectedNotice}
          <div class="fee-warning" style="margin-top: 0.75rem;">
            <strong>This unit's lineage has not been collected.</strong>
            <span>Its memo commits to lineage record {uncollectedNotice.hash.slice(0, 16)}…, which exists and can usually be collected: open the item and press "Collect its lineage now", then send again.</span>
            <label style="display: flex; gap: 0.5rem; align-items: center; margin-top: 0.5rem; cursor: pointer;">
              <input type="checkbox" bind:checked={abandonLineage} />
              Abandon this unit's lineage for good. The record cannot be attached later; every future owner receives it unproven.
            </label>
          </div>
        {/if}
        {#if feeNotice}
          <!-- The real fee came out above the estimate shown (the estimate counts outputs, the
               fee counts the notes that pay it too). Not a failure: the real figure, and the
               same button sends at it (review 2026-10-09). -->
          <div class="fee-warning" style="margin-top: 0.75rem;">
            <strong>The network fee is {(feeNotice.fee_zat / 1e8).toFixed(8)} ZEC, not {((acceptedFeeZat ?? estimate?.fee_zat ?? 0) / 1e8).toFixed(8)} as shown.</strong>
            <span>{feeNotice.text}</span>
          </div>
        {/if}
        <button class="btn secondary" onclick={cancelSend} disabled={isSending}>Cancel</button>
        <button class="btn primary" onclick={() => { if (feeNotice) { acceptedFeeZat = feeNotice.fee_zat; feeNotice = null; } confirmAndSend(); }} disabled={isSending || (!!unprovenNotice && !acknowledgeUnproven) || (!!uncollectedNotice && !abandonLineage) || (yubikeyWallet && !yubikeyPresent) || (assetType === "ZSA" && !estimate)}>
          {#if isSending && yubiMsg}
            <span>👉 {yubiMsg}</span>
          {:else if isSending}
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
      {#if txResult.success && txResult.txid}
        <!-- 0.7.1: whether the lineage record of an asset send reached the recipient's
             drop-box. Renders nothing for a ZEC send, which has no such record. -->
        <LineageDelivery txid={txResult.txid} />
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
  .yubikey-gate {
    margin: 0.75rem 0 0.25rem;
    padding: 0.6rem 0.8rem;
    border-radius: 8px;
    background: rgba(245, 158, 11, 0.12);
    border: 1px solid rgba(245, 158, 11, 0.5);
    font-size: 0.9rem;
  }
  .yubikey-gate.ready {
    background: rgba(16, 185, 129, 0.1);
    border-color: rgba(16, 185, 129, 0.5);
  }
</style>