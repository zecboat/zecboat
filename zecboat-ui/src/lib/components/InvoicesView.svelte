<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  interface Invoice {
    id: string;
    invoice_id: string;
    date: string;
    items: string;
    total_zec: number;
    total_fiat_value: number;
    txid: string;
  }

  let invoices = $state<Invoice[]>([]);
  let isLoading = $state(true);
  let error = $state("");
  let selectedInvoice = $state<Invoice | null>(null);

  async function loadInvoices() {
    isLoading = true;
    error = "";
    try {
      const data: Invoice[] = await invoke("get_invoices");
      invoices = data;
    } catch (e: any) {
      error = "Failed to load invoices from database.";
      console.error(e);
    } finally {
      isLoading = false;
    }
  }

  onMount(() => {
    loadInvoices();
  });

  function selectInvoice(inv: Invoice) {
    selectedInvoice = inv;
  }

  function closeInvoice() {
    selectedInvoice = null;
  }

  // Both of these were alert() mocks describing work that never happened. The
  // verification one was the worse: it told the user a cryptographic proof of their
  // transaction id had been sent to zecboat.com and a signed official receipt returned.
  // Nothing was sent, nothing was signed, nothing was verified.
  //
  // A wallet that claims to have cryptographically verified something it did not is the
  // exact defect this project removes wherever it finds it. Buttons that do nothing are
  // better than buttons that lie about what they did.
  //
  // This whole view is currently unreachable — Invoices was removed from the navigation
  // when the in-wallet market was withdrawn. Left in place so the layout survives if
  // invoices return, with the claims taken out.

  function exportToPDF() {
    alert("Not implemented. Exporting invoices to PDF is not built yet.");
  }

  function verifyInvoice() {
    alert(
      "Not implemented.\n\n" +
      "Nothing is verified by this button and no receipt is issued. " +
      "To check a transaction yourself, look up its id on any Zcash block explorer."
    );
  }
</script>

<div class="invoices-view card">
  <h2>Market Invoices</h2>
  <p class="subtitle">Commercial receipts for your Zecboat.com purchases, securely separated from your raw transaction history.</p>

  {#if isLoading}
    <div class="status-msg">Loading invoices...</div>
  {:else if error}
    <div class="status-msg error">{error}</div>
  {:else if invoices.length === 0}
    <div class="empty-state">
      <div class="icon">🧾</div>
      <p>No market invoices found.</p>
      <p class="hint">When you purchase ZSAs from the market, your receipts will appear here.</p>
    </div>
  {:else}
    <div class="invoice-list">
      <table>
        <thead>
          <tr>
            <th>Date</th>
            <th>Invoice ID</th>
            <th>Items</th>
            <th>Total (ZEC)</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {#each invoices as inv}
            <tr>
              <td>{inv.date}</td>
              <td>{inv.invoice_id}</td>
              <td class="items-col">{inv.items}</td>
              <td class="amount-col">{inv.total_zec} ZEC</td>
              <td>
                <button class="btn btn-secondary btn-sm" onclick={() => selectInvoice(inv)}>View</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  {#if selectedInvoice}
    <div class="modal-backdrop" onclick={closeInvoice}>
      <div class="modal-content invoice-modal" onclick={(e) => e.stopPropagation()}>
        <div class="modal-header">
          <h3>Receipt: {selectedInvoice.invoice_id}</h3>
          <button class="close-btn" onclick={closeInvoice}>✕</button>
        </div>
        <div class="modal-body invoice-body">
          <div class="invoice-header-info">
            <div class="company-info">
              <h2>Zecboat Inc.</h2>
              <p>Decentralized Commerce</p>
            </div>
            <div class="invoice-meta">
              <p><strong>Date:</strong> {selectedInvoice.date}</p>
              <p><strong>Invoice #:</strong> {selectedInvoice.invoice_id}</p>
            </div>
          </div>
          
          <div class="invoice-items">
            <h4>Description</h4>
            <p class="item-desc">{selectedInvoice.items}</p>
          </div>
          
          <div class="invoice-totals">
            <div class="total-row">
              <span>Total Paid (ZEC):</span>
              <strong>{selectedInvoice.total_zec} ZEC</strong>
            </div>
            <div class="total-row fiat-row">
              <span>Estimated Fiat Value at Purchase:</span>
              <strong>${selectedInvoice.total_fiat_value.toFixed(2)} USD</strong>
            </div>
          </div>
          
          <div class="invoice-crypto">
            <h4>Cryptographic Proof</h4>
            <p class="txid"><strong>TxID:</strong> <span>{selectedInvoice.txid}</span></p>
          </div>
          
          <div class="invoice-actions">
            <button class="btn btn-secondary" onclick={exportToPDF}>Export to PDF</button>
            <button class="btn" onclick={verifyInvoice}>Request Official Verification</button>
          </div>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .subtitle {
    color: var(--text-secondary);
    margin-bottom: 2rem;
  }
  
  .empty-state {
    text-align: center;
    padding: 3rem 1rem;
    color: var(--text-secondary);
  }
  .empty-state .icon {
    font-size: 3rem;
    margin-bottom: 1rem;
    opacity: 0.5;
  }
  
  table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 1rem;
  }
  
  th, td {
    padding: 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
  }
  
  th {
    color: var(--text-secondary);
    font-weight: 500;
    text-transform: uppercase;
    font-size: 0.85rem;
    letter-spacing: 0.05em;
  }
  
  .items-col {
    max-width: 250px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  
  .amount-col {
    font-family: monospace;
    font-weight: bold;
    color: var(--secondary-accent-color);
  }
  
  .btn-sm {
    padding: 0.4rem 0.8rem;
    font-size: 0.85rem;
  }
  
  /* Invoice Modal Styles */
  .modal-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
  }

  .modal-content {
    background: var(--surface-color, #1e1e24);
    border: 1px solid var(--border-color, #333);
    border-radius: 16px;
    width: 90%;
    max-height: 90vh;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.5rem;
    border-bottom: 1px solid var(--border-color, #333);
  }

  .modal-header h3 {
    margin: 0;
    color: var(--text-primary, #fff);
  }

  .close-btn {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 1.2rem;
    cursor: pointer;
  }

  .close-btn:hover {
    color: var(--text-primary);
  }

  .invoice-modal {
    max-width: 600px;
    background-color: #fff;
    color: #333;
  }
  
  .invoice-modal .modal-header h3 {
    color: #111;
  }
  
  .invoice-body {
    padding: 2rem;
  }
  
  .invoice-header-info {
    display: flex;
    justify-content: space-between;
    border-bottom: 2px solid #eee;
    padding-bottom: 1.5rem;
    margin-bottom: 1.5rem;
  }
  
  .company-info h2 {
    margin: 0 0 0.5rem 0;
    color: #111;
  }
  
  .invoice-meta p {
    margin: 0.25rem 0;
    text-align: right;
  }
  
  .invoice-items {
    background: #f9f9f9;
    padding: 1.5rem;
    border-radius: 8px;
    margin-bottom: 1.5rem;
  }
  
  .invoice-items h4 {
    margin-top: 0;
    border-bottom: 1px solid #ddd;
    padding-bottom: 0.5rem;
  }
  
  .item-desc {
    font-size: 1.1rem;
    margin-top: 1rem;
  }
  
  .invoice-totals {
    margin-bottom: 2rem;
  }
  
  .total-row {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    font-size: 1.1rem;
  }
  
  .fiat-row {
    color: #666;
    border-top: 1px solid #eee;
    padding-top: 1rem;
    margin-top: 0.5rem;
  }
  
  .invoice-crypto {
    background: #f0f8ff;
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid #bce8f1;
    margin-bottom: 2rem;
  }
  
  .invoice-crypto h4 {
    margin-top: 0;
    color: #31708f;
  }
  
  .txid {
    font-family: monospace;
    word-break: break-all;
    font-size: 0.9rem;
    margin: 0;
  }
  
  .invoice-actions {
    display: flex;
    justify-content: flex-end;
    gap: 1rem;
  }
</style>