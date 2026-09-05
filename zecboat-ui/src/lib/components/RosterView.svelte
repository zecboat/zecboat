<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  interface Contact {
    id: number;
    name: string;
    address: string;
    notes: string;
  }

  let roster = $state<Contact[]>([]);
  let isLoading = $state(true);
  
  // Add Contact Form State
  let showAddForm = $state(false);
  let newName = $state("");
  let newAddress = $state("");
  let newNotes = $state("");
  let formError = $state("");
  let isSubmitting = $state(false);

  // Profile Drawer State
  let selectedContact = $state<Contact | null>(null);
  let copyFeedback = $state("");

  async function loadRoster() {
    isLoading = true;
    try {
      roster = await invoke<Contact[]>("get_roster");
    } catch (e) {
      console.error("Failed to load roster:", e);
    } finally {
      isLoading = false;
    }
  }

  onMount(() => {
    loadRoster();
  });

  async function handleAddContact(e: Event) {
    e.preventDefault();
    if (!newName.trim() || !newAddress.trim()) {
      formError = "Name and Address are required.";
      return;
    }
    
    formError = "";
    isSubmitting = true;

    // Decode the address rather than checking its prefix. A prefix test accepts
    // "u1garbage" and the contact only fails much later, at send time, after it
    // has been saved and trusted. This calls the same decoder send_transaction
    // uses, so the Roster cannot accept an address a send would reject.
    try {
      await invoke("validate_address", { address: newAddress.trim() });
    } catch (e: any) {
      formError = e.toString();
      isSubmitting = false;
      return;
    }

    try {
      await invoke("add_roster_contact", { 
        name: newName.trim(), 
        address: newAddress.trim(), 
        notes: newNotes.trim() 
      });
      
      // Reset form and reload list
      newName = "";
      newAddress = "";
      newNotes = "";
      showAddForm = false;
      await loadRoster();
    } catch (e: any) {
      formError = e.toString();
    } finally {
      isSubmitting = false;
    }
  }

  async function handleDeleteContact(id: number) {
    if (!confirm("Are you sure you want to remove this contact from your Roster?")) return;
    
    try {
      await invoke("delete_roster_contact", { id });
      if (selectedContact?.id === id) selectedContact = null;
      await loadRoster();
    } catch (e) {
      console.error("Failed to delete contact:", e);
      alert("Failed to delete contact.");
    }
  }

  function openProfile(contact: Contact) {
    selectedContact = contact;
    copyFeedback = "";
  }

  function copyAddress(address: string) {
    navigator.clipboard.writeText(address).then(() => {
      copyFeedback = "Address copied to clipboard!";
      setTimeout(() => copyFeedback = "", 3000);
    });
  }

  // Auto-generate a simple identicon color based on name
  function stringToColor(str: string) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = str.charCodeAt(i) + ((hash << 5) - hash);
    }
    const c = (hash & 0x00FFFFFF).toString(16).toUpperCase();
    return '#' + '00000'.substring(0, 6 - c.length) + c;
  }
</script>

<div class="roster-view">
  <div class="main-panel card">
    <div class="header">
      <div class="title-area">
        <h2>Crew Roster</h2>
        <p class="subtitle">Secure, local address book for your trusted contacts.</p>
      </div>
      <button class="btn primary" onclick={() => showAddForm = !showAddForm}>
        {showAddForm ? 'Cancel' : '➕ Add Contact'}
      </button>
    </div>

    {#if showAddForm}
      <div class="add-form-container slide-down">
        <h3>Add New Crewmate</h3>
        <form onsubmit={handleAddContact}>
          <div class="form-group">
            <label for="c-name">Display Name</label>
            <input id="c-name" type="text" bind:value={newName} placeholder="e.g. Alice or @merchant_dan" />
          </div>
          <div class="form-group">
            <label for="c-address">Unified Address</label>
            <input id="c-address" type="text" bind:value={newAddress} placeholder="u1..." />
          </div>
          <div class="form-group">
            <label for="c-notes">Private Notes (Optional)</label>
            <textarea id="c-notes" bind:value={newNotes} placeholder="Memo template or context about this contact..."></textarea>
          </div>
          
          {#if formError}
            <div class="error-msg">{formError}</div>
          {/if}
          
          <button type="submit" class="btn primary" disabled={isSubmitting}>
            {isSubmitting ? 'Saving...' : 'Save to Roster'}
          </button>
        </form>
      </div>
    {/if}

    <div class="contact-list">
      {#if isLoading}
        <div class="loading-state">
          <div class="spinner"></div>
          <p>Loading roster...</p>
        </div>
      {:else if roster.length === 0}
        <div class="empty-state">
          <div class="empty-icon">👥</div>
          <h3>Your Roster is Empty</h3>
          <p>Add trusted contacts to easily send funds without copy-pasting addresses.</p>
        </div>
      {:else}
        <div class="grid">
          {#each roster as contact}
            <div class="contact-card" onclick={() => openProfile(contact)}>
              <div class="avatar" style="background-color: {stringToColor(contact.name)}">
                {contact.name.charAt(0).toUpperCase()}
              </div>
              <div class="info">
                <h4>{contact.name}</h4>
                <p class="mono-trunc">{contact.address.substring(0, 15)}...</p>
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  </div>

  {#if selectedContact}
    <div class="side-panel card slide-left">
      <div class="panel-header">
        <h3>Contact Profile</h3>
        <button class="icon-btn" onclick={() => selectedContact = null}>✕</button>
      </div>
      
      <div class="profile-content">
        <div class="profile-header">
          <div class="large-avatar" style="background-color: {stringToColor(selectedContact.name)}">
            {selectedContact.name.charAt(0).toUpperCase()}
          </div>
          <h2>{selectedContact.name}</h2>
        </div>

        <div class="detail-section">
          <h4>Unified Address</h4>
          <div class="address-box">
            <span class="full-address">{selectedContact.address}</span>
            <button class="copy-btn" onclick={() => copyAddress(selectedContact!.address)}>📋 Copy</button>
          </div>
          {#if copyFeedback}
            <span class="feedback success">{copyFeedback}</span>
          {/if}
        </div>

        {#if selectedContact.notes}
          <div class="detail-section">
            <h4>Private Notes</h4>
            <div class="notes-box">
              {selectedContact.notes}
            </div>
          </div>
        {/if}

        <div class="action-footer">
          <button class="btn secondary" style="width: 100%; border-color: rgba(255,82,82,0.5); color: #ff5252;" onclick={() => handleDeleteContact(selectedContact!.id)}>
            🗑️ Remove Contact
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .roster-view {
    display: flex;
    gap: 1.5rem;
    height: 100%;
  }

  .card {
    background: var(--surface-color, #1e1e1e);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 16px;
    padding: 1.5rem;
  }

  .main-panel {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }

  .side-panel {
    width: 350px;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    background: linear-gradient(180deg, var(--surface-color) 0%, #151515 100%);
  }

  .header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 1.5rem;
    margin-bottom: 1.5rem;
  }

  .title-area h2 {
    margin: 0 0 0.25rem 0;
    font-size: 1.5rem;
  }

  .subtitle {
    color: var(--text-secondary);
    margin: 0;
    font-size: 0.95rem;
  }

  .btn {
    padding: 0.75rem 1.25rem;
    border-radius: 8px;
    font-weight: 600;
    cursor: pointer;
    border: none;
    transition: all 0.2s;
  }

  .btn.primary {
    background: var(--accent-color, #1D7989);
    color: white;
  }
  .btn.primary:hover:not(:disabled) {
    background: var(--accent-hover, #0E3B43);
  }
  .btn.primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn.secondary {
    background: transparent;
    border: 1px solid var(--border-color);
    color: var(--text-primary);
  }
  .btn.secondary:hover {
    background: var(--surface-hover);
  }

  /* Form Styles */
  .add-form-container {
    background: var(--surface-hover);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 2rem;
    border: 1px solid var(--border-color);
  }

  .add-form-container h3 {
    margin-top: 0;
    margin-bottom: 1rem;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  .form-group label {
    font-size: 0.9rem;
    color: var(--text-secondary);
  }

  input, textarea {
    padding: 0.75rem;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    background: var(--bg-color);
    color: white;
    font-family: inherit;
    resize: vertical;
  }

  input:focus, textarea:focus {
    outline: none;
    border-color: var(--accent-color);
  }

  .error-msg {
    color: #ff5252;
    font-size: 0.9rem;
    margin-bottom: 1rem;
  }

  /* Grid Styles */
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 1rem;
  }

  .contact-card {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem;
    background: var(--surface-hover);
    border-radius: 12px;
    border: 1px solid transparent;
    cursor: pointer;
    transition: all 0.2s;
  }

  .contact-card:hover {
    border-color: var(--accent-color);
    transform: translateY(-2px);
  }

  .avatar {
    width: 48px;
    height: 48px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.5rem;
    font-weight: bold;
    color: white;
    text-shadow: 0 1px 3px rgba(0,0,0,0.3);
  }

  .info h4 {
    margin: 0 0 0.25rem 0;
    font-size: 1.1rem;
  }

  .mono-trunc {
    margin: 0;
    font-family: monospace;
    color: var(--text-secondary);
    font-size: 0.85rem;
  }

  /* Side Panel Styles */
  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 2rem;
  }

  .panel-header h3 {
    margin: 0;
  }

  .icon-btn {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 1.2rem;
    cursor: pointer;
  }
  .icon-btn:hover { color: white; }

  .profile-header {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    margin-bottom: 2rem;
  }

  .large-avatar {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 2.5rem;
    font-weight: bold;
    color: white;
    margin-bottom: 1rem;
  }

  .detail-section {
    margin-bottom: 1.5rem;
  }

  .detail-section h4 {
    margin: 0 0 0.5rem 0;
    color: var(--text-secondary);
    font-size: 0.9rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .address-box, .notes-box {
    background: var(--bg-color);
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    position: relative;
  }

  .full-address {
    font-family: monospace;
    font-size: 0.85rem;
    word-break: break-all;
    line-height: 1.4;
    display: block;
    margin-bottom: 1rem;
  }

  .copy-btn {
    width: 100%;
    padding: 0.5rem;
    background: var(--surface-hover);
    border: 1px solid var(--border-color);
    color: white;
    border-radius: 4px;
    cursor: pointer;
  }
  .copy-btn:hover { background: var(--border-color); }

  .feedback.success {
    display: block;
    color: #4CAF50;
    font-size: 0.85rem;
    margin-top: 0.5rem;
    text-align: center;
  }

  .action-footer {
    margin-top: auto;
    padding-top: 2rem;
  }

  /* States */
  .empty-state, .loading-state {
    text-align: center;
    padding: 4rem 2rem;
    color: var(--text-secondary);
  }

  .empty-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
    opacity: 0.5;
  }

  .spinner {
    width: 40px;
    height: 40px;
    border: 3px solid rgba(255,255,255,0.1);
    border-top-color: var(--accent-color);
    border-radius: 50%;
    animation: spin 1s infinite linear;
    margin: 0 auto 1rem auto;
  }

  /* Animations */
  .slide-down {
    animation: slideDown 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  }
  .slide-left {
    animation: slideLeft 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  }
  
  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-20px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes slideLeft {
    from { opacity: 0; transform: translateX(20px); }
    to { opacity: 1; transform: translateX(0); }
  }

  @media (max-width: 900px) {
    .roster-view {
      flex-direction: column;
    }
    .side-panel {
      width: 100%;
    }
  }
</style>