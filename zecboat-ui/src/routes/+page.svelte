<script lang="ts">
  import { onMount } from "svelte";
  import { onOpenUrl } from "@tauri-apps/plugin-deep-link";
  import NodeStatus from "$lib/components/NodeStatus.svelte";
  import UpgradeNotice from "$lib/components/UpgradeNotice.svelte";
  import BalanceCard from "$lib/components/BalanceCard.svelte";
  import TransactionHistory from "$lib/components/TransactionHistory.svelte";
  import TransactionsView from "$lib/components/TransactionsView.svelte";
  import ZsaGallery from "$lib/components/ZsaGallery.svelte";
  import SendView from "$lib/components/SendView.svelte";
  import ReceiveView from "$lib/components/ReceiveView.svelte";
  import SettingsView from "$lib/components/SettingsView.svelte";
  import UnlockWallet from "$lib/components/UnlockWallet.svelte";
  import WelcomeWizard from "$lib/components/WelcomeWizard.svelte";
  import RosterView from "$lib/components/RosterView.svelte";
  import CollectionsView from "$lib/components/CollectionsView.svelte";
  // import InvoicesView from "$lib/components/InvoicesView.svelte";
  import PendingBroadcasts from "$lib/components/PendingBroadcasts.svelte";
  import { invoke } from "@tauri-apps/api/core";

  let currentView = $state("Dashboard");
  let appState = $state("Checking"); // Checking, Uninitialized, Locked, Unlocked
  
  let sendProps = $state<{
    initialAssetType?: string,
    initialToAddress?: string,
    initialAmount?: string,
    initialMemo?: string
  }>({});

  function setView(view: string) {
    currentView = view;
  }

  // A global handler to parse zecboat:// URIs
  function handleDeepLink(url: string) {
    // Example: zecboat://pay?address=zs1...&amount=0.1&memo=OrderID:123
    try {
      const parsedUrl = new URL(url);
      if (parsedUrl.protocol === "zecboat:") {
        const address = parsedUrl.searchParams.get("address") || "";
        const amount = parsedUrl.searchParams.get("amount") || "";
        const memo = parsedUrl.searchParams.get("memo") || "";
        
        sendProps = {
          initialAssetType: "ZSA", // Or determine based on logic
          initialToAddress: address,
          initialAmount: amount,
          initialMemo: memo
        };
        setView("Send");
      }
    } catch (e) {
      console.error("Failed to parse deep link URL:", e);
    }
  }

  async function handleLock() {
    try {
      await invoke("lock_wallet");
    } catch (e) {
      console.error("Failed to lock wallet in backend", e);
    }
    appState = "Locked";
  }

  onMount(() => {
    // Restore the saved node endpoint BEFORE anything can start syncing.
    //
    // The Rust side keeps PROVIDER_URL in memory only, so it resets to its
    // compiled-in default (127.0.0.1:9067) on every launch. The restore used to
    // live solely in SettingsView's onMount — which only runs if the user opens
    // Settings. Until then the sync engine hammered the wrong address and every
    // launch began with:
    //
    //   [sync] pass failed: could not reach the node at http://127.0.0.1:9067
    //
    // Doing it here means the endpoint is correct before unlock, so the engine's
    // first pass goes to the right node.
    try {
      const saved = localStorage.getItem("zecboat.provider");
      if (saved) {
        const { url } = JSON.parse(saved);
        if (url) invoke("set_provider_url", { url });
      }
    } catch (e) {
      console.error("Could not restore the saved node endpoint:", e);
    }

    // 0.7.1: whether lineage travels in the transfer (Knotline) is a saved choice too.
    try {
      const route = localStorage.getItem("zecboat.lineage");
      if (route) invoke("set_lineage_route", { route });
    } catch (e) {
      console.error("Could not restore the saved lineage route:", e);
    }

    // 0.7.1: the drop-box for lineage records is a choice too, restored the same way.
    try {
      const box = localStorage.getItem("zecboat.dropbox");
      if (box) invoke("set_dropbox", { choice: box });
    } catch (e) {
      console.error("Could not restore the saved drop-box:", e);
    }

    // Check initial state
    invoke("check_initialization_status").then((initialized) => {
      appState = initialized ? "Locked" : "Uninitialized";
    }).catch((e) => {
      console.error("Failed to check initialization status:", e);
      appState = "Uninitialized";
    });

    // Listen for OS-level deep links
    onOpenUrl((urls) => {
      if (urls.length > 0) {
        handleDeepLink(urls[0]);
      }
    }).catch(console.error);

    // Removed 2026-08-13: a 2-second poll of `check_pending_proposal`, which read
    // ~/.AppVault/data/pending_proposal.json. Nothing writes that file — it
    // belonged to the retired SSH/Galley hand-off from the deadbeef-mock era —
    // so this woke every 2 seconds for the life of the app to read a path that
    // never exists.
  });
</script>

{#if appState === 'Checking'}
  <div class="loading-screen">
    <div class="spinner"></div>
    <p>Loading Zecboat...</p>
  </div>
{:else if appState === 'Uninitialized'}
  <WelcomeWizard onComplete={() => appState = 'Unlocked'} />
{:else if appState === 'Locked'}
  <UnlockWallet onUnlock={() => appState = 'Unlocked'} />
{:else}
  <div class="app-layout">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="logo">
        <img src="/logo.png" alt="Zecboat Logo" class="logo-image" />
      </div>
      <nav>
        <button class="nav-item {currentView === 'Dashboard' ? 'active' : ''}" onclick={() => setView('Dashboard')}>Dashboard</button>
        <button class="nav-item {currentView === 'Send' ? 'active' : ''}" onclick={() => setView('Send')}>Send</button>
        <button class="nav-item {currentView === 'Receive' ? 'active' : ''}" onclick={() => setView('Receive')}>Receive</button>
        <button class="nav-item {currentView === 'Transactions' ? 'active' : ''}" onclick={() => setView('Transactions')}>🧾 Transactions</button>
        <button class="nav-item {currentView === 'Shielded Assets' ? 'active' : ''}" onclick={() => setView('Shielded Assets')}>📦 Shielded Assets</button>
        <button class="nav-item {currentView === 'Collections' ? 'active' : ''}" onclick={() => setView('Collections')}>🔎 Collections</button>
        <button class="nav-item {currentView === 'Roster' ? 'active' : ''}" onclick={() => setView('Roster')}>👥 Roster</button>
        <button class="nav-item {currentView === 'Settings' ? 'active' : ''}" onclick={() => setView('Settings')}>⚙️ Settings</button>
      </nav>
      <div class="sidebar-bottom">
        <NodeStatus />
      </div>
    </aside>

    <!-- Main Content Area -->
    <main class="main-content">
      <header class="top-bar">
        <h2>{currentView}</h2>
        <div class="user-profile">
          <UpgradeNotice compact />
          <button class="lock-btn" onclick={handleLock} title="Lock Wallet">🔒</button>
        </div>
      </header>
      
      <!--
        Unconfirmed transactions, on every view rather than only the Dashboard.
        A signed transaction that never reached the network holds its inputs
        spent; that is not something to find only if you happen to navigate
        somewhere. It renders nothing unless something is actually at risk.

        Mounted inside the unlocked branch, so its first check runs at unlock —
        which is the startup check.
      -->
      <div class="dashboard-grid">
        <PendingBroadcasts />

        {#if currentView === 'Dashboard'}
          <div class="main-col">
            <BalanceCard />
            <TransactionHistory onViewAll={() => setView('Transactions')} />
          </div>
          <div class="side-col">
            <ZsaGallery />
          </div>
        {:else if currentView === 'Send'}
          <div class="full-col">
            <SendView {...sendProps} />
          </div>
        {:else if currentView === 'Receive'}
          <div class="full-col">
            <ReceiveView />
          </div>
        {:else if currentView === 'Transactions'}
          <TransactionsView />
        {:else if currentView === 'Shielded Assets'}
          <div class="full-col">
            <ZsaGallery />
          </div>
        <!-- Invoices removed from the navigation when the in-wallet market was withdrawn
             before release; this branch has been unreachable since, and its two buttons were
             both alert() mocks — "Request Official Verification" claimed a cryptographic proof
             had been sent to zecboat.com and did nothing, and "Export to PDF" described what a
             PDF export would do. Kept commented rather than deleted: if invoices return, the
             layout is worth having. Nothing here works. -->
        <!--
        {:else if currentView === 'Invoices'}
          <div class="full-col">
            <InvoicesView />
          </div>
        -->
        {:else if currentView === 'Collections'}
          <div class="full-col">
            <CollectionsView />
          </div>
        {:else if currentView === 'Roster'}
          <div class="full-col">
            <RosterView />
          </div>
        {:else if currentView === 'Settings'}
          <div class="full-col">
            <SettingsView />
          </div>
        {:else}
          <div class="placeholder-view">
            <h3>{currentView} Module</h3>
            <p>This module is under construction for Phase 3 parity.</p>
          </div>
        {/if}
      </div>
    </main>
  </div>
{/if}

<style>
/* Global Modern Theme Variables */
:global(:root) {
  --bg-color: #171717; /* From zecboat.com --body-color */
  --surface-color: #1e1e1e;
  --surface-hover: #2a2a2a;
  --surface-active: #323232;
  --border-color: #2c2c2c;
  --text-primary: #ffffff;
  --text-secondary: #aaaaaa;
  --accent-color: #1D7989; /* Zecboat link-color */
  --accent-hover: #0E3B43;
  --special-color: #001B4C;

  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  color: var(--text-primary);
  background-color: var(--bg-color);
  -webkit-font-smoothing: antialiased;
}

:global(body) {
  margin: 0;
  padding: 0;
  height: 100vh;
  overflow: hidden;
}

.app-layout {
  display: flex;
  height: 100vh;
  width: 100vw;
}

/* Sidebar Styles */
.sidebar {
  width: 280px;
  background: var(--surface-color);
  border-right: 1px solid var(--border-color);
  display: flex;
  flex-direction: column;
  padding: 1.5rem;
  z-index: 10;
}

.logo {
  display: flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 1.75rem;
}

.logo-image {
  max-width: 100%;
  height: auto;
  max-height: 60px;
}

/* NOT `flex: 1`. That made nav absorb every spare pixel in the sidebar, which — with
   `.sidebar-bottom { margin-top: auto }` — pinned Network Status to the very bottom of the
   window. On a tall window the status sat alone, far below the menu, and the taller the
   window the further away it got. The menu now takes the height it needs and the status
   follows it. */
nav {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.nav-item {
  color: var(--text-secondary);
  background: transparent;
  border: none;
  text-align: left;
  font-family: inherit;
  font-size: 1rem;
  font-weight: 500;
  padding: 0.55rem 1rem;
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.2s;
}

.nav-item:hover {
  background: var(--surface-hover);
  color: var(--text-primary);
}

.nav-item.active {
  background: var(--special-color);
  color: #ffffff;
  font-weight: 600;
}

/* `margin-top: auto` is gone with nav's `flex: 1` — see the note above. Network Status now
   sits just under the last menu item, separated by a rule rather than by empty space, and
   stays visible without scanning to the bottom of the window. `margin-bottom: auto` keeps
   the whole block top-aligned in the column. */
.sidebar-bottom {
  margin-top: 1.25rem;
  margin-bottom: auto;
  padding-top: 1rem;
  border-top: 1px solid var(--border-color);
}

/* Main Content Styles */
.main-content {
  flex: 1;
  display: flex;
  flex-direction: column;
  background: var(--bg-color);
  overflow-y: auto;
}

.top-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 2rem 3rem 1rem 3rem;
  position: sticky;
  top: 0;
  background: rgba(23, 23, 23, 0.8);
  backdrop-filter: blur(12px);
  z-index: 5;
}

.top-bar h2 {
  margin: 0;
  font-size: 1.75rem;
  font-weight: 600;
}

.user-profile {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.lock-btn {
  background: transparent;
  border: none;
  font-size: 1.2rem;
  cursor: pointer;
  padding: 0.5rem;
  border-radius: 8px;
  transition: background 0.2s;
}

.lock-btn:hover {
  background: var(--surface-hover);
}

.avatar {
  background: var(--surface-hover);
  width: 40px;
  height: 40px;
  border-radius: 50%;
  display: flex;
  justify-content: center;
  align-items: center;
  font-size: 1.2rem;
  cursor: pointer;
  border: 1px solid var(--border-color);
}

.dashboard-grid {
  display: grid;
  grid-template-columns: 1fr 350px;
  gap: 2rem;
  padding: 1rem 3rem 3rem 3rem;
  max-width: 1400px;
}

.main-col {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.side-col {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.full-col {
  grid-column: 1 / -1;
}

.placeholder-view {
  grid-column: 1 / -1;
  background: var(--surface-color);
  padding: 3rem;
  border-radius: 16px;
  text-align: center;
  border: 1px dashed var(--border-color);
}

/* Responsive adjustments */
@media (max-width: 1024px) {
  .dashboard-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 768px) {
  .app-layout {
    flex-direction: column;
  }
  .sidebar {
    width: 100%;
    height: auto;
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
    padding: 1rem;
    border-right: none;
    border-bottom: 1px solid var(--border-color);
  }
  .sidebar nav {
    flex-direction: row;
    display: none;
  }
  .sidebar-bottom {
    display: none;
  }
  .top-bar {
    padding: 1rem;
  }
  .dashboard-grid {
    padding: 1rem;
  }
}
</style>