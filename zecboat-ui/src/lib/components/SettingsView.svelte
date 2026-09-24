<script lang="ts">
  import CopyButton from "./CopyButton.svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  // About panel. Everything here is either public or a path the user already owns -- no
  // secret is rendered. The build hash lets someone compare what they are running against
  // SHA256SUMS without opening a terminal, and the pinned keys make the Design Verified
  // badge's "a key pinned in this wallet" claim inspectable instead of taken on trust.
  type About = {
    version: string; build_hash: string; build_hash_caveat: string; executable: string;
    wallet_db: string; node: string; registry: string;
    pinned_issuers: { range: string; key: string }[];
    release_key: string; does_not: string[];
  };
  let about = $state<About | null>(null);
  invoke<About>("wallet_about").then((a) => { about = a; }).catch(() => { about = null; });

  // Where the wallet streams compact blocks from. Every option speaks the same
  // lightwalletd gRPC protocol (CompactTxStreamer); only the host differs.
  type NodePreset = {
    id: string;
    label: string;
    url: string;
    detail: string;
    editable?: boolean;
  };

  const NODE_PRESETS: NodePreset[] = [
    {
      id: "public",
      label: "zec.rocks (public)",
      // Must serve Ironwood (NU6.3). A node that does not will report a ZERO
      // balance for funds that are really there, which reads as data loss.
      // zec.rocks verified serving Ironwood 2026-08-26.
      url: "https://zec.rocks:443",
      detail: "A public lightwalletd. Works immediately with no setup — but the operator sees which blocks you ask for, which narrows down which addresses are yours."
    },
    {
      id: "local",
      label: "Local node",
      url: "http://127.0.0.1:9067",
      detail: "zebrad + zainod on this machine. Full sovereignty, nothing leaves the box. Requires running your own node."
    },
    {
      id: "custom",
      label: "Custom",
      url: "",
      detail: "Any lightwalletd-compatible gRPC endpoint — including a zainod elsewhere on your LAN.",
      editable: true
    }
  ];

  // Two presets were removed here, both for the same reason: they were true for
  // the machine this was written on and false for everyone else.
  //
  //   "Zecboat Port" (https://port.zecboat.com:9067) — retired hosted infrastructure.
  //   Shipping it points new users at a host that need not exist, and a node preset
  //   that silently fails looks like a broken wallet.
  //
  //   "Local node (LAN)" (http://192.168.1.2:8137) — a hardcoded private address.
  //   Nobody else's zainod is at that IP, so it could only ever fail. A LAN node is
  //   a Custom URL, which is what Custom is for.

  const STORAGE_KEY = "zecboat.provider";

  // A new user has no node of their own, so the wallet must work on first run.
  let selectedPreset = $state("public");
  let nodeUrl = $state(NODE_PRESETS[0].url);
  let customUrl = $state("");
  let isTestingNode = $state(false);

  let actionFeedback = $state<{type: 'success' | 'info' | 'error', message: string, detail?: string, copyValue?: string} | null>(null);
  let nodeFeedback = $state<{type: 'success' | 'info' | 'error', message: string, detail?: string} | null>(null);
  let showImportInput = $state(false);
  let importSeed = $state("");
  // null = scan from Sapling activation, the "I don't know" answer that cannot silently
  // lose funds. Import previously hardcoded 3,364,599 (Aug 2025) with a comment admitting
  // any older seed would under-report — the literal "zero balance, funds are really there"
  // outcome, by design. Restore has offered this choice all along; import did not.
  let importBirthday = $state<number | null>(null);
  let isImporting = $state(false);
  // Import REPLACES the wallet on this machine. The user has to say so explicitly;
  // see the warning block in the markup for why a plain button was not enough.
  let importAcknowledged = $state(false);

  let showRestoreInput = $state(false);
  let backupsList = $state<string[]>([]);
  let selectedBackup = $state("");
  let isRestoring = $state(false);

  // The Rust side keeps PROVIDER_URL in memory only, so it resets to its default
  // on every app start. Re-apply the user's saved choice on mount.
  onMount(async () => {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (!saved) {
      // No stored choice. Do NOT leave the screen showing "public" — the backend may
      // have resolved something else entirely from ZECBOAT_PROVIDER, and a Settings
      // panel that names the wrong node is worse than one that names none: it is the
      // screen a user opens specifically to find out where their wallet is talking.
      try {
        const current = (await invoke<string>("get_provider_url"))?.trim() ?? "";
        if (!current) return;
        const preset = NODE_PRESETS.find(p => p.url === current);
        nodeUrl = current;
        selectedPreset = preset ? preset.id : "custom";
        if (!preset) customUrl = current;
      } catch (e) {
        console.error("Could not read the current node endpoint:", e);
      }
      return;
    }
    try {
      const { presetId, url } = JSON.parse(saved);

      // Never trust a stored id. Presets get renamed and removed between versions,
      // and an id that matches nothing leaves every button unselected and the
      // Custom field hidden — a settings screen with no way to tell what is in use
      // and no way to change it. Map anything unknown onto something valid.
      let restored = NODE_PRESETS.some(p => p.id === presetId) ? presetId : null;

      if (!restored) {
        if (presetId === "port") {
          // Zecboat Port, retired. Its URL points at a host that no longer answers,
          // so carrying the address over would only produce a wallet stuck on
          // "Disconnected". Move to the public node instead.
          restored = "public";
          nodeUrl = NODE_PRESETS.find(p => p.id === "public")!.url;
          await invoke("set_provider_url", { url: nodeUrl });
          localStorage.setItem(STORAGE_KEY, JSON.stringify({ presetId: restored, url: nodeUrl }));
          selectedPreset = restored;
          return;
        }
        // "lan", or anything else: the address itself is still perfectly valid,
        // it simply has no preset any more. That is what Custom is for.
        restored = "custom";
      }

      selectedPreset = restored;
      nodeUrl = url;
      if (selectedPreset === "custom") customUrl = url;
      await invoke("set_provider_url", { url });
    } catch {
      // Corrupt entry — fall back to the default rather than blocking startup.
      localStorage.removeItem(STORAGE_KEY);
    }
  });

  function choosePreset(preset: NodePreset) {
    selectedPreset = preset.id;
    nodeUrl = preset.editable ? customUrl : preset.url;
    nodeFeedback = null;
  }

  $effect(() => {
    if (selectedPreset === "custom") nodeUrl = customUrl;
  });

  // Apply the URL, then actually prove the node answers instead of assuming it.
  async function saveNodeConnection() {
    const target = nodeUrl.trim();
    if (!target) {
      nodeFeedback = { type: 'error', message: "Enter a node URL first." };
      return;
    }

    isTestingNode = true;
    nodeFeedback = { type: 'info', message: `Connecting to ${target}...` };

    try {
      await invoke("set_provider_url", { url: target });

      // sync_status performs a real GetLightdInfo against the endpoint. It
      // reports targetHeight 0 / "Disconnected" when the node is unreachable,
      // so this is a genuine reachability check, not a timer.
      const raw = await invoke<string>("sync_status");
      const status = JSON.parse(raw);

      if (!status.targetHeight || status.status === "Disconnected") {
        nodeFeedback = {
          type: 'error',
          message: `No response from ${target}`,
          detail: selectedPreset === "local"
            ? "Is the node running and reachable at that address? Check zebrad and zainod, or try a public lightwalletd."
            : "The node did not answer a GetLightdInfo request. Check the address and that the host is up."
        };
        return;
      }

      localStorage.setItem(STORAGE_KEY, JSON.stringify({ presetId: selectedPreset, url: target }));
      nodeFeedback = {
        type: 'success',
        message: `Connected to ${target}`,
        detail: `Node at block ${status.targetHeight.toLocaleString()} · wallet at ${Number(status.blockHeight).toLocaleString()} (${status.status})`
      };
    } catch (e: any) {
      nodeFeedback = { type: 'error', message: `Failed to connect: ${e}` };
    } finally {
      isTestingNode = false;
    }
  }

  let isWaitingForYubiKey = $state(false);

  async function handleAction(action: string) {
    if (action === 'Import Keys') {
      showImportInput = true;
      showRestoreInput = false;
      importAcknowledged = false;
      actionFeedback = null;
      return;
    }
    
    if (action === 'Restore Backup') {
      showRestoreInput = true;
      showImportInput = false;
      actionFeedback = null;
      try {
        backupsList = await invoke<string[]>("list_backups");
        if (backupsList.length > 0) {
            selectedBackup = backupsList[0];
        }
      } catch (e: any) {
        actionFeedback = { type: 'error', message: `Failed to list backups: ${e}` };
      }
      return;
    }

    if (action === 'Setup YubiKey') {
      isWaitingForYubiKey = true;
      actionFeedback = { type: 'info', message: 'Please touch your YubiKey to register it.' };
      return;
    }

    actionFeedback = { type: 'info', message: `Processing: ${action}...` };
    
    try {
      // 'Create New Wallet' was removed on 2026-09-03. It called
      // initialize_new_wallet with the literal password "default-password" — a
      // constant in published source — then moved the user's real wallet aside and
      // replaced it with one anyone holding the source could open. One click, no
      // confirmation, from inside an unlocked session.
      //
      // Creating a wallet belongs on the unlock screen, where it now asks for a
      // password twice and walks the seed backup and verification. There is no
      // reason to offer it again behind a login the user has already passed.
      if (action === 'Create New Account') {
        const res: string = await invoke("create_new_account");
        actionFeedback = { type: 'success', message: res };
      } else if (action === 'Backup Wallet') {
        const res: string = await invoke("backup_wallet");
        actionFeedback = { type: 'success', message: res };
      } else if (action === 'Export Keys') {
        const res: string = await invoke("export_keys");
        // copyValue is the key itself, so the button never copies the surrounding prose.
        actionFeedback = { type: 'success', message: res, copyValue: res };
      } else if (action === 'Get Viewkey') {
        const res: string = await invoke("get_viewkey");
        actionFeedback = { type: 'success', message: 'Full Viewing Key generated safely!', detail: res, copyValue: res };
      } else if (action === 'Remove YubiKey') {
        actionFeedback = { type: 'success', message: 'YubiKey removed from wallet configuration. Database re-encrypted with standard password.' };
      }
    } catch (e: any) {
      actionFeedback = { type: 'error', message: `Failed: ${e}` };
    }
  }

  async function confirmImport() {
    if (!importSeed.trim()) return;
    // Belt and braces: the button is already disabled without this, but the guard is
    // cheap and the action is not reversible from inside the app.
    if (!importAcknowledged) return;

    isImporting = true;
    actionFeedback = { type: 'info', message: 'Replacing wallet, deriving keys and starting a rescan...' };

    try {
      await invoke("import_wallet", { seed: importSeed.trim(), birthday: importBirthday });
      // Say what actually happened. The old message ("successfully imported") did not
      // mention that a wallet had just been replaced, which is the part that matters.
      actionFeedback = {
        type: 'success',
        message: 'Wallet replaced from seed phrase. Rescan started.',
        detail: 'Your previous wallet database was not deleted \u2014 it was renamed to wallet.db.replaced-<timestamp> in ~/.AppVault/data.'
      };
      showImportInput = false;
      importSeed = "";
      importAcknowledged = false;
    } catch (e: any) {
      actionFeedback = { type: 'error', message: `Import Failed: ${e}` };
    } finally {
      isImporting = false;
    }
  }

  async function confirmRestore() {
    if (!selectedBackup) return;
    
    isRestoring = true;
    actionFeedback = { type: 'info', message: 'Restoring database from backup...' };
    
    try {
      const res: string = await invoke("restore_backup", { backupName: selectedBackup });
      actionFeedback = { type: 'success', message: res, detail: "Please completely restart the Zecboat application to load the restored database." };
      showRestoreInput = false;
    } catch (e: any) {
      actionFeedback = { type: 'error', message: `Restore Failed: ${e}` };
    } finally {
      isRestoring = false;
    }
  }
  function simulateYubikeyTouch() {
    isWaitingForYubiKey = false;
    actionFeedback = { type: 'success', message: 'YubiKey 2FA Enabled! Database re-encrypted with hardware challenge-response.' };
  }
</script>

<div class="settings-view">
  
  <div class="settings-section card">
    <h3>Node Connection</h3>
    <p class="desc">
      Choose where Zecboat streams compact blocks from. Your keys never leave this machine either
      way &mdash; the node only sees which blocks you ask for.
    </p>

    <div class="preset-list">
      {#each NODE_PRESETS as preset}
        <button
          type="button"
          class="preset"
          class:selected={selectedPreset === preset.id}
          onclick={() => choosePreset(preset)}
        >
          <span class="radio" aria-hidden="true"></span>
          <span class="preset-body">
            <span class="preset-label">
              {preset.label}
              {#if preset.id === "public"}<span class="badge">works out of the box</span>{/if}
              {#if preset.id === "local"}<span class="badge">most private</span>{/if}
            </span>
            <span class="preset-detail">{preset.detail}</span>
            {#if !preset.editable}
              <span class="preset-url">{preset.url}</span>
            {/if}
          </span>
        </button>
      {/each}
    </div>

    {#if selectedPreset === "custom"}
      <div class="input-group slide-in" style="margin-top: 1rem;">
        <label for="node-url">Node URL</label>
        <input
          id="node-url"
          type="text"
          placeholder="http://127.0.0.1:9067"
          bind:value={customUrl}
        />
      </div>
    {/if}

    <button
      class="btn primary"
      style="width: 100%; margin-top: 1rem;"
      onclick={saveNodeConnection}
      disabled={isTestingNode || !nodeUrl.trim()}
    >
      {isTestingNode ? "Connecting..." : "Connect"}
    </button>

    {#if nodeFeedback}
      <div class="feedback-banner {nodeFeedback.type}" style="margin-top: 1rem;">
        <p class="main-msg">{nodeFeedback.message}</p>
        {#if nodeFeedback.detail}
          <p class="sub-msg">{nodeFeedback.detail}</p>
        {/if}
      </div>
    {/if}
  </div>

  <div class="settings-section card">
    <h3>Wallet Management</h3>
    <p class="desc">Manage your wallet keys, accounts, and backups securely.</p>
    
    {#if showImportInput}
      <div class="import-section slide-in">
        <div class="destructive-warning">
          <strong>This replaces the wallet on this machine.</strong>
          <p>
            The seed phrase you enter becomes the only wallet Zecboat uses here. The wallet
            currently open &mdash; its accounts, addresses and transaction history &mdash; is
            moved aside and will no longer appear in the app.
          </p>
          <p>
            Nothing is deleted: the existing database is renamed to
            <code>wallet.db.replaced-&lt;timestamp&gt;</code> in <code>~/.AppVault/data</code>.
            Getting back to it means renaming that file by hand.
          </p>
          <p>
            <strong>Do not continue unless you have this wallet's own seed phrase written
            down.</strong> Replacing it without one is how funds are lost.
          </p>
        </div>
        <label for="import-seed">Enter the 24-word seed phrase to use instead</label>
        <textarea id="import-seed" rows="3" placeholder="abandon abandon abandon..." bind:value={importSeed}></textarea>
        <label for="import-bday">Scan from (optional)</label>
        <input id="import-bday" type="number" min="0" placeholder="leave empty to scan everything"
               bind:value={importBirthday} disabled={isImporting} />
        <p class="hint">
          Leave this empty unless you know the block your wallet was created at. Empty scans
          from Sapling activation — slowest, and it cannot miss funds. A height set later than
          a block your funds arrived in means that block is never scanned and the wallet shows
          zero for money that is really there.
        </p>
        <label class="ack-line">
          <input type="checkbox" bind:checked={importAcknowledged} disabled={isImporting} />
          <span>I understand this replaces the wallet currently on this machine.</span>
        </label>
        <div class="import-actions">
          <button class="btn secondary" onclick={() => { showImportInput = false; importAcknowledged = false; }} disabled={isImporting}>Cancel</button>
          <button class="btn danger" onclick={confirmImport} disabled={isImporting || !importSeed.trim() || !importAcknowledged}>
            {isImporting ? "Replacing..." : "Replace Wallet"}
          </button>
        </div>
      </div>
    {:else if showRestoreInput}
      <div class="import-section slide-in">
        <label for="restore-file">Select Database Backup File</label>
        {#if backupsList.length === 0}
          <p class="desc" style="color: #ff3d00;">No backups found in ~/ZecboatBackups</p>
        {:else}
          <select id="restore-file" bind:value={selectedBackup}>
            {#each backupsList as backup}
              <option value={backup}>{backup}</option>
            {/each}
          </select>
        {/if}
        <div class="import-actions">
          <button class="btn secondary" onclick={() => showRestoreInput = false} disabled={isRestoring}>Cancel</button>
          <button class="btn primary" onclick={confirmRestore} disabled={isRestoring || backupsList.length === 0}>
            {isRestoring ? "Restoring..." : "Restore Database"}
          </button>
        </div>
      </div>
    {:else}
      <div class="action-grid">
        <button class="btn action-btn" onclick={() => handleAction('Create New Account')}>👥 Create New Account</button>
        <button class="btn action-btn" onclick={() => handleAction('Backup Wallet')}>💾 Backup Wallet</button>
        <button class="btn action-btn" onclick={() => handleAction('Restore Backup')}>🔄 Restore Backup</button>
        <button class="btn action-btn" onclick={() => handleAction('Import Keys')}>♻️ Replace Wallet with Seed</button>
        <button class="btn action-btn" onclick={() => handleAction('Export Keys')}>📤 Export Keys</button>
        <button class="btn action-btn" onclick={() => handleAction('Get Viewkey')}>👁️ Get Viewkey</button>
      </div>
    {/if}

    {#if actionFeedback}
      <div class="feedback-banner {actionFeedback.type}">
        <p class="main-msg">{actionFeedback.message}</p>
        {#if actionFeedback.detail}
          <pre class="detail-box">{actionFeedback.detail}</pre>
        {/if}
        {#if actionFeedback.copyValue}
          <CopyButton value={actionFeedback.copyValue} label="Copy" title="Copy to clipboard" />
        {/if}
      </div>
    {/if}
  </div>

  <div class="settings-section card">
    <h3>About this wallet</h3>
    {#if about}
      <div class="about-grid">
        <span class="about-label">Version</span>
        <span class="about-value">{about.version}</span>

        <span class="about-label">Build</span>
        <span class="about-value mono">
          {about.build_hash.slice(0, 32)}…
          <CopyButton value={about.build_hash} label="Copy" compact title="Copy the full build hash" />
        </span>

        <span class="about-label">Wallet data</span>
        <span class="about-value mono">{about.wallet_db}</span>

        <span class="about-label">Node</span>
        <span class="about-value mono">{about.node}</span>

        <span class="about-label">Registry</span>
        <span class="about-value mono">{about.registry}</span>
      </div>

      <!-- Shipped with the hash, not hidden behind it. A build that can lie about its own
           hash is exactly the case a user needs told about, and stating it is the difference
           between a useful field and a false one. -->
      <p class="about-note">{about.build_hash_caveat}</p>

      <h4>Issuer keys pinned in this build</h4>
      <p class="about-note">
        The Design Verified badge checks signatures against these keys, compiled in. They are
        never fetched, so a compromised website cannot change which issuers this wallet trusts.
        Changing them takes a new release.
      </p>
      <div class="about-grid">
        {#each about.pinned_issuers as p}
          <span class="about-label">{p.range}</span>
          <span class="about-value mono">{p.key.slice(0, 32)}…
            <CopyButton value={p.key} label="Copy" compact title="Copy the full key" />
          </span>
        {/each}
        <span class="about-label">Release signing</span>
        <span class="about-value mono">{about.release_key.slice(0, 32)}…
          <CopyButton value={about.release_key} label="Copy" compact title="Copy the full key" />
        </span>
      </div>

      <!-- "What this wallet does not do" was here. Removed 2026-09-22 at the owner's
           direction: the limits belong in ZMAP-v0.3 §13 and on the website, not on a
           settings panel a holder opens to check a build hash. `wallet_about` still
           returns `does_not`, so nothing downstream breaks and the text has one home
           rather than two that can drift apart. -->
    {:else}
      <p class="about-note">Reading build information…</p>
    {/if}
  </div>

  <!-- Security section hidden 2026-09-01. Every control here operated a MOCK: no YubiKey
       is ever contacted, and "Simulate Physical Touch" is exactly what it says. Telling a
       user their wallet is protected from physical access and keyloggers when it is not is
       the most damaging thing this interface could do. See zecboat-core/src/yubi.rs. -->
  <!--
  <div class="settings-section card">
    <h3>Security</h3>
    <p class="desc">Manage hardware security tokens like YubiKey to protect your wallet from physical access and keyloggers.</p>
    <div class="action-grid">
      <button class="btn action-btn" onclick={() => handleAction('Setup YubiKey')}>🔐 Setup YubiKey 2FA</button>
      <button class="btn action-btn" onclick={() => handleAction('Remove YubiKey')} style="color: #ff5252; border-color: rgba(255, 82, 82, 0.3);">🗑️ Remove YubiKey</button>
    </div>
    
    {#if isWaitingForYubiKey}
      <div class="yubikey-animation">
        <div class="yk-indicator blinking"></div>
      </div>
      <button type="button" class="btn primary" style="background: #4CAF50; margin-top: 1rem;" onclick={simulateYubikeyTouch}>
        Simulate Physical Touch
      </button>
    {/if}
  </div>
  -->
</div>

<style>
  .settings-view {
    display: flex;
    flex-direction: column;
    gap: 2rem;
    max-width: 800px;
  }

  .card {
    background: var(--surface-color, #1e1e1e);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 16px;
    padding: 1.5rem 2rem;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
  }

  .about-grid {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.45rem 1rem;
    align-items: baseline;
    margin: 0.75rem 0;
  }
  .about-label { color: var(--text-secondary, #999); font-size: 0.85rem; }
  .about-value { color: var(--text-primary, #fff); font-size: 0.9rem; word-break: break-all; }
  .about-value.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.82rem; }
  .about-note {
    color: var(--text-secondary, #999);
    font-size: 0.82rem;
    line-height: 1.55;
    margin: 0.5rem 0 0;
  }
  .about-list {
    margin: 0.5rem 0 0;
    padding-left: 1.1rem;
    color: var(--text-secondary, #bbb);
    font-size: 0.85rem;
    line-height: 1.6;
  }
  .about-list li { margin-bottom: 0.4rem; }
  h4 {
    margin: 1.5rem 0 0;
    font-size: 0.95rem;
    color: var(--text-primary, #fff);
  }

  h3 {
    margin-top: 0;
    margin-bottom: 0.5rem;
    font-size: 1.25rem;
    font-weight: 600;
  }

  .desc {
    color: var(--text-secondary);
    font-size: 0.9rem;
    margin-bottom: 1.5rem;
  }

  .input-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    margin-bottom: 1.5rem;
  }

  label {
    font-size: 0.9rem;
    font-weight: 500;
    color: var(--text-secondary);
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
  }
  
  select {
    appearance: none;
    -webkit-appearance: none;
    -moz-appearance: none;
    background-color: var(--surface-hover);
    color: var(--text-primary);
  }

  select option {
    background-color: #2c2c2c !important;
    color: #ffffff !important;
  }

  textarea {
    resize: vertical;
    margin-bottom: 1rem;
  }

  input:focus, select:focus, textarea:focus {
    border-color: var(--accent-color);
  }

  .btn {
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    font-weight: 600;
    font-size: 1rem;
    cursor: pointer;
    border: none;
    transition: all 0.2s;
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

  .action-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
  }

  .action-btn {
    background: var(--surface-hover);
    color: var(--text-primary);
    border: 1px solid var(--border-color);
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }
  
  .action-btn.full-width {
    grid-column: 1 / -1;
  }

  .action-btn:hover {
    background: var(--surface-active);
    border-color: var(--text-secondary);
  }

  .import-section {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    background: var(--surface-hover);
    padding: 1.5rem;
    border-radius: 12px;
    border: 1px solid var(--border-color);
  }

  .import-actions {
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
  }

  /* Replacing the wallet is not undoable from inside the app, so it does not get
     to look like the buttons beside it. */
  .destructive-warning {
    border: 1px solid #b3261e;
    border-left-width: 4px;
    border-radius: 8px;
    padding: 0.9rem 1rem;
    margin-bottom: 0.5rem;
    background: rgba(179, 38, 30, 0.08);
    font-size: 0.9rem;
    line-height: 1.45;
  }

  .destructive-warning p {
    margin: 0.55rem 0 0;
  }

  .destructive-warning code {
    font-size: 0.85em;
    padding: 0.05rem 0.3rem;
    border-radius: 4px;
    background: var(--surface-active, rgba(0, 0, 0, 0.15));
  }

  .ack-line {
    display: flex;
    align-items: flex-start;
    gap: 0.55rem;
    margin: 0.35rem 0 0.25rem;
    font-size: 0.9rem;
    cursor: pointer;
  }

  .ack-line input {
    margin-top: 0.15rem;
    flex-shrink: 0;
  }

  .btn.danger {
    background: #b3261e;
    border-color: #b3261e;
    color: #fff;
  }

  .btn.danger:hover:not(:disabled) {
    background: #8c1d18;
    border-color: #8c1d18;
  }

  .btn.danger:disabled {
    opacity: 0.5;
  }

  .slide-in {
    animation: slideDown 0.3s ease-out forwards;
  }

  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .feedback-banner {
    margin-top: 1.5rem;
    padding: 1rem;
    border-radius: 8px;
    font-size: 0.95rem;
    text-align: center;
  }
  
  .main-msg {
    margin: 0;
    font-weight: 500;
  }

  .sub-msg {
    margin: 0.5rem 0 0;
    font-size: 0.85rem;
    opacity: 0.85;
    line-height: 1.4;
  }

  .preset-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }

  .preset {
    display: flex;
    align-items: flex-start;
    gap: 0.85rem;
    width: 100%;
    text-align: left;
    padding: 1rem;
    border-radius: 12px;
    background: var(--surface-hover);
    border: 1px solid var(--border-color);
    color: var(--text-primary);
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s;
    font: inherit;
  }

  .preset:hover {
    background: var(--surface-active);
    border-color: var(--text-secondary);
  }

  .preset.selected {
    border-color: var(--accent-color);
    background: color-mix(in srgb, var(--accent-color) 10%, var(--surface-hover));
  }

  .radio {
    flex: 0 0 auto;
    width: 16px;
    height: 16px;
    margin-top: 0.2rem;
    border-radius: 50%;
    border: 2px solid var(--text-secondary);
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  .preset.selected .radio {
    border-color: var(--accent-color);
    box-shadow: inset 0 0 0 3px var(--accent-color);
  }

  .preset-body {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    min-width: 0;
  }

  .preset-label {
    font-weight: 600;
    font-size: 0.95rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .badge {
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.15rem 0.45rem;
    border-radius: 999px;
    background: rgba(0, 230, 118, 0.15);
    color: #00e676;
  }

  .preset-detail {
    font-size: 0.85rem;
    color: var(--text-secondary);
    line-height: 1.4;
  }

  .preset-url {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.8rem;
    color: var(--text-secondary);
    opacity: 0.8;
    word-break: break-all;
  }

  .detail-box {
    margin-top: 1rem;
    background: rgba(0,0,0,0.2);
    padding: 1rem;
    border-radius: 8px;
    text-align: left;
    white-space: pre-wrap;
    word-break: break-all;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 0.85rem;
  }

  .feedback-banner.success {
    background: rgba(0, 230, 118, 0.1);
    color: #00e676;
    border: 1px solid rgba(0, 230, 118, 0.3);
  }

  .feedback-banner.info {
    background: rgba(0, 176, 255, 0.1);
    color: #00b0ff;
    border: 1px solid rgba(0, 176, 255, 0.3);
  }
  
  .feedback-banner.error {
    background: rgba(255, 61, 0, 0.1);
    color: #ff3d00;
    border: 1px solid rgba(255, 61, 0, 0.3);
  }

  .yubikey-animation {
    display: flex;
    justify-content: center;
    margin: 1rem 0;
  }

  .yk-indicator {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background-color: #333;
    border: 3px solid #4CAF50;
    box-shadow: 0 0 10px rgba(76, 175, 80, 0.5);
  }

  .yk-indicator.blinking {
    animation: pulse 1.5s infinite;
  }

  @keyframes pulse {
    0% { transform: scale(0.95); opacity: 0.7; box-shadow: 0 0 0 0 rgba(76, 175, 80, 0.7); }
    70% { transform: scale(1.05); opacity: 1; box-shadow: 0 0 0 10px rgba(76, 175, 80, 0); }
    100% { transform: scale(0.95); opacity: 0.7; box-shadow: 0 0 0 0 rgba(76, 175, 80, 0); }
  }
</style>