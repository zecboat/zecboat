<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";
  import SeedBackup from "$lib/components/SeedBackup.svelte";

  let { onUnlock } = $props<{ onUnlock: () => void }>();
  let seedPhrase = $state("");
  let isUnlocking = $state(false);
  let errorMsg = $state("");
  let showPassword = $state(false);
  let useYubikey = $state(false);
  let yubikeyDetected = $state(false);

  // Whether THIS wallet directory is sealed to a YubiKey. Asked of the backend rather
  // than remembered in the UI: the stub file beside the wallet is the only authority,
  // and a wallet that moved between machines must still open correctly.
  let yubikeyWallet = $state(false);
  // Only true when a key carrying an age identity is really attached. Gates the create
  // checkbox, so the option appears exactly when it can be honoured.
  let yubikeyCreateAvailable = $state(false);

  onMount(async () => {
    try {
      yubikeyCreateAvailable = await invoke<boolean>("check_yubikey");
      yubikeyWallet = await invoke<boolean>("wallet_uses_yubikey");
      // A YubiKey wallet asks for the PIV PIN, not a password. The distinction matters:
      // three wrong PINs block the device, and someone who thinks they are guessing at a
      // password will keep guessing.
      if (yubikeyWallet) yubikeyDetected = await invoke<boolean>("check_yubikey");
    } catch (e) {
      console.error(e);
    }
  });

  async function handleUnlock(e: Event) {
    e.preventDefault();
    if (!seedPhrase.trim()) {
      errorMsg = "Please enter your wallet password.";
      return;
    }

    await performUnlock();
  }

  // What the YubiKey plugin is waiting for right now ("touch"), shown in place of
  // "Decrypting..." so the touch comes when the key is actually listening. Null for a
  // password wallet, so polling it is harmless there.
  let yubiMsg = $state<string | null>(null);

  async function performUnlock() {
    isUnlocking = true;
    errorMsg = "";
    yubiMsg = null;
    const poll = setInterval(async () => {
      try { yubiMsg = await invoke<string | null>("yubikey_message"); } catch { yubiMsg = null; }
    }, 250);
    
    try {
      await invoke("unlock_wallet", { password: seedPhrase.trim(), useYubikey });
      isUnlocking = false;
      onUnlock();
    } catch (e: any) {
      isUnlocking = false;
      errorMsg = e.toString();
    } finally {
      clearInterval(poll);
      yubiMsg = null;
    }
  }

  function togglePasswordVisibility() {
    showPassword = !showPassword;
  }

  // Restore from seed phrase — the path back in when the password is lost.
  //
  // Before this existed the 24 words the wizard insists you write down had no
  // route into the application at all: unlock needs the password, "restore
  // backup" restores a database encrypted with that same password, and "create
  // new wallet" makes a NEW seed. The backup the app demands could not be used.
  // One disclosure rather than three buttons on the unlock screen. Labelled
  // "Wallet options", NOT "New Wallet": two of the three are recovery, and a
  // locked-out user hunting for their funds will not click something that reads
  // as 'start over'.
  let showOptions = $state(false);
  let createdSeed = $state("");
  // null = use the chain tip, which is right for a new seed.
  let newWalletBirthday = $state<number | null>(null);
  let showCreateNew = $state(false);
  let showNewBirthday = $state(false);
  let newPassword = $state("");
  let newPassword2 = $state("");
  let showSeedRestore = $state(false);
  let recoverySeed = $state("");
  let recoveryPassword = $state("");
  let recoveryPassword2 = $state("");
  let recoveryBirthday = $state<number | null>(null);
  let isRecovering = $state(false);

  // Heights the user might actually mean, so nobody has to know their birthday
  // in blocks. "I don't know" maps to the SAFEST option, not the fastest — that
  // is the case this control exists for.
  const BIRTHDAY_PRESETS = [
    { label: "I don't know / oldest", height: 419_200,   note: "Sapling activation — scans everything, slowest, never misses funds" },
    { label: "Orchard era",           height: 1_687_104, note: "NU5 — only if this wallet never held funds before then" },
    { label: "Zecboat wallet",        height: 3_428_143, note: "Ironwood (NU6.3) — only if this seed was created by Zecboat" },
  ];

  // One panel at a time, opened by name. Each explains itself when opened rather
  // than on the unlock screen — three paragraphs of consequence stacked under the
  // password box is a wall nobody reads, and it pushed the buttons off the fold.
  function openPanel(which: "seed" | "backup" | "new") {
    errorMsg = "";
    const wasOpen =
      (which === "seed" && showSeedRestore) ||
      (which === "backup" && showRestoreInput) ||
      (which === "new" && showCreateNew);
    showSeedRestore = false;
    showRestoreInput = false;
    showCreateNew = false;
    if (wasOpen) return;              // clicking the open one closes it
    if (which === "seed") showSeedRestore = true;
    if (which === "new") showCreateNew = true;
    if (which === "backup") handleRestoreClick();
  }

  async function confirmSeedRestore() {
    errorMsg = "";
    const words = recoverySeed.trim().split(/\s+/).filter(Boolean);
    if (words.length !== 24) {
      // Count only. Never echo the phrase or name which word is wrong — that
      // tells anyone holding a partial phrase what they still need.
      errorMsg = `A recovery phrase is 24 words. You entered ${words.length}.`;
      return;
    }
    if (!recoveryPassword) {
      errorMsg = "Choose a password. It encrypts the recovered wallet on this machine.";
      return;
    }
    if (recoveryPassword !== recoveryPassword2) {
      errorMsg = "The two passwords do not match.";
      return;
    }

    isRecovering = true;
    try {
      const height = await invoke<number>("recover_wallet_from_seed", {
        seed: words.join(" "),
        password: recoveryPassword,
        birthday: recoveryBirthday,
      });
      // Clear the phrase from memory as soon as it is no longer needed.
      recoverySeed = ""; recoveryPassword = ""; recoveryPassword2 = "";
      setupMsg = {
        type: 'success',
        text: `Wallet recovered. Scanning from block ${height.toLocaleString()} — `
            + `this can take a while on first run. Your previous wallet was moved `
            + `aside, not deleted.`
      };
      showSeedRestore = false;
      onUnlock();
    } catch (e) {
      errorMsg = String(e);
    } finally {
      isRecovering = false;
    }
  }

  let showRestoreInput = $state(false);
  let backupsList = $state<string[]>([]);
  let selectedBackup = $state("");
  let isRestoring = $state(false);
  let isCreating = $state(false);
  let setupMsg = $state<{type: 'success' | 'error', text: string} | null>(null);

  // Was: fired immediately on click, using whatever sat in the UNLOCK password box.
  // On a machine that already had a wallet, one click replaced it — preserved aside,
  // but with no warning and no confirmation. It now has its own password fields and
  // a panel that says what is about to happen.
  async function handleCreateNew() {
    if (!newPassword) {
      errorMsg = "Choose a password for the new wallet.";
      return;
    }
    if (newPassword !== newPassword2) {
      errorMsg = "The two passwords do not match.";
      return;
    }
    
    isCreating = true;
    errorMsg = "";
    setupMsg = null;
    
    try {
      const seed = await invoke<string>("initialize_new_wallet", { password: newPassword, useYubikey, birthday: newWalletBirthday });
      // Into the backup flow — grid, copy, and a 3-word check — rather than a
      // single status line shown once. This phrase is the only way back into the
      // wallet that was just created.
      newPassword = ""; newPassword2 = "";
      showCreateNew = false;
      createdSeed = seed;
    } catch (e: any) {
      errorMsg = e.toString();
    } finally {
      isCreating = false;
    }
  }

  async function handleRestoreClick() {
    showRestoreInput = !showRestoreInput;
    if (showRestoreInput) {
      try {
        backupsList = await invoke<string[]>("list_backups");
        if (backupsList.length > 0) {
          selectedBackup = backupsList[0];
        }
      } catch (e: any) {
        errorMsg = "Failed to load backups";
      }
    }
  }

  async function confirmRestore() {
    if (!selectedBackup) return;
    isRestoring = true;
    errorMsg = "";
    try {
      const res = await invoke<string>("restore_backup", { backupName: selectedBackup });
      setupMsg = { type: 'success', text: res + " Please restart Zecboat to load the database." };
      showRestoreInput = false;
    } catch (e: any) {
      errorMsg = e.toString();
    } finally {
      isRestoring = false;
    }
  }
</script>

<div class="unlock-container">
  <div class="unlock-card">
    <div class="logo-wrapper">
      <img src="/logo.png" alt="Zecboat Logo" class="logo" />
    </div>
    
    <h2>Unlock Your Wallet</h2>
    {#if yubikeyWallet}
      <p class="subtitle">
        This wallet is sealed to a YubiKey. Insert it and enter its PIN, then touch the key
        <strong>only when this screen says so</strong> (its light blinks). A touch before that
        does nothing useful.
        {#if !yubikeyDetected}
          <strong>No YubiKey detected.</strong>
        {/if}
      </p>
    {:else}
      <p class="subtitle">Enter your wallet password to decrypt and access your funds.</p>
    {/if}

    <form onsubmit={handleUnlock}>
      <div class="input-group">
        <div class="password-wrapper">
          <input
            type={showPassword ? "text" : "password"}
            placeholder={yubikeyWallet ? "YubiKey PIN..." : "Wallet Password..."}
            bind:value={seedPhrase}
          />
          <button type="button" class="visibility-btn" onclick={togglePasswordVisibility}>
            {showPassword ? "🙈" : "👁️"}
          </button>
        </div>
      </div>
      
      <!-- Hidden 2026-09-01. This was the most misleading control in the application:
           the status indicator read "● Detected" whether or not a key was present,
           because check_yubikey() returns true unconditionally. A user could plug in
           nothing, be told a hardware token was detected, and believe their wallet was
           protected by it. See zecboat-core/src/yubi.rs. -->
      <!--
      <div class="yubikey-toggle">
        <label>
          <input type="checkbox" bind:checked={useYubikey} />
          Use YubiKey Hardware Token
        </label>
        {#if yubikeyDetected}
          <span class="status-indicator active">● Detected</span>
        {:else}
          <span class="status-indicator">○ Waiting...</span>
        {/if}
      </div>
      -->
      
      {#if errorMsg}
        <div class="error-msg">{errorMsg}</div>
      {/if}

      <button type="submit" class="btn primary" disabled={isUnlocking || isCreating || isRestoring}>
        {#if isUnlocking && yubiMsg}
          <span class="spinner"></span> 👉 {yubiMsg}
        {:else if isUnlocking}
          <span class="spinner"></span> Decrypting...
        {:else}
          🔓 Unlock Wallet
        {/if}
      </button>
    </form>
    
    {#if setupMsg}
      <div class="status-msg {setupMsg.type}">
        {setupMsg.text}
      </div>
    {/if}

    <!-- Options live inside the card; every PANEL is a modal rendered outside it.
         .unlock-card carries `animation: fadeIn` whose keyframes use
         `transform: translateY(...)`, and a transformed element becomes the
         containing block for `position: fixed` descendants. A modal nested here
         has its `inset: 0` resolved against the 480px card instead of the
         viewport, which is why inputs and buttons had nowhere to go. -->
    {#if !createdSeed}
      <button class="disclosure-btn" onclick={() => (showOptions = !showOptions)}>
        {showOptions ? "▾" : "▸"} Wallet options
      </button>

      {#if showOptions}
        <div class="options">
          <button class="soft-btn" onclick={() => openPanel('seed')} disabled={isRecovering}>Restore from Seed Phrase</button>
          <button class="soft-btn" onclick={() => openPanel('backup')} disabled={isRestoring}>Restore from Backup</button>
          <button class="soft-btn" onclick={() => openPanel('new')} disabled={isCreating}>Create a New Wallet</button>
        </div>
      {/if}
    {/if}
  </div>
</div>

{#if showSeedRestore}
  <div class="modal-backdrop" role="presentation" onclick={() => (showSeedRestore = false)}>
    <div class="modal" role="dialog" aria-modal="true" aria-label="Restore from seed phrase"
         tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
      <div class="modal-head">
        <h3>Restore from seed phrase</h3>
        <p>Enter the 24 words from this wallet's backup. Sets a new password.</p>
      </div>
      <div class="modal-body">
        <label for="seed-words">Recovery phrase — 24 words</label>
        <textarea id="seed-words" rows="3" autocomplete="off" autocapitalize="none"
                  spellcheck="false" placeholder="word word word …" bind:value={recoverySeed}></textarea>
        <label for="rec-pw">New password</label>
        <input id="rec-pw" type="password" autocomplete="new-password" bind:value={recoveryPassword} />
        <label for="rec-pw2">Confirm password</label>
        <input id="rec-pw2" type="password" autocomplete="new-password" bind:value={recoveryPassword2} />
        <label for="rec-bday">Scan from</label>
        <select id="rec-bday" bind:value={recoveryBirthday}>
          {#each BIRTHDAY_PRESETS as bp}
            <option value={bp.height}>{bp.label} — {bp.height.toLocaleString()}</option>
          {/each}
        </select>
        <p class="hint">A later block scans faster but <strong>misses funds received before it</strong>. Unsure? Leave it oldest.</p>
        <p class="hint">Your existing wallet is moved aside, not deleted.</p>
        {#if errorMsg}<p class="modal-err">{errorMsg}</p>{/if}
      </div>
      <div class="modal-foot">
        <button class="btn secondary" onclick={() => (showSeedRestore = false)} disabled={isRecovering}>Cancel</button>
        <button class="btn primary" onclick={confirmSeedRestore} disabled={isRecovering}>
          {isRecovering ? "Recovering…" : "Restore wallet"}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if showCreateNew}
  <div class="modal-backdrop" role="presentation" onclick={() => (showCreateNew = false)}>
    <div class="modal" role="dialog" aria-modal="true" aria-label="Create a new wallet"
         tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
      <div class="modal-head">
        <h3>Create a new wallet</h3>
        <p>Generates a new 24-word seed. <strong>This does not recover an existing wallet</strong> —
           if you lost your password, use Restore from Seed Phrase.</p>
      </div>
      <div class="modal-body">
        <label for="new-pw">Password</label>
        <input id="new-pw" type="password" autocomplete="new-password" bind:value={newPassword} />
        <label for="new-pw2">Confirm password</label>
        <input id="new-pw2" type="password" autocomplete="new-password" bind:value={newPassword2} />
        <label for="new-bday">Scan from (optional)</label>
        <input id="new-bday" type="number" min="0" placeholder="leave empty for the current chain tip"
               bind:value={newWalletBirthday} />
        <p class="hint">A new seed has no history, so this starts at the chain tip. Lowering it only costs scanning time.</p>
        <p class="hint">Any wallet already here is moved aside, not deleted.</p>

        <!-- Restored 2026-09-23, after the mock behind it was replaced with a real age
             plugin. The control was hidden on 2026-09-01 because check_yubikey() returned
             true unconditionally, so it read "● Detected" with nothing plugged in.
             It is now shown ONLY when a key carrying an age identity is actually present:
             an option that cannot be honoured should not be offerable. -->
        {#if yubikeyCreateAvailable}
          <label class="yubikey-opt">
            <input type="checkbox" bind:checked={useYubikey} />
            Seal this wallet to the YubiKey that is plugged in
          </label>
          <p class="hint">
            The wallet identity is encrypted to the device and can only be opened with it,
            using its PIV PIN instead of a password. <strong>This protects the identity
            file, not the spend</strong> — Zcash spend authorization is RedPallas over
            Pallas and no YubiKey implements it. Keep your 24-word seed: it is the only way
            back in if the key is lost.
          </p>
        {/if}
        {#if errorMsg}<p class="modal-err">{errorMsg}</p>{/if}
      </div>
      <div class="modal-foot">
        <button class="btn secondary" onclick={() => (showCreateNew = false)} disabled={isCreating}>Cancel</button>
        <button class="btn primary" onclick={handleCreateNew} disabled={isCreating}>
          {isCreating ? "Creating…" : "Create wallet"}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if showRestoreInput}
  <div class="modal-backdrop" role="presentation" onclick={() => (showRestoreInput = false)}>
    <div class="modal" role="dialog" aria-modal="true" aria-label="Restore from backup"
         tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
      <div class="modal-head">
        <h3>Restore from backup</h3>
        <p>Reopens a saved database file. Needs the password it was created with.</p>
      </div>
      <div class="modal-body">
        {#if backupsList.length === 0}
          <p class="hint">No backups found in ~/ZecboatBackups</p>
        {:else}
          <label for="restore-file">Backup file</label>
          <select id="restore-file" bind:value={selectedBackup}>
            {#each backupsList as backup}<option value={backup}>{backup}</option>{/each}
          </select>
        {/if}
        {#if errorMsg}<p class="modal-err">{errorMsg}</p>{/if}
      </div>
      <div class="modal-foot">
        <button class="btn secondary" onclick={() => (showRestoreInput = false)} disabled={isRestoring}>Cancel</button>
        <button class="btn primary" onclick={confirmRestore} disabled={isRestoring || backupsList.length === 0}>
          {isRestoring ? "Restoring…" : "Restore database"}
        </button>
      </div>
    </div>
  </div>
{/if}

{#if createdSeed}
  <div class="modal-backdrop" role="presentation">
    <div class="modal" role="dialog" aria-modal="true" aria-label="Back up your seed phrase" tabindex="-1">
      <div class="modal-body">
        <SeedBackup
          seedPhrase={createdSeed}
          onComplete={() => {
            createdSeed = "";
            setupMsg = { type: 'success', text: "Wallet created. Unlock it with the password you just set." };
          }}
        />
      </div>
    </div>
  </div>
{/if}

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    z-index: 1200;
    background: rgba(0, 0, 0, 0.72);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1rem;
  }

  .modal {
    background: var(--surface-color, #1e1e1e);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 14px;
    width: 100%;
    max-width: 440px;
    /* Bounded, and a flex COLUMN so the three parts divide the space. */
    max-height: 90vh;
    display: flex;
    flex-direction: column;
    text-align: left;
  }

  .modal-head { padding: 1rem 1.15rem 0.6rem; flex-shrink: 0; }
  .modal-head h3 { margin: 0 0 .3rem; font-size: 1rem; }
  .modal-head p { margin: 0; font-size: .8rem; opacity: .75; line-height: 1.4; }

  /* The only scrolling part. min-height: 0 is required — a flex child defaults to
     min-height: auto and refuses to shrink below its content, which is what makes
     "overflow: auto" silently do nothing inside a flex column. */
  .modal-body {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
    padding: 0.6rem 1.15rem;
    display: flex;
    flex-direction: column;
    gap: .3rem;
  }
  .modal-body label { font-size: .78rem; opacity: .8; margin-top: .4rem; }
  .modal-body input,
  .modal-body select,
  .modal-body textarea {
    width: 100%;
    box-sizing: border-box;
    font-family: inherit;
  }
  .modal-body textarea { resize: vertical; }
  .yubikey-opt {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.75rem;
    font-size: 0.9rem;
  }

  .hint { font-size: .74rem; opacity: .7; line-height: 1.35; margin: .35rem 0 0; }

  /* Never scrolls, never shrinks. The buttons are always on screen. */
  .modal-err {
    color: #ff6b6b;
    font-size: .78rem;
    margin: .5rem 0 0;
    line-height: 1.35;
  }

  .modal-foot {
    flex-shrink: 0;
    display: flex;
    gap: .5rem;
    justify-content: flex-end;
    padding: .8rem 1.15rem 1rem;
    border-top: 1px solid var(--border-color, #2c2c2c);
  }

  .disclosure-btn {
    margin-top: 1.5rem;
    background: transparent;
    border: none;
    color: var(--text-secondary, #aaaaaa);
    font-family: inherit;
    font-size: 0.85rem;
    cursor: pointer;
    transition: color 0.18s;
  }
  .disclosure-btn:hover { color: var(--accent-color, #1D7989); }

  .options {
    margin-top: 1.5rem;
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    justify-content: center;
  }

  /* Soft buttons rather than a row of links: three choices with real consequences
     deserve equal weight and room for a line saying what each one does. Ordered
     by what a locked-out person needs first. */
  .soft-btn {
    padding: 0.55rem 0.9rem;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 8px;
    color: inherit;
    font-family: inherit;
    font-size: 0.85rem;
    cursor: pointer;
    transition: background 0.18s, border-color 0.18s;
  }

  .soft-btn:not(:disabled):hover {
    background: rgba(255, 255, 255, 0.06);
    border-color: var(--accent-color, #1D7989);
  }

  .soft-btn:disabled { opacity: 0.55; cursor: not-allowed; }

  /* NO max-height or inner overflow on .restore-section.
     A previous attempt capped it at 70vh with its own scrollbar. That created two
     nested scroll areas: the outer container scrolled the card, the panel scrolled
     its own contents, and the wheel moved whichever the pointer happened to be
     over. The Restore button sat at the bottom of the INNER one and stayed
     invisible while a scrollbar was plainly on screen — worse than the original
     bug, because it looked like scrolling was already working.

     One scroll context. The container scrolls; the panel is whatever height it
     needs to be. */

  .seed-title { margin: 0 0 .25rem; font-size: 1.05rem; }
  .seed-sub { margin: 0 0 .9rem; font-size: .85rem; opacity: .8; }
  .seed-note { font-size: .78rem; opacity: .75; margin: .35rem 0 .6rem; }
  .seed-note.warn { opacity: .95; }
  .seed-caution { font-size: .8rem; margin: .6rem 0; padding: .5rem .6rem;
                  border-left: 3px solid currentColor; opacity: .85; }
  .lockout-hint { font-size: .78rem; opacity: .8; margin-top: .6rem; text-align: center; }
  textarea { width: 100%; box-sizing: border-box; font-family: inherit; }

  .unlock-container {
    display: flex;
    /* flex-start, not center: a centred item in a fixed-height flex container
       overflows equally in BOTH directions, and the part above the viewport
       cannot be scrolled to. The seed-restore panel — textarea, two passwords,
       birthday, notes, buttons — is taller than the viewport, and its submit
       button was simply unreachable. */
    align-items: flex-start;
    justify-content: center;
    /* min-height, not height: the container must be allowed to grow. */
    min-height: 100vh;
    width: 100vw;
    overflow-y: auto;
    padding: 2rem 1rem;
    box-sizing: border-box;
    background: var(--bg-color, #171717);
    background-image: radial-gradient(circle at center, #1e2530 0%, #171717 100%);
  }

  @media (max-height: 800px) {
    .unlock-card { padding: 1.5rem; }
  }

  .unlock-card {
    background: var(--surface-color, #1e1e1e);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 20px;
    padding: 3rem;
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.4);
    width: 100%;
    max-width: 480px;
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    animation: fadeIn 0.4s ease-out;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .logo-wrapper {
    margin-bottom: 2rem;
  }

  .logo {
    max-height: 60px;
  }

  h2 {
    margin: 0 0 0.5rem 0;
    font-size: 1.75rem;
    font-weight: 600;
  }

  .subtitle {
    color: var(--text-secondary, #aaaaaa);
    font-size: 0.95rem;
    margin-bottom: 2rem;
    line-height: 1.5;
  }

  form {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
  }

  .input-group {
    width: 100%;
  }

  .password-wrapper {
    position: relative;
    display: flex;
    align-items: center;
  }

  input[type="password"], input[type="text"] {
    width: 100%;
    background: var(--surface-hover, #2a2a2a);
    border: 1px solid var(--border-color, #2c2c2c);
    color: var(--text-primary, #ffffff);
    padding: 1rem;
    padding-right: 3rem;
    border-radius: 12px;
    font-size: 1rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    outline: none;
    transition: border-color 0.2s;
    box-sizing: border-box;
  }

  input:focus {
    border-color: var(--accent-color, #1D7989);
    box-shadow: 0 0 0 3px rgba(29, 121, 137, 0.2);
  }

  .visibility-btn {
    position: absolute;
    right: 0.5rem;
    background: transparent;
    border: none;
    cursor: pointer;
    font-size: 1.2rem;
    color: var(--text-secondary);
    padding: 0.5rem;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .error-msg {
    color: #ff3d00;
    font-size: 0.9rem;
    background: rgba(255, 61, 0, 0.1);
    padding: 0.75rem;
    border-radius: 8px;
    border: 1px solid rgba(255, 61, 0, 0.2);
  }

  .status-msg {
    margin-top: 1rem;
    padding: 1rem;
    border-radius: 8px;
    font-size: 0.9rem;
    width: 100%;
    word-break: break-word;
    box-sizing: border-box;
  }
  
  .status-msg.success {
    background: rgba(0, 230, 118, 0.1);
    color: #00e676;
    border: 1px solid rgba(0, 230, 118, 0.2);
  }

  .restore-section {
    margin-top: 1.5rem;
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    text-align: left;
    background: var(--surface-hover, #2a2a2a);
    padding: 1rem;
    border-radius: 12px;
    border: 1px solid var(--border-color, #2c2c2c);
    box-sizing: border-box;
  }
  
  .restore-section label {
    font-size: 0.9rem;
    color: var(--text-secondary);
  }

  select {
    width: 100%;
    background: var(--bg-color, #171717);
    border: 1px solid var(--border-color, #2c2c2c);
    color: var(--text-primary, #ffffff);
    padding: 0.75rem;
    border-radius: 8px;
    font-size: 1rem;
    outline: none;
    appearance: none;
    -webkit-appearance: none;
  }

  select option {
    background: #2c2c2c !important;
    color: #ffffff !important;
  }

  .restore-actions {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.5rem;
  }
  
  .btn.secondary {
    background: transparent;
    border: 1px solid var(--border-color, #2c2c2c);
  }
  
  .btn.secondary:hover {
    background: rgba(255, 255, 255, 0.05);
  }

  .slide-in {
    animation: slideDown 0.3s ease-out;
  }

  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .yubikey-toggle {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.9rem;
    color: var(--text-secondary);
    background: rgba(255, 255, 255, 0.05);
    padding: 0.75rem 1rem;
    border-radius: 8px;
    border: 1px solid rgba(255, 255, 255, 0.1);
  }

  .yubikey-toggle label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    cursor: pointer;
  }

  .status-indicator {
    font-size: 0.85rem;
    display: flex;
    align-items: center;
    gap: 0.25rem;
  }

  .status-indicator.active {
    color: #4CAF50;
  }

  .btn {
    width: 100%;
    padding: 1rem;
    border-radius: 12px;
    font-weight: 600;
    font-size: 1.1rem;
    cursor: pointer;
    border: none;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }

  .btn.primary {
    background: var(--accent-color, #1D7989);
    color: #fff;
  }

  .btn.primary:not(:disabled):hover {
    background: var(--accent-hover, #0E3B43);
    transform: translateY(-2px);
  }

  .btn:disabled {
    opacity: 0.7;
    cursor: not-allowed;
  }

  .spinner {
    width: 18px;
    height: 18px;
    border: 3px solid rgba(255,255,255,0.3);
    border-radius: 50%;
    border-top-color: #fff;
    animation: spin 1s ease-in-out infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
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

  .footer-links {
    margin-top: 2rem;
    display: flex;
    gap: 0.75rem;
    align-items: center;
    font-size: 0.9rem;
  }

  .link-btn {
    background: transparent;
    border: none;
    color: var(--text-secondary, #aaaaaa);
    cursor: pointer;
    font-family: inherit;
    font-size: inherit;
    transition: color 0.2s;
  }

  .link-btn:hover {
    color: var(--accent-color, #1D7989);
    text-decoration: underline;
  }

  .divider {
    color: var(--border-color, #2c2c2c);
  }
</style>