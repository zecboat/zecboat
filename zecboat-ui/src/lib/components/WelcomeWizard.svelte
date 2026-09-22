<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

  let { onComplete } = $props<{ onComplete: () => void }>();

  let currentScreen = $state(1);
  let password = $state("");
  let confirmPassword = $state("");
  let seedPhrase = $state("");
  let seedWords: string[] = $state([]);
  let error = $state("");
  let loading = $state(false);

  // Verification
  // Which words to ask for, chosen fresh for each wallet.
  //
  // These were fixed at 4, 12 and 21 for every wallet ever created. A check that
  // always asks the same three positions verifies that the user copied three words,
  // not that they copied the phrase — and the answer is the same for everyone, so
  // it becomes something to learn rather than something to check.
  //
  // crypto.getRandomValues, not Math.random: this is key-backup material, and there
  // is no reason to reach for a predictable generator when the real one is free.
  let challengeIdx: number[] = $state([]);
  let challengeAnswers: string[] = $state([]);

  function pickChallenge(count: number, total: number): number[] {
    const chosen = new Set<number>();
    const buf = new Uint32Array(1);
    while (chosen.size < Math.min(count, total)) {
      crypto.getRandomValues(buf);
      chosen.add(buf[0] % total);
    }
    return [...chosen].sort((a, b) => a - b);
  }

  let nodePreference = $state("local");
  let useYubikey = $state(false);

  // What the backend resolved at startup. Non-empty only when ZECBOAT_PROVIDER was
  // exported and names something the preset list does not already cover.
  let configuredUrl = $state("");
  // Where Continue goes after the node screen: the create flow and the restore flow
  // both pass through it, and they resume at different places.
  let afterNode = $state(4);
  // The restore flow reaches the node screen too. It used to skip it entirely —
  // handleRestore opened the seed modal directly — so restoring a wallet made no
  // node choice at all and silently used the compiled-in default. On a downloaded
  // build with no ZECBOAT_PROVIDER that is a public lightwalletd, contacted before
  // the user has been offered any say in it.
  let pendingRestore = $state(false);

  onMount(async () => {
    // An operator who exported ZECBOAT_PROVIDER has already said which node they
    // trust. Offering them a two-item preset list and silently overruling that is
    // wrong on any screen and worst on this one, where a seed phrase is about to be
    // typed. Surface it as a preselected option instead.
    try {
      const current = (await invoke<string>("get_provider_url"))?.trim() ?? "";
      if (current && !Object.values(NODE_URLS).includes(current)) {
        configuredUrl = current;
        nodePreference = "configured";
      }
    } catch (e) {
      // A missing getter is not a reason to block onboarding; fall back to presets.
      console.error("Could not read the configured node endpoint:", e);
    }
  });

  async function handleCreate() {
    afterNode = 4; // Password
    currentScreen = 2; // Move to Node Selection
  }

  // Must match the presets and storage key in SettingsView.svelte.
  const NODE_URLS: Record<string, string> = {
    local: "http://127.0.0.1:9067",
    // Was https://port.zecboat.com:9067, retired hosted infrastructure — it still
    // resolves but answers nothing, so this option offered a new user a node that
    // could only fail on their very first screen. Must serve Ironwood (NU6.3).
    remote: "https://zec.rocks:443"
  };

  async function handleNodeSelection() {
    // Previously this discarded nodePreference entirely and just advanced the
    // screen, so the wizard's choice never reached the backend.
    const url =
      nodePreference === "configured"
        ? configuredUrl
        : NODE_URLS[nodePreference] ?? NODE_URLS.local;
    try {
      await invoke("set_provider_url", { url });
      localStorage.setItem(
        "zecboat.provider",
        // "public", not "port". SettingsView's presets were renamed when the retired
        // Zecboat Port host was removed; writing the old id here left a brand new
        // user's Settings screen with nothing selected and the Custom field hidden.
        //
        // "configured" is stored as "custom": SettingsView has no preset for an
        // environment-supplied URL, and Custom is exactly the case of "a valid
        // address with no preset", which is what its own comment says it is for.
        JSON.stringify({
          presetId:
            nodePreference === "remote"
              ? "public"
              : nodePreference === "configured"
                ? "custom"
                : "local",
          url
        })
      );
    } catch (e) {
      // Not fatal during onboarding — the wallet is created either way, and the
      // endpoint can be changed later in Settings.
      console.error("Failed to set provider URL during onboarding:", e);
    }
    currentScreen = afterNode; // Skips the mocked YubiKey screen
    if (pendingRestore) {
      pendingRestore = false;
      showRestore = true;
    }
  }

  async function handleYubiKeySelection() {
    currentScreen = 4; // Move to Password
  }

  // Restore from a seed phrase on first run.
  //
  // This was `alert("Restore functionality coming soon!")` — a dead button on the
  // FIRST screen a new user sees. Arriving on a new machine with your 24 words is
  // the *common* recovery case, more common than a forgotten password, and the
  // wizard told those users the feature did not exist. Worse than a missing
  // button: someone could conclude their seed phrase was useless.
  //
  // The backend (recover_wallet_from_seed) has existed since 2026-09-03; only the
  // wiring was absent.
  let showRestore = $state(false);
  let restoreSeed = $state("");
  let restorePw = $state("");
  let restorePw2 = $state("");
  let restoreBirthday = $state<number | null>(419_200);
  let isRestoring = $state(false);

  // Sapling activation is the "I don't know" answer that cannot silently lose
  // funds. A later block scans faster and misses anything received before it.
  const RESTORE_PRESETS = [
    { label: "I don't know / oldest", height: 419_200 },
    { label: "Orchard era",           height: 1_687_104 },
    { label: "Zecboat wallet",        height: 3_428_143 },
  ];

  function handleRestore() {
    error = "";
    // Choose the node BEFORE the seed phrase is typed, not after. The modal opens
    // from handleNodeSelection once an endpoint has actually been set.
    pendingRestore = true;
    afterNode = 1;
    currentScreen = 2;
  }

  async function confirmRestore() {
    error = "";
    const words = restoreSeed.trim().split(/\s+/).filter(Boolean);
    if (words.length !== 24) {
      // Count only. Never name which word is wrong — that tells someone holding a
      // partial phrase exactly what they still need.
      error = `A recovery phrase is 24 words. You entered ${words.length}.`;
      return;
    }
    if (!restorePw) { error = "Choose a password for this wallet."; return; }
    if (restorePw !== restorePw2) { error = "The two passwords do not match."; return; }

    isRestoring = true;
    try {
      const height = await invoke<number>("recover_wallet_from_seed", {
        seed: words.join(" "),
        password: restorePw,
        birthday: restoreBirthday,
      });
      restoreSeed = ""; restorePw = ""; restorePw2 = "";
      showRestore = false;
      onComplete();
      console.log(`[wizard] wallet recovered, scanning from ${height}`);
    } catch (e) {
      error = String(e);
    } finally {
      isRestoring = false;
    }
  }

  async function submitPassword() {
    error = "";
    if (password.length < 8) {
      error = "Password must be at least 8 characters.";
      return;
    }
    if (password !== confirmPassword) {
      error = "Passwords do not match.";
      return;
    }

    currentScreen = 5;
    
    if (!useYubikey) {
      await performInitialization();
    }
  }

  // Optional birthday for a NEW wallet. The correct answer is almost always the
  // chain tip, which is what the backend uses when this is null — a brand new seed
  // cannot have history, so scanning earlier is pure waste. It is offered because
  // the caller sometimes knows better: a phrase written down elsewhere weeks ago,
  // or a node reporting a tip that is wrong.
  //
  // Lowering it only costs scanning time. That is why there is no warning here,
  // unlike the recovery screen where raising it silently hides funds.
  let newBirthday = $state<number | null>(null);
  let showBirthday = $state(false);

  async function performInitialization() {
    loading = true;
    error = "";
    
    try {
      seedPhrase = await invoke("initialize_new_wallet", { password, useYubikey, birthday: newBirthday });
      seedWords = seedPhrase.trim().split(/\s+/);
      currentScreen = 6;
    } catch (e) {
      console.error(e);
      error = e as string;
      currentScreen = 4; // Go back to password screen on error
    } finally {
      loading = false;
    }
  }

  let copyLabel = $state("Copy to clipboard");

  // Offered because transcribing 24 words by hand is where people make mistakes,
  // and a wrong transcription is only discovered when the funds are already gone.
  // The caution below the button is the point, not decoration: the clipboard is
  // readable by other processes, so this is a convenience, not the backup.
  async function copySeed() {
    try {
      await navigator.clipboard.writeText(seedWords.join(" "));
      copyLabel = "Copied";
    } catch {
      // Clipboard access can be denied or unavailable in the webview. Say so
      // rather than silently appearing to have worked — a user who believes the
      // phrase is copied and moves on has no backup at all.
      copyLabel = "Copy failed — write them down";
      return;
    }
    setTimeout(() => (copyLabel = "Copy to clipboard"), 2000);
  }

  function handleBackupNext() {
    // Pick the positions now, once the phrase exists and before the check is shown.
    challengeIdx = pickChallenge(3, seedWords.length);
    challengeAnswers = challengeIdx.map(() => "");
    currentScreen = 7;
  }

  function verifyBackup() {
    error = "";
    const wrong = challengeIdx.filter(
      (idx, slot) => (challengeAnswers[slot] ?? "").trim().toLowerCase() !== seedWords[idx]
    );
    if (wrong.length > 0) {
      // Say how many are wrong but never which — naming the wrong position tells
      // someone holding a partial phrase which words they still need.
      error = wrong.length === 1
        ? "One of those words does not match. Please check your backup."
        : `${wrong.length} of those words do not match. Please check your backup.`;
      return;
    }
    currentScreen = 8;
  }
</script>

<div class="wizard-container">
  {#if currentScreen === 1}
    <div class="wizard-card">
      <img src="/logo.png" alt="Zecboat Logo" class="logo" />
      <h2>Welcome to Zecboat</h2>
      <p class="subtitle">The secure, private gateway to the Zcash ecosystem.</p>
      
      <div class="actions">
        <button class="primary-btn" onclick={handleCreate}>Create New Wallet</button>
        <button class="secondary-btn" onclick={handleRestore}>Restore Existing</button>
      </div>
    </div>
  {:else if currentScreen === 2}
    <div class="wizard-card wide">
      <h2>Network Connection</h2>
      <p class="subtitle">How would you like Zecboat to connect to the Zcash network?</p>
      
      <div class="form-group node-selection">
        {#if configuredUrl}
          <label class="node-option">
            <input type="radio" bind:group={nodePreference} value="configured" />
            <div class="option-details">
              <span class="option-title">Configured Node (Recommended)</span>
              <span class="option-desc">Use <code>{configuredUrl}</code>, set by <code>ZECBOAT_PROVIDER</code> in the environment this wallet was launched from. You have already named the node you trust &mdash; this keeps it.</span>
            </div>
          </label>
        {/if}

        <label class="node-option">
          <input type="radio" bind:group={nodePreference} value="local" />
          <div class="option-details">
            <span class="option-title">Local Node{configuredUrl ? "" : " (Recommended)"}</span>
            <span class="option-desc">Connect to zebrad + zainod running on this machine (127.0.0.1:9067). Maximum privacy &mdash; no one sees which blocks you request. Requires ~300GB disk and an initial sync.</span>
          </div>
        </label>

        <label class="node-option">
          <input type="radio" bind:group={nodePreference} value="remote" />
          <div class="option-details">
            <span class="option-title">zec.rocks (Public Node)</span>
            <span class="option-desc">Connect to zec.rocks, a public Zcash node. Zero setup and no disk cost, but the node learns which blocks you ask for, which narrows down which addresses are yours. You can switch at any time in Settings.</span>
          </div>
        </label>
      </div>

      <div class="actions">
        <button class="secondary-btn" onclick={() => { pendingRestore = false; currentScreen = 1; }}>Back</button>
        <button class="primary-btn" onclick={handleNodeSelection}>Continue</button>
      </div>
    </div>
  <!-- YubiKey screen hidden 2026-09-01. The integration is a MOCK: zecboat-core/src/yubi.rs
       returns is_yubikey_connected() = true unconditionally and derives its "hardware" response
       from a static software hash — no key is ever contacted. Offering hardware protection that
       does not exist is worse than offering none, because a user acts on the confidence it
       creates. Screen 2 now goes straight to 4. Restore when a real HMAC-SHA1
       challenge-response is wired to slot 2. -->
  <!--
  {:else if currentScreen === 3}
    <div class="wizard-card">
      <h2>Hardware Security (Optional)</h2>
      <p class="subtitle">A password protects against remote attacks, but a YubiKey protects against physical access and keyloggers.</p>
      
      <div class="form-group node-selection">
        <label class="node-option">
          <input type="checkbox" bind:checked={useYubikey} />
          <div class="option-details">
            <span class="option-title">Enable YubiKey 2FA</span>
            <span class="option-desc">Require a physical touch on your YubiKey to unlock Zecboat or sign shielded transactions.</span>
          </div>
        </label>
      </div>

      <div class="actions">
        <button class="secondary-btn" onclick={() => currentScreen = 2}>Back</button>
        <button class="primary-btn" onclick={handleYubiKeySelection}>Continue</button>
      </div>
    </div>
  -->
  {:else if currentScreen === 4}
    <div class="wizard-card">
      <h2>Protect Your Wallet</h2>
      <p class="subtitle">Set a strong password. This encrypts your cryptographic identity and keys on this device.</p>
      
      <div class="form-group">
        <input type="password" placeholder="Password" bind:value={password} />
        <input type="password" placeholder="Confirm Password" bind:value={confirmPassword} />
      </div>
      
      {#if error}
        <p class="error">{error}</p>
      {/if}

      <div class="actions">
        <button class="secondary-btn" onclick={() => currentScreen = 2}>Back</button>
        <button class="primary-btn" onclick={submitPassword}>Continue</button>
      </div>
    </div>
  {:else if currentScreen === 5}
    <div class="wizard-card loading-card">
      <!-- The YubiKey branch is unreachable now that the hardware screen is hidden:
           useYubikey can no longer be set. Markup removed rather than left dormant, so a
           future change cannot resurrect a "Simulate Physical Touch" button by accident. -->
      {#if false}
        <div class="spinner"></div>
        <h2>Forging Cryptographic Identity...</h2>
        <p class="subtitle">Generating zero-knowledge proofs, deriving unified addresses, and initializing secure storage.</p>
      {/if}
    </div>
  {:else if currentScreen === 6}
    <div class="wizard-card wide">
      <h2>Secret Recovery Phrase</h2>
      <p class="subtitle warning">WARNING: Write down these 24 words on paper. If you lose them, you lose your funds. Never share them with anyone.</p>
      
      <div class="seed-grid">
        {#each seedWords as word, i}
          <div class="seed-word">
            <span class="index">{i + 1}.</span> {word}
          </div>
        {/each}
      </div>

      <div class="actions">
        <button class="secondary-btn" onclick={copySeed}>{copyLabel}</button>
        <button class="primary-btn" onclick={handleBackupNext}>I have saved these words safely</button>
      </div>
      <p class="subtitle copy-caution">
        Paper is the safe copy. Anything on the clipboard can be read by other programs on this
        machine and may be kept in clipboard history — clear it once you have written the words down.
      </p>
    </div>
  {:else if currentScreen === 7}
    <div class="wizard-card">
      <h2>Verify Backup</h2>
      <p class="subtitle">To ensure you wrote it down correctly, please provide the following words from your phrase.</p>
      
      <div class="form-group">
        {#each challengeIdx as idx, slot}
          <label>Word #{idx + 1}</label>
          <input
            type="text"
            autocomplete="off"
            autocapitalize="none"
            spellcheck="false"
            bind:value={challengeAnswers[slot]}
          />
        {/each}
      </div>
      
      {#if error}
        <p class="error">{error}</p>
      {/if}

      <div class="actions">
        <button class="secondary-btn" onclick={() => currentScreen = 6}>Back</button>
        <button class="primary-btn" onclick={verifyBackup}>Verify</button>
      </div>
    </div>
  {:else if currentScreen === 8}
    <div class="wizard-card">
      <div class="success-icon">✓</div>
      <h2>Setup Complete!</h2>
      <p class="subtitle">Your wallet is encrypted and ready to use.</p>
      
      <div class="actions">
        <button class="primary-btn" onclick={onComplete}>Enter Zecboat</button>
      </div>
    </div>
  {/if}
</div>

{#if showRestore}
  <!-- Rendered at the component root, NOT inside .wizard-card. A transformed
       ancestor becomes the containing block for position:fixed, which made four
       unlock-screen panels unreachable on 2026-09-03. -->
  <div class="rs-backdrop" role="presentation" onclick={() => (showRestore = false)}>
    <div class="rs-modal" role="dialog" aria-modal="true" aria-label="Restore from seed phrase"
         tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
      <div class="rs-head">
        <h3>Restore from seed phrase</h3>
        <p>Enter the 24 words from an existing wallet's backup.</p>
      </div>
      <div class="rs-body">
        <label for="rs-words">Recovery phrase — 24 words</label>
        <textarea id="rs-words" rows="3" autocomplete="off" autocapitalize="none"
                  spellcheck="false" placeholder="word word word …" bind:value={restoreSeed}></textarea>
        <label for="rs-pw">Password for this machine</label>
        <input id="rs-pw" type="password" autocomplete="new-password" bind:value={restorePw} />
        <label for="rs-pw2">Confirm password</label>
        <input id="rs-pw2" type="password" autocomplete="new-password" bind:value={restorePw2} />
        <label for="rs-bday">Scan from</label>
        <select id="rs-bday" bind:value={restoreBirthday}>
          {#each RESTORE_PRESETS as p}
            <option value={p.height}>{p.label} — {p.height.toLocaleString()}</option>
          {/each}
        </select>
        <p class="rs-hint">
          A later block scans faster but <strong>misses funds received before it</strong>.
          Unsure? Leave it oldest.
        </p>
        {#if error}<p class="rs-err">{error}</p>{/if}
      </div>
      <div class="rs-foot">
        <button class="secondary-btn" onclick={() => (showRestore = false)} disabled={isRestoring}>Cancel</button>
        <button class="primary-btn" onclick={confirmRestore} disabled={isRestoring}>
          {isRestoring ? "Recovering…" : "Restore wallet"}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .rs-backdrop { position: fixed; inset: 0; z-index: 1400; background: rgba(0,0,0,.72);
                 display: flex; align-items: center; justify-content: center; padding: 1rem; }
  .rs-modal { background: var(--surface-color, #1e1e1e); border: 1px solid var(--border-color, #2c2c2c);
              border-radius: 14px; width: 100%; max-width: 440px; max-height: 90vh;
              display: flex; flex-direction: column; text-align: left; }
  .rs-head { padding: 1rem 1.15rem .6rem; flex-shrink: 0; }
  .rs-head h3 { margin: 0 0 .3rem; font-size: 1rem; }
  .rs-head p { margin: 0; font-size: .8rem; opacity: .75; }
  /* min-height:0 — a flex child will not shrink below its content without it, and
     overflow then silently does nothing. */
  .rs-body { flex: 1 1 auto; min-height: 0; overflow-y: auto; padding: .6rem 1.15rem;
             display: flex; flex-direction: column; gap: .3rem; }
  .rs-body label { font-size: .78rem; opacity: .8; margin-top: .4rem; }
  .rs-body input, .rs-body select, .rs-body textarea { width: 100%; box-sizing: border-box; font-family: inherit; }
  .rs-hint { font-size: .74rem; opacity: .7; line-height: 1.35; margin: .35rem 0 0; }
  .rs-err { color: #ff6b6b; font-size: .78rem; margin: .5rem 0 0; }
  /* Never scrolls, never shrinks — the buttons are always on screen. */
  .rs-foot { flex-shrink: 0; display: flex; gap: .5rem; justify-content: flex-end;
             padding: .8rem 1.15rem 1rem; border-top: 1px solid var(--border-color, #2c2c2c); }

  .wizard-container {
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 100vh;
    background-color: var(--bg-color, #171717);
    color: var(--text-primary, #ffffff);
    padding: 2rem;
    box-sizing: border-box;
  }

  .wizard-card {
    background: var(--surface-color, #1e1e1e);
    padding: 3rem;
    border-radius: 16px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    width: 100%;
    max-width: 480px;
    text-align: center;
    border: 1px solid var(--border-color, #2c2c2c);
  }
  
  .wizard-card.wide {
    max-width: 650px;
  }

  .logo {
    height: 80px;
    margin-bottom: 1.5rem;
  }

  h2 {
    margin-top: 0;
    margin-bottom: 0.5rem;
    font-size: 1.8rem;
  }

  .subtitle {
    color: var(--text-secondary, #aaaaaa);
    margin-bottom: 2rem;
    line-height: 1.5;
  }
  
  .warning {
    color: #ff9800;
    font-weight: 600;
  }

  .actions {
    display: flex;
    gap: 1rem;
    margin-top: 2rem;
  }

  button {
    flex: 1;
    padding: 0.8rem 1.5rem;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    border: none;
    transition: all 0.2s;
  }

  .primary-btn {
    background: var(--accent-color, #1D7989);
    color: white;
  }
  .primary-btn:hover {
    background: var(--accent-hover, #0E3B43);
  }

  .secondary-btn {
    background: transparent;
    border: 1px solid var(--border-color, #2c2c2c);
    color: white;
  }
  .secondary-btn:hover {
    background: var(--surface-hover, #2a2a2a);
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    text-align: left;
  }
  
  .form-group label {
    font-size: 0.9rem;
    color: var(--text-secondary);
    margin-bottom: -0.5rem;
  }

  input {
    width: 100%;
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid var(--border-color, #2c2c2c);
    background: var(--bg-color, #171717);
    color: white;
    font-size: 1rem;
    box-sizing: border-box;
  }
  
  input:focus {
    outline: none;
    border-color: var(--accent-color);
  }

  .error {
    color: #ff5252;
    margin-top: 1rem;
    font-size: 0.9rem;
  }

  .spinner {
    border: 4px solid rgba(255, 255, 255, 0.1);
    border-top: 4px solid var(--accent-color);
    border-radius: 50%;
    width: 60px;
    height: 60px;
    animation: spin 1s linear infinite;
    margin: 0 auto 2rem auto;
  }

  @keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  .yubikey-animation {
    display: flex;
    justify-content: center;
    margin-bottom: 2rem;
  }

  .yk-indicator {
    width: 60px;
    height: 60px;
    border-radius: 50%;
    background-color: #333;
    border: 4px solid #4CAF50;
    box-shadow: 0 0 15px rgba(76, 175, 80, 0.5);
  }

  .yk-indicator.blinking {
    animation: pulse 1.5s infinite;
  }

  @keyframes pulse {
    0% { transform: scale(0.95); opacity: 0.7; box-shadow: 0 0 0 0 rgba(76, 175, 80, 0.7); }
    70% { transform: scale(1.05); opacity: 1; box-shadow: 0 0 0 15px rgba(76, 175, 80, 0); }
    100% { transform: scale(0.95); opacity: 0.7; box-shadow: 0 0 0 0 rgba(76, 175, 80, 0); }
  }

  .copy-caution {
    margin-top: 0.75rem;
    font-size: 0.8rem;
    opacity: 0.75;
  }

  .seed-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    text-align: left;
  }

  .seed-word {
    background: var(--bg-color);
    padding: 0.75rem;
    border-radius: 8px;
    border: 1px solid var(--border-color);
    font-weight: 500;
  }

  .index {
    color: var(--text-secondary);
    font-size: 0.8rem;
    margin-right: 0.25rem;
  }

  .success-icon {
    font-size: 4rem;
    color: #4CAF50;
    margin-bottom: 1rem;
  }
  
  .node-selection {
    gap: 1.5rem;
  }

  .node-option {
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    padding: 1.5rem;
    border: 2px solid var(--border-color);
    border-radius: 12px;
    cursor: pointer;
    transition: border-color 0.2s, background-color 0.2s;
  }

  .node-option:hover {
    background-color: var(--surface-hover);
  }

  .node-option:has(input:checked) {
    border-color: var(--accent-color);
    background-color: rgba(29, 121, 137, 0.1); /* Slight accent tint */
  }

  .node-option input {
    width: auto;
    margin-top: 0.25rem;
  }

  .option-details {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .option-title {
    font-weight: 600;
    font-size: 1.1rem;
    color: var(--text-primary);
  }

  .option-desc {
    font-size: 0.9rem;
    color: var(--text-secondary);
    line-height: 1.4;
  }

  @media (max-width: 600px) {
    .seed-grid {
      grid-template-columns: repeat(2, 1fr);
    }
    .actions {
      flex-direction: column;
    }
  }
</style>