<script lang="ts">
  // The seed backup flow — display, copy, and prove it was written down.
  //
  // Extracted from WelcomeWizard so the unlock screen's "Create a New Wallet" uses
  // the same one. It previously returned the phrase in a single status line
  // ("…back up your seed phrase: abandon ability able…") shown once, with no grid,
  // no copy button and no verification. Dismiss it and the phrase was gone for
  // good — a wallet created there had a strictly worse backup than one created by
  // the wizard, on the same screen that now offers seed recovery.
  //
  // Duplicating it was the alternative. Two copies of a random-position challenge
  // is two places to get the randomness wrong.

  let { seedPhrase, onComplete }: { seedPhrase: string; onComplete: () => void } = $props();

  const seedWords = $derived(seedPhrase.trim().split(/\s+/).filter(Boolean));

  let stage = $state<"show" | "verify">("show");
  let copyLabel = $state("Copy to clipboard");
  let error = $state("");
  let challengeIdx = $state<number[]>([]);
  let challengeAnswers = $state<string[]>([]);

  // crypto.getRandomValues, not Math.random: this is key-backup material and the
  // real generator is free. Fixed positions would make the check something to
  // learn rather than something to prove.
  function pickChallenge(count: number, total: number): number[] {
    const chosen = new Set<number>();
    const buf = new Uint32Array(1);
    while (chosen.size < Math.min(count, total)) {
      crypto.getRandomValues(buf);
      chosen.add(buf[0] % total);
    }
    return [...chosen].sort((a, b) => a - b);
  }

  async function copySeed() {
    try {
      await navigator.clipboard.writeText(seedWords.join(" "));
      copyLabel = "Copied";
      setTimeout(() => (copyLabel = "Copy to clipboard"), 2000);
    } catch {
      // Say so rather than appearing to have worked. Someone who believes the
      // phrase is copied and moves on has no backup at all.
      copyLabel = "Copy failed — write them down";
    }
  }

  function toVerify() {
    challengeIdx = pickChallenge(3, seedWords.length);
    challengeAnswers = challengeIdx.map(() => "");
    error = "";
    stage = "verify";
  }

  function verify() {
    const wrong = challengeIdx.filter(
      (idx, slot) => (challengeAnswers[slot] ?? "").trim().toLowerCase() !== seedWords[idx]
    );
    if (wrong.length > 0) {
      // How many, never which. Naming the wrong position tells someone holding a
      // partial phrase exactly what they still need.
      error = wrong.length === 1
        ? "One of those words does not match. Please check your backup."
        : `${wrong.length} of those words do not match. Please check your backup.`;
      return;
    }
    onComplete();
  }
</script>

<div class="seed-backup">
  {#if stage === "show"}
    <h3>Secret Recovery Phrase</h3>
    <p class="warn">
      <strong>Write these 24 words down on paper.</strong> They are the only way to recover this
      wallet. If you lose them, you lose your funds. Never share them with anyone.
    </p>

    <div class="seed-grid">
      {#each seedWords as word, i}
        <div class="seed-word"><span class="index">{i + 1}.</span> {word}</div>
      {/each}
    </div>

    <div class="row">
      <button class="btn secondary" onclick={copySeed}>{copyLabel}</button>
      <button class="btn primary" onclick={toVerify}>I have saved these words safely</button>
    </div>

    <p class="note">
      Paper is the safe copy. Anything on the clipboard can be read by other programs on this
      machine and may be kept in clipboard history — clear it once you have written the words down.
    </p>
  {:else}
    <h3>Verify your backup</h3>
    <p class="note">Enter these words from the phrase you just wrote down.</p>

    <div class="verify-grid">
      {#each challengeIdx as idx, slot}
        <label for={`vw-${slot}`}>Word #{idx + 1}</label>
        <input
          id={`vw-${slot}`}
          type="text"
          autocomplete="off"
          autocapitalize="none"
          spellcheck="false"
          bind:value={challengeAnswers[slot]}
        />
      {/each}
    </div>

    {#if error}<p class="err">{error}</p>{/if}

    <div class="row">
      <button class="btn secondary" onclick={() => (stage = "show")}>Show phrase again</button>
      <button class="btn primary" onclick={verify}>Verify</button>
    </div>
  {/if}
</div>

<style>
  .seed-backup { text-align: left; }
  h3 { margin: 0 0 .5rem; font-size: 1.05rem; }
  .warn { font-size: .85rem; line-height: 1.5; margin: 0 0 .9rem; }
  .note { font-size: .78rem; opacity: .75; line-height: 1.4; margin: .7rem 0 0; }
  .err { color: #ff6b6b; font-size: .82rem; margin: .6rem 0 0; }

  .seed-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: .4rem;
    margin-bottom: 1rem;
  }
  .seed-word {
    background: rgba(255,255,255,.04);
    border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 6px;
    padding: .35rem .5rem;
    font-size: .82rem;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  .index { opacity: .5; margin-right: .3rem; }

  .verify-grid { display: flex; flex-direction: column; gap: .3rem; margin-bottom: .5rem; }
  .verify-grid input { width: 100%; box-sizing: border-box; }

  .row { display: flex; gap: .6rem; justify-content: flex-end; margin-top: .8rem; }
</style>
