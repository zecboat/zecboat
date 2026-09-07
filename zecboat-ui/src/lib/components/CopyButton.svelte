<script lang="ts">
  /**
   * One copy button for the whole app.
   *
   * There were already three separate clipboard implementations here — ReceiveView,
   * TransactionDetail and SeedBackup each rolled their own — with different feedback and
   * different failure behaviour. This replaces the need for a fourth.
   *
   * The value copied is exactly the `value` prop. Callers pass the same string they
   * render, so what a user reads and what they paste cannot drift apart. For an address
   * or a key that difference is money.
   */
  let {
    value,
    label = "Copy",
    copiedLabel = "Copied",
    title = "",
    compact = false,
  }: {
    value: string;
    label?: string;
    copiedLabel?: string;
    title?: string;
    compact?: boolean;
  } = $props();

  let copied = $state(false);
  let failed = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function copy() {
    failed = false;
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // The async clipboard API needs a secure context and permission. Fall back rather
      // than leaving a button that silently does nothing.
      try {
        const el = document.createElement("textarea");
        el.value = value;
        el.setAttribute("readonly", "");
        el.style.position = "fixed";
        el.style.opacity = "0";
        document.body.appendChild(el);
        el.select();
        const ok = document.execCommand("copy");
        document.body.removeChild(el);
        if (!ok) throw new Error("execCommand refused");
      } catch {
        failed = true;
      }
    }
    if (!failed) copied = true;
    clearTimeout(timer);
    timer = setTimeout(() => { copied = false; failed = false; }, 2000);
  }
</script>

<button
  type="button"
  class="copy-btn"
  class:compact
  class:ok={copied}
  class:bad={failed}
  onclick={copy}
  disabled={!value}
  title={title || (copied ? copiedLabel : label)}
  aria-label={copied ? copiedLabel : label}
>
  <span aria-hidden="true">{failed ? "!" : copied ? "✓" : "⧉"}</span>
  {#if !compact}<span>{failed ? "Copy failed" : copied ? copiedLabel : label}</span>{/if}
</button>
<span aria-live="polite" class="sr-only">{copied ? copiedLabel : ""}</span>

<style>
  .copy-btn {
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    font: inherit;
    font-size: 0.85rem;
    padding: 0.35rem 0.7rem;
    border-radius: 6px;
    border: 1px solid var(--border-color, #2c2c2c);
    background: transparent;
    color: var(--text-color, #eee);
    cursor: pointer;
    transition: border-color .15s ease, color .15s ease;
  }
  .copy-btn:hover:not(:disabled) { border-color: var(--secondary-accent-color, #6c8cff); }
  .copy-btn:disabled { opacity: .45; cursor: default; }
  .copy-btn.compact { padding: 0.25rem 0.45rem; }
  .copy-btn.ok  { color: #4ade80; border-color: #4ade80; }
  .copy-btn.bad { color: #f87171; border-color: #f87171; }
  .sr-only {
    position: absolute; width: 1px; height: 1px;
    overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap;
  }
</style>
