<script lang="ts">
  // Two notices, one component. The amber line: the running build does not follow the next
  // network upgrade (`wallet_about().upgrade_notice`; null when it does). The blue line, 0.7.3:
  // a newer release is signed under the pinned release key (`check_update`; null, or any
  // error, when there is nothing to say -- the wallet never depends on the site). `compact`
  // is the header pill; the default is the About line, which carries the install button.
  import { invoke } from "@tauri-apps/api/core";

  type Notice = { name: string; date: string; update_to: string };
  type Update = { version: string; released: string; deb_url: string; deb_sha256: string; notes_url: string; current: string };
  let { compact = false }: { compact?: boolean } = $props();
  let notice = $state<Notice | null>(null);
  let update = $state<Update | null>(null);
  let installing = $state(false);
  let result = $state<string | null>(null);
  let failed = $state(false);

  invoke<{ upgrade_notice: Notice | null }>("wallet_about")
    .then((a) => { notice = a.upgrade_notice ?? null; })
    .catch(() => { notice = null; });
  invoke<Update | null>("check_update")
    .then((u) => { update = u ?? null; })
    .catch(() => { update = null; });

  async function install() {
    if (!update || installing) return;
    installing = true; result = null; failed = false;
    try {
      // The core re-reads the signed note and verifies the package before anything is
      // installed; the system asks for the user's own authentication.
      result = await invoke<string>("install_update", { version: update.version });
    } catch (e) {
      failed = true;
      result = String(e);
    } finally {
      installing = false;
    }
  }
</script>

{#if notice}
  {#if compact}
    <span class="notice pill" title="{notice.name} activates on {notice.date}. This build stops syncing and sending from then. Update to {notice.update_to} first.">
      ⚠ Update before {notice.date}
    </span>
  {:else}
    <p class="notice line">
      ⚠ {notice.name} activates on {notice.date}. This build stops working then. Update to {notice.update_to} before that date.
    </p>
  {/if}
{/if}

{#if update}
  {#if compact}
    <span class="update pill" title="Zecboat {update.version} is available (released {update.released}). Settings → About installs it.">
      ⬆ {update.version} available
    </span>
  {:else}
    <div class="update line">
      <span>
        Zecboat {update.version} is available{#if update.released}, released {update.released}{/if}. This is {update.current}.
        The release note is signed with the key pinned in this build; the package is checked against it before it is installed.
      </span>
      <button class="btn" onclick={install} disabled={installing}>
        {installing ? "Installing…" : `Install ${update.version}`}
      </button>
      {#if result}
        <p class="result" class:failed>{result}</p>
      {/if}
    </div>
  {/if}
{/if}

<style>
  .notice {
    color: #fbbf24;
    background: rgba(245, 158, 11, 0.12);
    border: 1px solid rgba(245, 158, 11, 0.5);
    border-radius: 8px;
  }
  .update {
    color: #60a5fa;
    background: rgba(59, 130, 246, 0.12);
    border: 1px solid rgba(59, 130, 246, 0.5);
    border-radius: 8px;
  }
  .pill {
    font-size: 0.8rem;
    font-weight: 600;
    padding: 0.25rem 0.6rem;
    white-space: nowrap;
    cursor: default;
  }
  .line {
    font-size: 0.9rem;
    line-height: 1.5;
    padding: 0.5rem 0.75rem;
    margin: 0 0 0.9rem;
  }
  div.line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.6rem 1rem;
  }
  div.line > span { flex: 1 1 24rem; }
  .btn {
    font: inherit;
    font-weight: 600;
    color: #0b1220;
    background: #60a5fa;
    border: none;
    border-radius: 6px;
    padding: 0.4rem 0.9rem;
    cursor: pointer;
  }
  .btn:disabled { opacity: 0.6; cursor: default; }
  .result { flex-basis: 100%; margin: 0; color: #86efac; }
  .result.failed { color: #fca5a5; }
</style>
