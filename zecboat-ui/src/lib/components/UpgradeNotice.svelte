<script lang="ts">
  // One amber line, shown while the running build does not follow the next network upgrade.
  // Driven by `wallet_about().upgrade_notice`; a build that follows the upgrade returns null
  // and this renders nothing. `compact` is the header pill; the default is the About line.
  import { invoke } from "@tauri-apps/api/core";

  type Notice = { name: string; date: string; update_to: string };
  let { compact = false }: { compact?: boolean } = $props();
  let notice = $state<Notice | null>(null);

  invoke<{ upgrade_notice: Notice | null }>("wallet_about")
    .then((a) => { notice = a.upgrade_notice ?? null; })
    .catch(() => { notice = null; });
</script>

{#if notice}
  {#if compact}
    <span class="notice pill" title="{notice.name} activates on {notice.date}. This build stops syncing and sending from then. Update to {notice.update_to} before that date.">
      ⚠ Update before {notice.date}
    </span>
  {:else}
    <p class="notice line">
      ⚠ {notice.name} activates on {notice.date}. This build stops working then. Update to {notice.update_to} before that date.
    </p>
  {/if}
{/if}

<style>
  .notice {
    color: #fbbf24;
    background: rgba(245, 158, 11, 0.12);
    border: 1px solid rgba(245, 158, 11, 0.5);
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
</style>
