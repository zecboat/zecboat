<script lang="ts">
  // Settings → Artwork (0.7.3). The holder's own IPFS gateway, asked before zecboat.com for a
  // unit's artwork. Every image is still checked against the hash the unit carries, so the
  // gateway is trusted for availability only. Saved like the node choice; restored on load by
  // +page.svelte. ZECBOAT_IPFS_GATEWAY at start wins over this screen.
  import { invoke } from "@tauri-apps/api/core";

  const KEY = "zecboat.ipfsGateway";
  const OWN_NODE = "http://127.0.0.1:8080";
  let url = $state("");
  let saved = $state<string | null>(null);
  let fromEnv = $state(false);
  let busy = $state(false);
  let status = $state<{ ok: boolean; text: string } | null>(null);

  invoke<{ gateway: string | null; from_env: boolean }>("get_ipfs_gateway")
    .then((g) => { saved = g.gateway; fromEnv = g.from_env; url = g.gateway ?? ""; })
    .catch(() => {});

  async function save(target: string) {
    busy = true; status = null;
    try {
      const t = target.trim();
      if (t) {
        const norm = await invoke<string>("probe_ipfs_gateway", { url: t });
        await invoke("set_ipfs_gateway", { url: norm });
        try { localStorage.setItem(KEY, norm); } catch {}
        saved = norm; url = norm;
        status = { ok: true, text: "answering" };
      } else {
        await invoke("set_ipfs_gateway", { url: "" });
        try { localStorage.removeItem(KEY); } catch {}
        saved = null;
        status = { ok: true, text: "cleared: artwork comes from zecboat.com" };
      }
    } catch (e) {
      status = { ok: false, text: String(e) };
    } finally {
      busy = false;
    }
  }
</script>

<div class="artwork">
  <p class="line">
    {#if saved}
      <span class="mark ok">✓</span> {saved} · asked before zecboat.com
    {:else}
      <span class="mark none">○</span> zecboat.com only
    {/if}
  </p>

  {#if fromEnv}
    <p class="note">Set by ZECBOAT_IPFS_GATEWAY when the wallet started.</p>
  {:else}
    <div class="row">
      <input type="text" placeholder="http://127.0.0.1:8080" bind:value={url} aria-label="Your IPFS gateway" disabled={busy} />
      <button class="btn" onclick={() => save(url)} disabled={busy}>{busy ? "Checking…" : "Save"}</button>
    </div>
    <div class="row">
      <button class="btn link" onclick={() => save(OWN_NODE)} disabled={busy}>Use my own node</button>
      {#if saved}<button class="btn link" onclick={() => save("")} disabled={busy}>Clear</button>{/if}
    </div>
    {#if status}
      <p class="status" class:bad={!status.ok}>{status.ok ? "✓" : "✗"} {status.text}</p>
    {/if}
  {/if}

  <details>
    <summary>How this works</summary>
    <p>
      A unit carries its picture's fingerprint, and its IPFS address is computed from it. With a
      gateway set, the wallet asks it first, then zecboat.com. Whatever answers, the picture is shown
      only if it matches the fingerprint. A gateway learns which picture you opened; your own node
      learns nothing it did not already have.
    </p>
  </details>
</div>

<style>
  .line { margin: 0 0 0.75rem; }
  .mark.ok { color: #22c55e; font-weight: 700; }
  .mark.none { color: var(--text-secondary, #9ca3af); }
  .row { display: flex; gap: 0.5rem; margin-bottom: 0.5rem; align-items: center; }
  .row input { flex: 1; }
  .btn.link { background: none; border: none; color: var(--secondary-accent-color, #3fc1b0); padding: 0.2rem 0; cursor: pointer; }
  .status { margin: 0.25rem 0 0.5rem; color: #22c55e; }
  .status.bad { color: #f87171; }
  .note { color: var(--text-secondary, #9ca3af); }
  details { margin-top: 0.5rem; color: var(--text-secondary, #9ca3af); font-size: 0.9rem; }
</style>
