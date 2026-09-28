<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import CopyButton from "./CopyButton.svelte";

  // A3b: collections in the Zecboat Registry, read and checked by this wallet from the chain.
  // Visual first: one status mark and one button per collection; the record behind "Details".

  type Registration = {
    name: string; ik: string; registration_txid: string; registration_height: number;
    close_txid: string; mint_height: number; close_height: number; manifest_sha256: string;
    ufvk: string | null; signature_ok: boolean; ufvk_hash_ok: boolean; valid: boolean; reason: string | null;
  };
  type RegistryView = { scanned_to: number; node: string; registrations: Registration[] };
  type Check = { n: number; label: string; pass: boolean; detail: string | null };
  type Unit = {
    unit: number; asset_id: string; desc: string; name: string; image_sha256: string;
    genesis_txid: string; genesis_action: number; genesis_cmx: string;
  };
  type AuditReport = {
    ik: string; name: string; passed: boolean; checks: Check[]; units: Unit[];
    close_height: number | null; close_txid: string | null; count: number | null;
    birthday: number; audited_to: number; node: string; audited_at: string;
  };

  let view = $state<RegistryView | null>(null);
  let audits = $state<Record<string, AuditReport>>({});
  let scanning = $state(false);
  let auditing = $state<string | null>(null);
  let error = $state<string | null>(null);
  let auditError = $state<Record<string, string>>({});
  let details = $state<string | null>(null);
  let showInvalid = $state(false);
  type Held = { count: number; asset_ids: string[]; bad_ids: number };
  let held = $state<Record<string, Held>>({});
  let query = $state("");
  let mineOnly = $state(false);

  const valid = $derived(view ? view.registrations.filter((r) => r.valid) : []);
  const mine = (r: Registration) => (held[r.ik.toLowerCase()]?.count ?? 0) > 0;
  // Search matches name, collection key, any unit's asset id, or a transaction id (prefixes).
  const matches = (r: Registration, q: string) => {
    q = q.trim().toLowerCase();
    if (!q) return true;
    const units = audits[key(r)]?.units ?? [];
    return (
      r.name.toLowerCase().includes(q) ||
      r.ik.startsWith(q) ||
      r.registration_txid.startsWith(q) ||
      r.close_txid.startsWith(q) ||
      units.some((u) => u.asset_id.startsWith(q) || u.name.toLowerCase().includes(q))
    );
  };
  // Held first, then checked-and-genuine, then the rest.
  const rank = (r: Registration) => (mine(r) ? 0 : audits[key(r)]?.passed ? 1 : 2);
  const shown = $derived(
    valid.filter((r) => (!mineOnly || mine(r)) && matches(r, query)).sort((a, b) => rank(a) - rank(b))
  );
  const invalid = $derived(view ? view.registrations.filter((r) => !r.valid) : []);
  // A name used twice is flagged, never merged: only the key tells collections apart.
  const dupNames = $derived(new Set(valid.map((r) => r.name).filter((n, i, a) => a.indexOf(n) !== i)));

  const key = (r: Registration) => `${r.registration_txid}:${r.ik}`;
  const fp = (ik: string) => `${ik.slice(0, 6)}…${ik.slice(-6)}`;
  const when = (secs: string) => {
    const n = Number(secs);
    return Number.isFinite(n) && n > 0 ? new Date(n * 1000).toLocaleDateString() : "";
  };

  async function load() {
    try {
      view = await invoke<RegistryView>("get_collections");
      audits = await invoke<Record<string, AuditReport>>("get_collection_audits");
      held = await invoke<Record<string, Held>>("get_collection_holdings");
    } catch (e) {
      error = String(e);
    }
  }

  async function refresh() {
    scanning = true;
    error = null;
    try {
      view = await invoke<RegistryView>("scan_collections");
    } catch (e) {
      error = String(e);
    } finally {
      scanning = false;
    }
  }

  async function check(r: Registration) {
    const k = key(r);
    auditing = k;
    const { [k]: _drop, ...rest } = auditError;
    auditError = rest;
    try {
      const a = await invoke<AuditReport>("audit_collection", { ik: r.ik, registrationTxid: r.registration_txid });
      audits = { ...audits, [k]: a };
    } catch (e) {
      auditError = { ...auditError, [k]: String(e) };
    } finally {
      auditing = null;
    }
  }

  onMount(async () => {
    await load();
    if (view && view.scanned_to === 0) await refresh();
  });
</script>

<div class="collections">
  <!-- The page title comes from the layout's top bar, as on every other page. -->
  <div class="top">
    <button class="refresh" onclick={refresh} disabled={scanning} title="Read the registry from the chain again">
      <span class:spin={scanning}>⟳</span>
    </button>
  </div>

  <div class="filters">
    <input class="search" type="search" placeholder="🔎  name, key or asset id" bind:value={query} />
    <button class="chip" class:on={mineOnly} onclick={() => (mineOnly = !mineOnly)}>Mine</button>
  </div>

  {#if error}
    <div class="banner bad">✗ {error}</div>
  {/if}

  {#if scanning && !view?.registrations.length}
    <div class="empty"><span class="spin big">⟳</span></div>
  {:else if view && view.scanned_to > 0 && valid.length === 0}
    <div class="empty">No collections yet</div>
  {:else if valid.length > 0 && shown.length === 0}
    <div class="empty">Nothing matches</div>
  {/if}

  <div class="grid">
    {#each shown as r (key(r))}
      {@const a = audits[key(r)]}
      {@const k = key(r)}
      <div class="card" class:ok={a?.passed} class:bad={a && !a.passed}>
        <div class="status" title={a ? (a.passed ? "Checked on the chain: genuine" : "The check failed") : "Not checked yet"}>
          {#if auditing === k}
            <span class="spin">⟳</span>
          {:else if a?.passed}
            ✓
          {:else if a}
            ✗
          {:else}
            ?
          {/if}
        </div>

        <div class="name">{r.name}</div>
        {#if mine(r)}
          <div class="yours" title="Units of this collection in your wallet, each id checked against the collection's key">
            ✦ {held[r.ik.toLowerCase()].count} yours
          </div>
        {/if}
        {#if (held[r.ik.toLowerCase()]?.bad_ids ?? 0) > 0}
          <div class="err" title="A note in your wallet claims this collection but its id does not match the collection's key">
            ⚠ {held[r.ik.toLowerCase()].bad_ids} fake
          </div>
        {/if}
        <div class="sub">
          {#if a?.passed}
            {a.count} units · genuine
          {:else if a}
            check failed
          {:else if auditing === k}
            checking…
          {:else}
            not checked
          {/if}
          {#if dupNames.has(r.name)}<span class="warn" title="Another collection uses this name. Compare the keys.">⚠</span>{/if}
        </div>

        {#if auditError[k]}
          <div class="err" title={auditError[k]}>✗ couldn't check</div>
        {/if}

        <div class="actions">
          <button class="btn" onclick={() => check(r)} disabled={auditing !== null}>
            {a ? "Check again" : "Check"}
          </button>
          <button class="link" onclick={() => (details = details === k ? null : k)}>
            {details === k ? "Hide" : "Details"}
          </button>
        </div>

        {#if details === k}
          <div class="details">
            <div class="kv"><span>Key</span><span class="mono">{fp(r.ik)} <CopyButton value={r.ik} label="Copy" compact /></span></div>
            <div class="kv"><span>Minted · closed</span><span>{r.mint_height.toLocaleString()} · {r.close_height.toLocaleString()}</span></div>
            <div class="kv"><span>Registered</span><span>{r.signature_ok && r.ufvk_hash_ok ? "✓" : "✗"} {r.registration_height.toLocaleString()}</span></div>
            {#if a}
              <div class="kv"><span>Checked</span><span>{a.checks.filter((c) => c.pass).length}/{a.checks.length} ✓ · to {a.audited_to.toLocaleString()} {when(a.audited_at)}</span></div>
              {#if a.units.length}
                <div class="units">
                  {#each a.units as u (u.asset_id)}
                    <span class="unit" class:mine={held[r.ik.toLowerCase()]?.asset_ids.includes(u.asset_id)} title={`${u.name}\nid ${u.asset_id}\nborn ${u.genesis_txid} #${u.genesis_action}\nartwork ${u.image_sha256}`}>#{u.unit}</span>
                  {/each}
                </div>
              {/if}
              <details class="checks">
                <summary>All {a.checks.length} checks</summary>
                <ol>
                  {#each a.checks as c (c.n)}
                    <li class:fail={!c.pass}>{c.pass ? "✓" : "✗"} {c.label}</li>
                  {/each}
                </ol>
              </details>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
  </div>

  {#if invalid.length > 0}
    <button class="link small" onclick={() => (showInvalid = !showInvalid)}>
      ✗ {invalid.length} invalid registration{invalid.length === 1 ? "" : "s"} {showInvalid ? "▴" : "▾"}
    </button>
    {#if showInvalid}
      {#each invalid as r (key(r))}
        <div class="invalid" title={r.reason ?? ""}>✗ {r.name} · {fp(r.ik)}</div>
      {/each}
    {/if}
  {/if}

  {#if view && view.scanned_to > 0}
    <div class="foot" title={`node ${view.node}`}>block {view.scanned_to.toLocaleString()}</div>
  {/if}
</div>

<style>
  .collections { display: flex; flex-direction: column; gap: 1rem; max-width: 900px; }
  .top { display: flex; align-items: center; justify-content: flex-end; }
  .refresh {
    width: 2.4rem; height: 2.4rem; border-radius: 50%; border: 1px solid var(--border-color, #2c2c2c);
    background: var(--surface-color, #1e1e1e); color: var(--text-primary, #fff); font-size: 1.2rem; cursor: pointer;
  }
  .refresh:disabled { cursor: default; opacity: 0.7; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 1rem; }
  .card {
    background: var(--surface-color, #1e1e1e); border: 2px solid var(--border-color, #2c2c2c);
    border-radius: 18px; padding: 1.3rem 1.1rem 1rem; display: flex; flex-direction: column;
    align-items: center; text-align: center; gap: 0.35rem;
  }
  .card.ok { border-color: rgba(76, 175, 80, 0.55); }
  .card.bad { border-color: rgba(255, 82, 82, 0.6); }
  .status {
    width: 3.6rem; height: 3.6rem; border-radius: 50%; display: flex; align-items: center; justify-content: center;
    font-size: 1.9rem; font-weight: 700; background: rgba(255, 255, 255, 0.06); color: var(--text-secondary, #999);
  }
  .card.ok .status { background: rgba(76, 175, 80, 0.18); color: #4caf50; }
  .card.bad .status { background: rgba(255, 82, 82, 0.18); color: #ff5252; }
  .name { font-weight: 700; font-size: 1.05rem; color: var(--text-primary, #fff); margin-top: 0.3rem; }
  .sub { font-size: 0.85rem; color: var(--text-secondary, #999); }
  .card.ok .sub { color: #81c784; }
  .card.bad .sub { color: #ff8a80; }
  .warn { color: #ffb74d; margin-left: 0.3rem; cursor: help; }
  .err { font-size: 0.8rem; color: #ff8a80; cursor: help; }
  .actions { display: flex; gap: 0.8rem; align-items: center; margin-top: 0.5rem; }
  .btn {
    background: var(--accent-color, #1D7989); color: #fff; border: none; border-radius: 999px;
    padding: 0.45rem 1.2rem; font-weight: 600; cursor: pointer;
  }
  .btn:disabled { opacity: 0.55; cursor: default; }
  .link { background: none; border: none; color: var(--text-secondary, #999); cursor: pointer; font-size: 0.85rem; padding: 0; }
  .link.small { align-self: flex-start; }
  .details { width: 100%; margin-top: 0.7rem; padding-top: 0.7rem; border-top: 1px solid var(--border-color, #2c2c2c); text-align: left; font-size: 0.8rem; display: flex; flex-direction: column; gap: 0.35rem; }
  .kv { display: flex; justify-content: space-between; gap: 0.6rem; color: var(--text-primary, #fff); }
  .kv > span:first-child { color: var(--text-secondary, #999); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
  .units { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.3rem; }
  .unit.mine { background: rgba(255, 213, 79, 0.2); color: #ffd54f; font-weight: 700; }
  .yours { font-size: 0.8rem; font-weight: 700; color: #ffd54f; background: rgba(255, 213, 79, 0.12); border-radius: 999px; padding: 0.1rem 0.6rem; }
  .filters { display: flex; gap: 0.6rem; align-items: center; }
  .search {
    flex: 1; background: var(--surface-color, #1e1e1e); border: 1px solid var(--border-color, #2c2c2c);
    border-radius: 999px; padding: 0.55rem 1rem; color: var(--text-primary, #fff); font-size: 0.9rem;
  }
  .chip {
    background: none; border: 1px solid var(--border-color, #2c2c2c); color: var(--text-secondary, #999);
    border-radius: 999px; padding: 0.45rem 1rem; cursor: pointer; font-weight: 600;
  }
  .chip.on { background: rgba(255, 213, 79, 0.15); border-color: rgba(255, 213, 79, 0.5); color: #ffd54f; }
  .unit { background: rgba(76, 175, 80, 0.12); color: #81c784; border-radius: 6px; padding: 0.1rem 0.4rem; cursor: help; }
  .checks summary { cursor: pointer; color: var(--text-secondary, #999); margin-top: 0.3rem; }
  .checks ol { list-style: none; padding: 0; margin: 0.4rem 0 0; display: flex; flex-direction: column; gap: 0.2rem; }
  .checks li.fail { color: #ff8a80; }
  .invalid { font-size: 0.8rem; color: var(--text-secondary, #999); cursor: help; }
  .empty { text-align: center; color: var(--text-secondary, #999); padding: 2rem 0; }
  .foot { font-size: 0.75rem; color: var(--text-secondary, #999); text-align: right; cursor: help; }
  .banner.bad { color: #ff8a80; font-size: 0.85rem; }
  .spin { display: inline-block; animation: spin 1s linear infinite; }
  .spin.big { font-size: 2rem; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
