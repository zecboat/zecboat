<script lang="ts">
  // Lineage, as the user sees it (0.7.1).
  //
  // The Settings card is one switch and a repair kit. The switch: lineage travels in the
  // transfer itself (the Knotline), so there is nothing to deliver and nobody in the middle. The
  // repair kit: a sent record can be saved as a file for the recipient, and a file can be opened,
  // for the cases the Knotline does not cover (an older wallet on the other side, the switch off).
  // A drop-box is still possible but only if one is named; none is contacted by default.
  //
  // `txid` narrows the component to the record of one transfer: the line under a finished send.
  import { invoke } from "@tauri-apps/api/core";

  type Outgoing = {
    asset_id: string; consignment_hash: string; txid: string; recipient: string;
    delivered: boolean; carried: boolean; delivered_at: string | null; note: string | null; created_at: string;
  };
  type Box = { choice: string; in_use: string | null };
  type Route = { route: "knotline" | "whole" | "off"; source: "settings" | "default" | "environment" };
  type ChainSource = { choice: "auto" | "node" | "provider"; source: string };

  let { txid = null }: { txid?: string | null } = $props();

  let rows = $state<Outgoing[]>([]);
  let box = $state<Box | null>(null);
  let busy = $state<string | null>(null);
  let message = $state<{ ok: boolean; text: string } | null>(null);
  let mode = $state<"custom" | "off">("off");
  let route = $state<Route | null>(null);
  let chain = $state<ChainSource | null>(null);
  let custom = $state("");
  let fileInput: HTMLInputElement;

  const shown = $derived(txid ? rows.filter((r) => r.txid === txid.toLowerCase()) : rows);
  const waiting = $derived(rows.filter((r) => !r.delivered).length);

  async function load() {
    try { rows = await invoke<Outgoing[]>("lineage_outgoing"); } catch { rows = []; }
    try {
      box = await invoke<Box>("get_dropbox");
      mode = box.choice && box.choice !== "off" ? "custom" : "off";
      custom = box.choice && box.choice !== "off" ? box.choice : "";
    } catch { box = null; }
    try { route = await invoke<Route>("get_lineage_route"); } catch { route = null; }
    try { chain = await invoke<ChainSource>("get_chain_source"); } catch { chain = null; }
  }

  // Who answers chain questions for lineage and issuance checks. "node": this wallet's own
  // zebrad and nobody else, so a node that is briefly silent means "could not be checked right
  // now" instead of a quiet switch to the provider (audit 2026-10-08).
  async function setChain(next: "auto" | "node" | "provider") {
    message = null;
    try {
      await invoke("set_chain_source", { choice: next });
      localStorage.setItem("zecboat.chain", next);
      await load();
    } catch (e) { message = { ok: false, text: String(e) }; }
  }
  load();

  async function setRoute(next: "knotline" | "off") {
    message = null;
    try {
      await invoke("set_lineage_route", { route: next });
      localStorage.setItem("zecboat.lineage", next);
      await load();
    } catch (e) { message = { ok: false, text: String(e) }; }
  }

  function short(s: string, n = 10) { return s.length > n * 2 ? `${s.slice(0, n)}…${s.slice(-6)}` : s; }
  function where(b: Box | null) {
    if (!b) return "…";
    if (!b.in_use) return "none";
    return b.in_use.replace(/^https?:\/\//, "").replace(/^file:\/\//, "shared folder ");
  }

  async function retry(hash: string | null) {
    busy = hash ?? "all"; message = null;
    try {
      const r = await invoke<{ delivered: number; failed: string[] }>("lineage_redeliver", { consignmentHash: hash });
      message = r.failed.length
        ? { ok: false, text: `Not delivered: ${r.failed[0].split(": ").slice(1).join(": ") || r.failed[0]}` }
        : { ok: true, text: r.delivered ? "Delivered." : "Nothing was waiting." };
    } catch (e) { message = { ok: false, text: String(e) }; }
    busy = null; await load();
  }

  async function save(hash: string) {
    busy = hash; message = null;
    try {
      const path = await invoke<string>("lineage_export", { consignmentHash: hash });
      message = { ok: true, text: `Saved: ${path}. Only the recipient's wallet can open it; send it to them any way you like.` };
    } catch (e) { message = { ok: false, text: String(e) }; }
    busy = null;
  }

  async function takeFile(e: Event) {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (!f) return;
    busy = "import"; message = null;
    try {
      if (f.size > 4 * 1024 * 1024) throw new Error("That file is too large to be a lineage file.");
      const r = await invoke<{ name: string; hops: number }>("lineage_import", { sealed: await f.text() });
      message = { ok: true, text: `Lineage record received for ${r.name}: ${r.hops} proof${r.hops === 1 ? "" : "s"}. Open the item to check it.` };
    } catch (err) { message = { ok: false, text: String(err).replace(/^Error: /, "") }; }
    busy = null; fileInput.value = "";
  }

  async function saveBox() {
    const choice = mode === "off" ? "off" : custom.trim();
    message = null;
    try {
      await invoke("set_dropbox", { choice });
      if (choice) localStorage.setItem("zecboat.dropbox", choice); else localStorage.removeItem("zecboat.dropbox");
      await load();
    } catch (e) { message = { ok: false, text: String(e) }; }
  }
</script>

{#if txid}
  {#each shown as r}
    <div class="line">
      {#if r.carried}
        <span class="mark ok">✓</span> Lineage carried in the transfer
      {:else if r.delivered}
        <span class="mark ok">✓</span> Lineage record delivered
      {:else}
        <span class="mark wait">⚠</span> Lineage record not delivered yet
        <button class="mini" onclick={() => retry(r.consignment_hash)} disabled={!!busy}>Retry</button>
        <button class="mini" onclick={() => save(r.consignment_hash)} disabled={!!busy}>Save file</button>
      {/if}
    </div>
  {/each}
{:else}
  <div class="box-row">
    <span class="mark {route?.route === 'off' ? 'wait' : 'ok'}">●</span>
    <span class="where" title="The lineage record is written into the same transaction as the item, sealed under a one-time key handed to its new owner; earlier owners cannot read what comes after their own sale. No server is needed to deliver it; a wallet without its own node still asks its provider for older records. It adds outputs to the transfer, so the fee is higher; the confirmation screen shows it.">
      {#if route?.route === "off"}Lineage does not travel with a sent item{:else if route?.route === "whole"}Lineage travels in the transfer · whole lading (test route){:else}Lineage travels in the transfer · Knotline{/if}
    </span>
    {#if route?.source === "environment"}
      <span class="when" title="Set by the ZECBOAT_LADING_IN_MEMOS variable this wallet was started with; it outranks this switch.">set at start</span>
    {:else if route?.route === "off"}
      <button class="mini primary" onclick={() => setRoute("knotline")}>Turn on</button>
    {:else}
      <button class="mini" onclick={() => setRoute("off")}>Turn off</button>
    {/if}
  </div>

  <div class="box-row">
    <span class="mark {chain?.choice === 'node' ? 'ok' : 'wait'}">●</span>
    <span class="where" title="Lineage and issuance checks ask the chain for tree roots and outputs. Your own node answers from its own state; a provider answers with its word, and learns which blocks the check touched.">
      {#if chain?.choice === "node"}Chain answers from your own node only{:else if chain?.choice === "provider"}Chain answers from your provider{:else}Chain answers from your node when it answers, else your provider{/if}{#if chain?.source?.startsWith("default")} · decided at start, change it here{/if}
    </span>
    <select class="mini" value={chain?.choice ?? "auto"} onchange={(e) => setChain((e.currentTarget as HTMLSelectElement).value as "auto" | "node" | "provider")}>
      <option value="auto">automatic</option>
      <option value="node">my own node only</option>
      <option value="provider">provider</option>
    </select>
  </div>

  {#if rows.length}
    <div class="list">
      {#each shown as r}
        <div class="item">
          <span class="mark {r.delivered ? 'ok' : 'wait'}" title={r.carried ? "Carried in the transfer itself" : r.delivered ? `Delivered ${r.delivered_at ?? ""}` : (r.note ?? "Not handed over yet")}>{r.delivered ? "✓" : "⚠"}</span>
          <span class="mono" title="Transfer {r.txid}">to {short(r.recipient, 8)}</span>
          <span class="when">{r.created_at.slice(0, 10)}</span>
          <span class="spacer"></span>
          {#if !r.carried && box?.in_use}
            <button class="mini" onclick={() => retry(r.consignment_hash)} disabled={!!busy}>{r.delivered ? "Send again" : "Retry"}</button>
          {/if}
          <button class="mini" onclick={() => save(r.consignment_hash)} disabled={!!busy}>Save file</button>
        </div>
      {/each}
    </div>
  {/if}

  <div class="import">
    <input type="file" accept=".json,application/json" bind:this={fileInput} onchange={takeFile} hidden />
    <button class="mini" onclick={() => fileInput.click()} disabled={!!busy}>Open a lineage file…</button>
  </div>

  <details class="more">
    <summary>Drop-box: {where(box)}</summary>
    <p class="note">Optional. A place where a record is left for the recipient to collect. It cannot read or change a record, but it sees the network address of both sides. None is used unless you name one.</p>
    <div class="edit">
      <label><input type="radio" bind:group={mode} value="off" /> None</label>
      <label><input type="radio" bind:group={mode} value="custom" /> My own</label>
      {#if mode === "custom"}
        <input type="text" bind:value={custom} placeholder="https://… or file:///folder" spellcheck="false" />
      {/if}
      <button class="mini primary" onclick={saveBox} disabled={mode === "custom" && !custom.trim()}>Save</button>
    </div>
    {#if box?.in_use && waiting > 0}
      <button class="mini" onclick={() => retry(null)} disabled={!!busy}>Retry {waiting} waiting</button>
    {/if}
  </details>
{/if}

{#if message}
  <p class="msg {message.ok ? 'ok' : 'bad'}">{message.text}</p>
{/if}

<style>
  .line, .box-row, .item { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; font-size: 0.9rem; }
  .line { margin-top: 0.6rem; }
  .mark.ok { color: #34d399; }
  .mark.wait { color: #fbbf24; }
  .where { flex: 1; min-width: 12rem; overflow-wrap: anywhere; }
  .list { margin-top: 0.8rem; display: flex; flex-direction: column; gap: 0.4rem; }
  .item { padding: 0.45rem 0.6rem; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; }
  .mono { font-family: ui-monospace, monospace; font-size: 0.8rem; }
  .when { opacity: 0.6; font-size: 0.8rem; }
  .spacer { flex: 1; }
  .edit { display: flex; flex-wrap: wrap; gap: 0.6rem 1rem; align-items: center; margin-top: 0.6rem; font-size: 0.9rem; }
  .edit input[type="text"] { flex: 1 1 100%; padding: 0.45rem 0.6rem; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.15); background: rgba(0, 0, 0, 0.25); color: inherit; }
  .import { margin-top: 0.8rem; }
  .more { margin-top: 0.8rem; font-size: 0.85rem; }
  .more summary { cursor: pointer; opacity: 0.75; }
  .note { margin: 0.5rem 0; opacity: 0.75; }
  .mini { font-size: 0.8rem; padding: 0.25rem 0.6rem; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.2); background: transparent; color: inherit; cursor: pointer; }
  .mini:hover:not(:disabled) { background: rgba(255, 255, 255, 0.08); }
  .mini:disabled { opacity: 0.5; cursor: default; }
  .mini.primary { border-color: rgba(52, 211, 153, 0.6); color: #34d399; }
  .msg { margin: 0.6rem 0 0; font-size: 0.85rem; overflow-wrap: anywhere; }
  .msg.ok { color: #34d399; }
  .msg.bad { color: #fca5a5; }
</style>
