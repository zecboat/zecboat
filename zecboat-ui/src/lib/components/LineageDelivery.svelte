<script lang="ts">
  // Lineage records on their way out (0.7.1). A lading used to be delivered once, to one fixed
  // address, and a failure was a console line. Here it is a mark the user can see, with one
  // button to retry, one to save it as a file for the recipient, and one to take a file in.
  //
  // `txid` narrows it to the record of one transfer: the line shown under a finished send.
  // Without it this is the Settings card, which also holds the drop-box choice.
  import { invoke } from "@tauri-apps/api/core";

  type Outgoing = {
    asset_id: string; consignment_hash: string; txid: string; recipient: string;
    delivered: boolean; carried: boolean; delivered_at: string | null; note: string | null; created_at: string;
  };
  type Box = { choice: string; in_use: string | null };

  let { txid = null }: { txid?: string | null } = $props();

  let rows = $state<Outgoing[]>([]);
  let box = $state<Box | null>(null);
  let busy = $state<string | null>(null);
  let message = $state<{ ok: boolean; text: string } | null>(null);
  let editing = $state(false);
  let mode = $state<"auto" | "custom" | "off">("auto");
  let custom = $state("");
  let fileInput: HTMLInputElement;

  const shown = $derived(txid ? rows.filter((r) => r.txid === txid.toLowerCase()) : rows);
  const waiting = $derived(rows.filter((r) => !r.delivered).length);

  async function load() {
    try { rows = await invoke<Outgoing[]>("lineage_outgoing"); } catch { rows = []; }
    try {
      box = await invoke<Box>("get_dropbox");
      mode = box.choice === "off" ? "off" : box.choice ? "custom" : "auto";
      custom = box.choice && box.choice !== "off" ? box.choice : "";
    } catch { box = null; }
  }
  load();

  function short(s: string, n = 10) { return s.length > n * 2 ? `${s.slice(0, n)}…${s.slice(-6)}` : s; }
  function where(b: Box | null) {
    if (!b) return "…";
    if (!b.in_use) return "none: records are handed over as files";
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
    const choice = mode === "auto" ? "" : mode === "off" ? "off" : custom.trim();
    message = null;
    try {
      await invoke("set_dropbox", { choice });
      if (choice) localStorage.setItem("zecboat.dropbox", choice); else localStorage.removeItem("zecboat.dropbox");
      editing = false; await load();
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
    <span class="mark {box?.in_use ? 'ok' : 'wait'}">●</span>
    <span class="where" title="Where a lineage record is left for the recipient to collect. It is sealed: only the recipient's wallet can open it. The drop-box does see the network addresses of both sides.">Drop-box: {where(box)}</span>
    <button class="mini" onclick={() => (editing = !editing)}>{editing ? "Close" : "Change"}</button>
  </div>
  {#if editing}
    <div class="edit">
      <label><input type="radio" bind:group={mode} value="auto" /> Automatic</label>
      <label><input type="radio" bind:group={mode} value="custom" /> My own</label>
      <label><input type="radio" bind:group={mode} value="off" /> None, files only</label>
      {#if mode === "custom"}
        <input type="text" bind:value={custom} placeholder="https://… or file:///folder" spellcheck="false" />
      {/if}
      <button class="mini primary" onclick={saveBox} disabled={mode === "custom" && !custom.trim()}>Save</button>
    </div>
  {/if}

  {#if rows.length}
    <div class="list">
      {#each shown as r}
        <div class="item">
          <span class="mark {r.delivered ? 'ok' : 'wait'}" title={r.carried ? "Carried in the transfer itself" : r.delivered ? `Delivered ${r.delivered_at ?? ""}` : (r.note ?? "Not delivered yet")}>{r.delivered ? "✓" : "⚠"}</span>
          <span class="mono" title="Transfer {r.txid}">to {short(r.recipient, 8)}</span>
          <span class="when">{r.created_at.slice(0, 10)}</span>
          <span class="spacer"></span>
          {#if !r.carried}
            <button class="mini" onclick={() => retry(r.consignment_hash)} disabled={!!busy}>{r.delivered ? "Send again" : "Retry"}</button>
          {/if}
          <button class="mini" onclick={() => save(r.consignment_hash)} disabled={!!busy}>Save file</button>
        </div>
      {/each}
    </div>
    {#if waiting > 1}
      <button class="mini" onclick={() => retry(null)} disabled={!!busy}>Retry all {waiting} waiting</button>
    {/if}
  {/if}

  <div class="import">
    <input type="file" accept=".json,application/json" bind:this={fileInput} onchange={takeFile} hidden />
    <button class="mini" onclick={() => fileInput.click()} disabled={!!busy}>Open a lineage file…</button>
  </div>
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
  .mini { font-size: 0.8rem; padding: 0.25rem 0.6rem; border-radius: 6px; border: 1px solid rgba(255, 255, 255, 0.2); background: transparent; color: inherit; cursor: pointer; }
  .mini:hover:not(:disabled) { background: rgba(255, 255, 255, 0.08); }
  .mini:disabled { opacity: 0.5; cursor: default; }
  .mini.primary { border-color: rgba(52, 211, 153, 0.6); color: #34d399; }
  .msg { margin: 0.6rem 0 0; font-size: 0.85rem; overflow-wrap: anywhere; }
  .msg.ok { color: #34d399; }
  .msg.bad { color: #fca5a5; }
</style>
