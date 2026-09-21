<script lang="ts">
  import CopyButton from "./CopyButton.svelte";
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  type Asset = {
    asset_id: string; name: string; amount: number; quantity: number;
    symbol: string | null; decimals: number; image_hash: string | null;
    metadata_uri: string | null; dialect: string; pools: string[];
  };
  type Verification = {
    verified: boolean; expected_hash: string; actual_hash: string;
    source_url: string; bytes: number; image: string | null;
  };

  // Split "Happy Birthday #010" into the range name and the design number.
  //
  // The memo is on-chain and immutable -- §5.2 requires byte-identical reproduction, so the
  // name will read "Happy Birthday #010" forever and nothing here changes that. What the
  // wallet DISPLAYS is ours, and rendering the number at the same weight as the name makes it
  // look like a denominator: "#010" reading as "10 of 10". It is not. ZMAP-v0.3 §12.2 says an
  // issuer's mint count is a lower bound on circulating carriers, and §13 says the protocol
  // "does not prove scarcity" -- so a UI that implies an edition size is claiming something
  // the protocol contradicts in writing.
  //
  // Shown small and secondary, it reads as what it is: a design number within a range, the way
  // a card shop has numbered stock forever. The number stays useful for telling two designs
  // apart; it stops implying how many exist.
  function splitName(name: string): { range: string; design: string | null } {
    const m = name.match(/^(.*?)\s*#\s*(\d+)\s*$/);
    return m ? { range: m[1].trim(), design: `#${m[2]}` } : { range: name, design: null };
  }

  let assets = $state<Asset[]>([]);
  let selectedAssetMetadata = $state<string | null>(null);
  let selectedAssetId = $state<string | null>(null);
  let isLoadingMetadata = $state(false);
  let verification = $state<Verification | null>(null);
  let verifyError = $state<string | null>(null);
  let isVerifying = $state(false);

  onMount(async () => {
    try {
      assets = await invoke("get_zsas");
    } catch (e) {
      console.error("Failed to load ZSAs:", e);
    }
  });

  // Asked of the backend rather than hardcoded, so ZECBOAT_REGISTRY reaches the UI too.
  // Previously fixed at https://zecboat.com, which answers 301 today — a fresh install
  // showed no artwork and no explanation.
  let registryBase = $state("https://zecboat.com");
  invoke<string>("registry_base").then((b) => { if (b) registryBase = b; }).catch(() => {});

  function getImageUrl(assetId: string) {
    if (assetId && assetId.length > 20) {
      return `${registryBase}/collection/${assetId}.png`;
    }
    return "";
  }
  
  async function showAssetDetails(assetId: string) {
    selectedAssetId = assetId;
    isLoadingMetadata = true;
    isVerifying = true;
    verification = null;
    verifyError = null;

    // Metadata is descriptive and host-trusted. The image check is the part that needs no trust,
    // so it runs independently — one failing must not hide the other's result.
    invoke<Verification>("verify_asset_image", { assetId })
      .then((v) => { verification = v; })
      .catch((e: any) => { verifyError = String(e); })
      .finally(() => { isVerifying = false; });

    try {
      selectedAssetMetadata = await invoke("view_asset", { assetId });
    } catch (e: any) {
      selectedAssetMetadata = `{"error": "${String(e).replace(/"/g, "'")}"}`;
    } finally {
      isLoadingMetadata = false;
    }
  }

  function closeDetails() {
    selectedAssetMetadata = null;
    selectedAssetId = null;
    verification = null;
    verifyError = null;
  }

  // Straight parse of the published metadata. The previous version also base64-decoded an
  // `asset_metadata` field and merged it in — that field belongs to the old z_viewasset RPC
  // response, not to the registry JSON, so it was always absent and now would render as a null row.
  let parsedMetadata = $derived.by(() => {
    if (!selectedAssetMetadata) return null;
    try {
      return JSON.parse(selectedAssetMetadata) as Record<string, unknown>;
    } catch {
      return null;
    }
  });
</script>

<div class="zsa-gallery card">
  {#if assets.length}
    <p class="preview-note">
      Thumbnails are <strong>unverified previews</strong> fetched by asset id. Open an asset to check
      its artwork against the hash committed in the memo.
    </p>
  {/if}
  <div class="asset-grid">
    {#each assets as asset}
      {@const n = splitName(asset.name)}
      <div class="asset-item" title="ID: {asset.asset_id}" onclick={() => showAssetDetails(asset.asset_id)}>
        <div class="asset-icon">
          <!-- "preview", not "unverified". These bytes genuinely are unchecked — they come from the
               registry by asset id and nothing has hashed them — but stamping "unverified" on every
               tile reads as a fault rather than as a description. The note above states the
               qualification once; the hover title keeps it on each tile; and opening the asset is
               where the real check happens. -->
          <span class="preview-chip" title="Preview fetched from the registry — nothing has verified these bytes. Open the asset to check it against the memo.">preview</span>
          {#if getImageUrl(asset.asset_id)}
            <img 
              src={getImageUrl(asset.asset_id)} 
              alt={asset.name} 
              style="width: 100%; height: auto; border-radius: 8px; display: block;" 
              onerror={(e) => { const t = e.currentTarget as HTMLImageElement; t.src = '/logo.png'; t.style.padding = '10px'; t.style.background = '#2a2a32'; }} 
            />
          {:else}
            📦
          {/if}
        </div>
        <div class="asset-info">
          <span class="asset-name">
            {n.range}{#if n.design}<span class="design-no" title="Design number within the range — not an edition size">{n.design}</span>{/if}
          </span>
          <span class="asset-balance">{asset.amount} {asset.amount === 1 ? 'unit' : 'units'}</span>
        </div>
      </div>
    {:else}
      <div class="empty-state">No Shielded Assets found.</div>
    {/each}
  </div>

  {#if isLoadingMetadata || selectedAssetMetadata}
    <div class="modal-backdrop" onclick={closeDetails}>
      <div class="modal-content" onclick={(e) => e.stopPropagation()}>
        <div class="modal-header">
          <h3>Asset Metadata</h3>
          <button class="close-btn" onclick={closeDetails}>✕</button>
        </div>
        <div class="modal-body">
          {#if isVerifying}
            <div class="verify-badge checking">Verifying artwork against the memo…</div>
          {:else if verification?.verified && verification.image}
            <div class="modal-image-container">
              <!-- These are the bytes that were hashed. Rendering the remote URL again here would
                   display something nobody checked. -->
              <img src={verification.image} alt={selectedAssetId ?? 'Asset'} />
            </div>
            <div class="verify-badge ok">
              ✓ Artwork matches the memo&rsquo;s commitment
              <span class="verify-detail">sha256 {verification.expected_hash.slice(0, 16)}… · {(verification.bytes / 1024).toFixed(0)} KB</span>
            </div>
            <!-- The check above is honest about what it did, but a green tick with nothing beside it
                 still reads as "this asset is genuine". It is not that: a forger can copy a memo and
                 point it at the same artwork, and this check passes for them too. State the gap
                 rather than leave the tick to be over-read. Replaced by the four-state display once
                 issuance verification lands. -->
            <div class="verify-badge unknown">
              Issuance not checked
              <span class="verify-detail">
                This confirms the artwork matches the identifier in the memo. It does not confirm who
                issued this asset, or that this note is the one they issued.
              </span>
            </div>
          {:else if verification && !verification.verified}
            <div class="verify-badge bad">
              ✕ Artwork does NOT match the memo
              <span class="verify-detail mono">memo {verification.expected_hash.slice(0, 16)}… · served {verification.actual_hash.slice(0, 16)}…</span>
            </div>
          {:else if verifyError}
            <div class="verify-badge unknown">
              Artwork could not be verified
              <span class="verify-detail">{verifyError}</span>
            </div>
          {/if}
          {#if isLoadingMetadata}
            <div class="loading">Fetching published metadata…</div>
          {:else if parsedMetadata}
            <div class="metadata-table">
              <div class="meta-row">
                <span class="meta-label">ASSET ID</span>
                <span class="meta-value mono">{selectedAssetId}</span>
                <CopyButton value={selectedAssetId ?? ''} label="Copy" compact title="Copy the asset id" />
              </div>
              {#if parsedMetadata.error}
                <div class="meta-row">
                  <span class="meta-label">METADATA</span>
                  <span class="meta-value">{parsedMetadata.error}</span>
                </div>
              {:else}
                <!-- Rendered from whatever the registry actually publishes. The previous version
                     hardcoded TOTAL SUPPLY / ISSUE HEIGHT / DESCRIPTION, none of which exist in the
                     real schema, so they always read "N/A" — leftovers from the fabricated-metadata
                     branch removed in v0.5.1. -->
                {#each Object.entries(parsedMetadata) as [k, v]}
                  <div class="meta-row">
                    <span class="meta-label">{k.replace(/_/g, ' ').toUpperCase()}</span>
                    <span class="meta-value {String(v).length > 40 ? 'mono' : ''}">{v}</span>
                  </div>
                {/each}
              {/if}
            </div>
          {:else}
            <pre>{selectedAssetMetadata}</pre>
          {/if}
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .card {
    background: var(--surface-color, #1e1e24);
    border: 1px solid var(--border-color, #333);
    border-radius: 16px;
    padding: 1.5rem;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    display: flex;
    flex-direction: column;
    gap: 1rem;
    height: 100%;
  }

  .header {
    border-bottom: 1px solid var(--border-color, #333);
    padding-bottom: 0.75rem;
  }

  h2 {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 600;
    color: var(--text-primary, #fff);
  }

  .preview-note {
    margin: 0 0 14px;
    font-size: 0.8rem;
    color: #8b949e;
    line-height: 1.45;
  }
  .preview-note strong { color: #d29922; font-weight: 600; }

  .asset-icon { position: relative; }
  .preview-chip {
    position: absolute;
    top: 6px;
    right: 6px;
    z-index: 1;
    padding: 2px 6px;
    border-radius: 999px;
    font-size: 0.6rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    color: #d29922;
    background: rgba(13, 17, 23, 0.82);
    border: 1px solid rgba(210, 153, 34, 0.45);
    pointer-events: none;
  }

  .verify-badge {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 0.85rem;
    font-weight: 600;
    margin-bottom: 12px;
  }
  .verify-badge.ok      { background: rgba(46, 160, 67, 0.15); color: #3fb950; border: 1px solid rgba(46, 160, 67, 0.4); }
  .verify-badge.bad     { background: rgba(248, 81, 73, 0.15); color: #f85149; border: 1px solid rgba(248, 81, 73, 0.4); }
  .verify-badge.unknown { background: rgba(210, 153, 34, 0.12); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.35); }
  .verify-badge.checking { background: rgba(139, 148, 158, 0.12); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.3); }
  .verify-detail {
    font-weight: 400;
    font-size: 0.75rem;
    opacity: 0.85;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    word-break: break-all;
  }

  .asset-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
    gap: 1rem;
    margin-top: 0.5rem;
  }

  .asset-item {
    background: var(--surface-hover, #2a2a32);
    border: 1px solid var(--border-color, #333);
    border-radius: 12px;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    transition: transform 0.2s, box-shadow 0.2s;
    cursor: pointer;
  }

  .asset-item:hover {
    transform: translateY(-4px);
    box-shadow: 0 8px 24px rgba(0, 230, 118, 0.15);
    border-color: var(--accent-color, #00e676);
  }

  .asset-icon {
    font-size: 2.5rem;
    margin-bottom: 0.5rem;
    line-height: 1;
  }

  .asset-info {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .asset-name {
    font-weight: 600;
    font-size: 0.9rem;
    color: var(--text-primary, #fff);
  }

  /* Secondary on purpose — see splitName(). At the same weight as the range name, a design
     number reads as an edition size. */
  .design-no {
    margin-left: 0.4rem;
    font-weight: 400;
    font-size: 0.8em;
    color: var(--text-secondary, #999);
  }

  .asset-balance {
    font-size: 0.8rem;
    color: var(--text-secondary, #999);
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  }
  
  .empty-state {
    grid-column: 1 / -1;
    text-align: center;
    color: var(--text-secondary);
    padding: 2rem 0;
  }

  .modal-backdrop {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
  }

  .modal-content {
    background: var(--surface-color, #1e1e24);
    border: 1px solid var(--border-color, #333);
    border-radius: 12px;
    width: 90%;
    max-width: 600px;
    max-height: 80vh;
    display: flex;
    flex-direction: column;
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.5);
    animation: slideUp 0.3s ease-out forwards;
  }

  @keyframes slideUp {
    from { opacity: 0; transform: translateY(20px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1.25rem 1.5rem;
    border-bottom: 1px solid var(--border-color, #333);
  }

  .modal-header h3 {
    margin: 0;
    font-size: 1.2rem;
    color: var(--text-primary);
  }

  .close-btn {
    background: transparent;
    border: none;
    color: var(--text-secondary);
    font-size: 1.2rem;
    cursor: pointer;
  }

  .close-btn:hover {
    color: var(--text-primary);
  }

  .modal-body {
    padding: 1.5rem;
    overflow-y: auto;
  }

  .modal-body pre {
    background: var(--surface-hover, #2a2a32);
    padding: 1rem;
    border-radius: 8px;
    border: 1px solid var(--border-color, #333);
    overflow-x: auto;
    font-size: 0.85rem;
    color: var(--accent-color, #1D7989);
    margin: 0;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .modal-image-container {
    display: flex;
    justify-content: center;
    margin-bottom: 1.5rem;
  }

  .modal-image-container img {
    max-width: 250px;
    height: auto;
    border-radius: 12px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
  }

  .loading {
    text-align: center;
    color: var(--text-secondary);
    padding: 2rem;
  }

  .metadata-table {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    background: var(--surface-hover, #2a2a32);
    padding: 1.5rem;
    border-radius: 12px;
    border: 1px solid var(--border-color, #333);
  }

  .meta-row {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .meta-label {
    font-size: 0.85rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .meta-value {
    color: var(--text-primary);
    font-size: 1.05rem;
  }
.meta-value.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.85rem;
  word-break: break-all;
  color: var(--accent-color, #1D7989);
}

.modal-body pre {
  background: var(--surface-hover);
  padding: 1rem;
  border-radius: 8px;
  overflow-x: auto;
}
</style>