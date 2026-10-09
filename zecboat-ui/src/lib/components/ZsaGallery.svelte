<script lang="ts">
  import CopyButton from "./CopyButton.svelte";
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";

  type Asset = {
    asset_id: string; name: string; amount: number; quantity: number;
    symbol: string | null; decimals: number; image_hash: string | null;
    metadata_uri: string | null; dialect: string; pools: string[];
    // Wake (chapter 8): whether a lading is held for this asset, what the memo commits to,
    // and when it last verified. The verdict itself comes from verify_lineage on open.
    wake?: { has_lading: boolean; consignment_hash: string | null; verified_at_height: number | null; hops: number | null };
  };

  // Lineage badge -- ZMAP v0.5 §9 check 7, WAKE-v1 §8. Five states, never one tick:
  // verified is a proof chain checked against a full node on this machine AND a genesis the
  // issuer's manifest names; provider_checked is the same checks with the chain's answers taken
  // from the wallet's provider (0.7.1: what a wallet without its own node sees); unverified is
  // "could not confirm" (no verdict); no_wake is "no lading held" (unproven, not forged); broken
  // is evidence of forgery or tampering.
  type Wake =
    | { state: 'verified'; hops: number; min_anchor_depth: number; genesis_txid: string; genesis_action_index: number; genesis_source: string; consignment_hash: string; asked: string }
    | { state: 'provider_checked'; hops: number; min_anchor_depth: number; genesis_txid: string; genesis_action_index: number; genesis_source: string; consignment_hash: string; asked: string }
    | { state: 'unverified'; detail: string; consignment_hash: string | null }
    | { state: 'no_wake'; detail: string }
    | { state: 'broken'; failure: string; detail: string };
  let wake = $state<Wake | null>(null);
  // Every copy of the asset this wallet holds, each judged on its own, when there is more
  // than one: the badge above is the best of them, and a copy someone sent with a broken
  // lineage must be visible beside a genuine unit, not hidden under it (review 2026-10-09).
  type CarrierState = { txid: string; output_index: number; state: Wake };
  let copies = $state<CarrierState[] | null>(null);
  let isCheckingLineage = $state(false);
  // WAKE-v1 §11: no implementation may report "verified" on the strength of a wake proof until
  // the circuit's external review. Until then a passing lineage shows AMBER, "awaiting external
  // review". Flip to true when the review is published with no open soundness issue
  // (~/zebd/wake_audit/01_plan/wake_review_timeline.md). The issuer badge does not depend on it.
  const WAKE_REVIEWED = false;
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

  // Issuance verification -- §9 checks 1, 3, 4 and 5, against an issuer key PINNED in the
  // binary. Deliberately separate from the artwork check: §12.1 forbids presenting checks
  // 1-4 and 6 as "genuine" without 5, so the two results are never merged into one tick.
  type Badge =
    | { state: 'verified'; issuer: string; pinned: boolean; issuer_key?: string | null; issuance_txid: string; issuance_height: number; checks: string[]; caveat: string; found_in_registry_at?: number | null }
    | { state: 'not_listed'; issuer: string; detail: string }
    | { state: 'signature_failed'; detail: string }
    | { state: 'could_not_check'; detail: string };
  let badge = $state<Badge | null>(null);
  let isCheckingIssuance = $state(false);
  let verifyError = $state<string | null>(null);
  let isVerifying = $state(false);

  // Card artwork, keyed by asset id, as hash-verified data: URIs from verify_asset_image.
  //
  // Cards used to build `${registryBase}/collection/${id}.png` client-side. That guessed the
  // extension: Happy Birthday is served as .png and rendered, Barcelona is served as .jpg and
  // every card 404'd to the fallback logo — while opening the asset worked, because the modal
  // already goes through verify_asset_image, which tries the formats server-side and returns
  // the bytes only if they hash to the asset id. Cards now take that same path, so what a
  // tile shows is verified rather than merely fetched, and the extension is never guessed.
  let cardImages = $state<Record<string, string>>({});

  onMount(async () => {
    try {
      assets = await invoke("get_zsas");
    } catch (e) {
      console.error("Failed to load ZSAs:", e);
      return;
    }
    // No artwork request on load. Fetching every held asset's artwork from zecboat.com each
    // time the list opened told the site the holder's whole set of items, with their address,
    // on every visit, unsolicited items included (audit 2026-10-08, Zecboat B / ZMAP J). A
    // card shows its artwork once the item has been opened in this session; opening is the
    // user's own, explicit request for that one item.
  });

  // Asked of the backend rather than hardcoded, so ZECBOAT_REGISTRY reaches the UI too.
  // Previously fixed at https://zecboat.com, which answers 301 today — a fresh install
  // showed no artwork and no explanation.
  let registryBase = $state("https://zecboat.com");
  invoke<string>("registry_base").then((b) => { if (b) registryBase = b; }).catch(() => {});

  async function showAssetDetails(assetId: string) {
    selectedAssetId = assetId;
    isLoadingMetadata = true;
    isVerifying = true;
    verification = null;
    verifyError = null;
    badge = null;
    isCheckingIssuance = true;

    // Runs independently of the artwork check. One failing must not hide the other's result,
    // and "could not reach the registry" is not a verdict about the asset.
    invoke<Badge>("verify_issuance", { assetId })
      .then((b) => { badge = b; })
      .catch((e: any) => { badge = { state: 'could_not_check', detail: String(e) }; })
      .finally(() => { isCheckingIssuance = false; });

    // Lineage, independent of both: the issuance badge says who minted the design; this says
    // this unit descends from that minting. One can pass while the other fails.
    wake = null;
    copies = null;
    isCheckingLineage = true;
    invoke<Wake>("verify_lineage", { assetId })
      .then((w) => { wake = w; })
      .catch((e: any) => { wake = { state: 'unverified', detail: String(e), consignment_hash: null }; })
      .finally(() => { isCheckingLineage = false; });
    if ((assets.find((a) => a.asset_id === assetId)?.quantity ?? 1) > 1) {
      invoke<CarrierState[]>("asset_carrier_states", { assetId })
        .then((c) => { copies = c; })
        .catch(() => { copies = null; });
    }

    // Metadata is descriptive and host-trusted. The image check is the part that needs no trust,
    // so it runs independently — one failing must not hide the other's result.
    invoke<Verification>("verify_asset_image", { assetId })
      .then((v) => { verification = v; if (v.verified && v.image) cardImages[assetId] = v.image; })
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
    badge = null;
    wake = null;
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
  <div class="asset-grid">
    {#each assets as asset}
      {@const n = splitName(asset.name)}
      <div class="asset-item" title="ID: {asset.asset_id}" onclick={() => showAssetDetails(asset.asset_id)}>
        <div class="asset-icon">
          {#if cardImages[asset.asset_id]}
            <!-- These bytes hashed to the asset id — check 6 — before they were shown. -->
            <img
              src={cardImages[asset.asset_id]}
              alt={asset.name}
              title="Artwork verified: sha256 matches the asset id in the memo"
              style="width: 100%; height: auto; border-radius: 8px; display: block;"
            />
          {:else}
            <!-- Nothing verified yet: still loading, unreachable, or a hash mismatch. Open the
                 asset for the specific reason; a placeholder must not pretend otherwise. -->
            <span class="preview-chip" title="No verified artwork for this asset yet. Open it to see why.">unchecked</span>
            📦
          {/if}
        </div>
        <div class="asset-info">
          <span class="asset-name">
            {n.range}{#if n.design}<span class="design-no" title="Design number within the range — not an edition size">{n.design}</span>{/if}
          </span>
          <span class="asset-balance">{asset.amount} {asset.amount === 1 ? 'unit' : 'units'}</span>
          {#if asset.wake?.has_lading}
            <span class="wake-chip held" title="A lineage proof is held for this unit. Open it to verify against your node.">lineage {asset.wake.hops ?? ''} {asset.wake.hops === 1 ? 'proof' : 'proofs'}</span>
          {:else if asset.wake?.consignment_hash}
            <span class="wake-chip pending" title="The sender committed to a lineage proof that has not been fetched yet.">lineage pending</span>
          {:else}
            <span class="wake-chip none" title="No lineage proof travels with this unit: nothing shows that it descends from the mint.">no lineage proof</span>
          {/if}
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
          <!-- Issuance, rendered on its own: until 2026-10-09 it sat inside the artwork-verified branch,
               so with the artwork host down the issuer verdict was not shown at all (review, session 4,
               Issue N). The artwork check says only that the bytes match the memo's identifier. A
               forger can copy a memo and point it at the same artwork and pass it too. The
               issuance badge below is the one that says who made this, and it is kept separate
               so the two can never merge into a single tick -- §12.1 forbids exactly that. -->
          {#if isCheckingIssuance}
            <div class="verify-badge checking">Checking issuance against a pinned issuer key…</div>
          {:else if badge?.state === 'verified'}
            <!-- The issuance check relates the memo's text to a manifest and the manifest's
                 genesis output to the chain. Anyone can copy a memo, so on its own it says
                 "this design is registered by…", not "this unit is genuine". The green tick
                 and the word Verified belong to it only when the unit's lineage holds too
                 (ZMAP §9: never "genuine" on checks 1-6 alone; audit 2026-10-08, ZMAP A).
                 Green and the word Verified only when the lineage is Verified against this
                 machine's own node: a provider-checked lineage is the provider's word, and
                 WAKE-v1 §8.1(c) says that state must never look like Verified in wording,
                 colour or mark (review 2026-10-09, Issue A: it did, here). -->
            {@const lineageHolds = wake?.state === 'verified'}
            {@const pinnedIssuer = badge.pinned === true}
            <!-- Green needs a key pinned in this wallet as well: the Registry is open, and a
                 name plus a short key fragment is forgeable (review 2026-10-09, session 4,
                 Issue A). A registry-only collection is "registered", never green. The
                 fingerprint is long for the same reason. -->
            <div class="verify-badge {lineageHolds && pinnedIssuer ? 'ok' : 'neutral'}">
              {lineageHolds && pinnedIssuer ? '✓ Verified — issued by' : (pinnedIssuer ? '▫ Design registered by' : '▫ In the Zecboat Registry as')} {badge.issuer}{#if badge.issuer_key}<code class="ik" title={`issuance key ${badge.issuer_key}`}> · key {badge.issuer_key.slice(0, 12)}…{badge.issuer_key.slice(-12)}</code>{/if}{#if !pinnedIssuer} · not a collection this wallet knows: compare the full key with one the issuer published{/if}{#if badge.found_in_registry_at}<span class="via-registry" title={`Found in the Zecboat Registry and audited to block ${badge.found_in_registry_at}, from the chain. zecboat.com was not needed.`}> · via Zecboat Registry</span>{/if}
              <!-- One line is the verdict. The checks, the anchor and the caveat are one click
                   away, not gone: the caveat still travels with the tick, so the badge states
                   its own limits to anyone who asks what "verified" covered. -->
              <details class="verify-details">
                <summary>what was checked</summary>
                {#each badge.checks as c}<span class="check-line">✓ {c}</span>{/each}
                <span class="check-line mono">issuance {badge.issuance_txid.slice(0, 16)}… · height {badge.issuance_height.toLocaleString()}</span>
                <span class="check-line caveat">{badge.caveat}</span>
              </details>
            </div>
          {:else if badge?.state === 'not_listed'}
            <div class="verify-badge bad">
              ✕ Not issued by {badge.issuer}
              <span class="verify-detail">{badge.detail}</span>
            </div>
          {:else if badge?.state === 'signature_failed'}
            <div class="verify-badge bad">
              ✕ Issuance check failed
              <span class="verify-detail">{badge.detail}</span>
            </div>
          {:else if badge?.state === 'could_not_check'}
            <!-- NOT a verdict about the asset. Rendering this as a failure would defame a
                 holder whose network is simply down. -->
            <div class="verify-badge unknown">
              Issuance could not be checked
              <span class="verify-detail">{badge.detail}</span>
            </div>
          {/if}
          <!-- Lineage (Wake). Rendered on its own, outside the artwork branch: a unit with no
               registry artwork (the throwaway collection) still has a lineage to show. Kept apart
               from the two badges above for the same reason they are kept apart from each other: a merged tick would claim what none of them
               checked. Verified here means: proofs, chain rule, anchors on a full node this
               wallet chose, and a genesis output the issuer's manifest names. -->
          {#if isCheckingLineage}
            <div class="verify-badge checking">Verifying lineage…</div>
          {:else if wake?.state === 'verified'}
            <div class="verify-badge {WAKE_REVIEWED ? 'ok' : 'amber'}">
              {#if WAKE_REVIEWED}
                ✓ Lineage verified — {wake.hops} proof{wake.hops === 1 ? '' : 's'} back to the issuance output
              {:else}
                ✓ Lineage checks out · your own node · awaiting external review
              {/if}
              <details class="verify-details">
                <summary>what was checked</summary>
                <span class="check-line">✓ every proof verifies under the pinned Wake keys</span>
                <span class="check-line">✓ each note's ρ is the previous note's nullifier (consensus-bound)</span>
                <span class="check-line">✓ every anchor is a tree root on your node ({wake.asked}), shallowest {wake.min_anchor_depth.toLocaleString()} blocks deep</span>
                <span class="check-line">✓ the genesis output {wake.genesis_txid.slice(0, 16)}… #{wake.genesis_action_index} is the one the {wake.genesis_source === 'local_manifest' ? 'local test manifest' : wake.genesis_source === 'registry' ? 'Zecboat Registry (audited, from the chain)' : "issuer's pinned manifest"} names</span>
                <span class="check-line mono">lading sha256 {wake.consignment_hash.slice(0, 16)}…</span>
                <span class="check-line caveat">Wake is a draft circuit without external review (WAKE-v1 §11). This badge is exploratory.</span>
              </details>
            </div>
          {:else if wake?.state === 'provider_checked'}
            <!-- 0.7.1: the same proofs, with the chain's answers from the provider. Never the
                 green tick of an own-node verdict, reviewed circuit or not (WAKE-v1 §8.1). -->
            <!-- Its own colour and its own mark, reviewed or not: a buyer must never take a
                 provider's word for an own-node verdict (WAKE-v1 §8.1(c); audit 2026-10-08). -->
            <div class="verify-badge provider">
              ◐ Lineage checks out · {wake.asked}{WAKE_REVIEWED ? '' : ' · awaiting external review'}
              <details class="verify-details">
                <summary>what was checked</summary>
                <span class="check-line">✓ every proof verifies under the pinned Wake keys, on this machine</span>
                <span class="check-line">✓ each note's ρ is the previous note's nullifier (consensus-bound)</span>
                <span class="check-line">✓ every anchor is a tree root according to {wake.asked}, shallowest {wake.min_anchor_depth.toLocaleString()} blocks deep</span>
                <span class="check-line">✓ the genesis output {wake.genesis_txid.slice(0, 16)}… #{wake.genesis_action_index} is the one the {wake.genesis_source === 'local_manifest' ? 'local test manifest' : wake.genesis_source === 'registry' ? 'Zecboat Registry' : "issuer's manifest"} names, and it is on chain according to the same source</span>
                <span class="check-line mono">lading sha256 {wake.consignment_hash.slice(0, 16)}…</span>
                <span class="check-line caveat">The chain's answers here are your provider's word, the same trust your balance rests on. With your own node running on this machine, the wallet checks them itself.</span>
                {#if !WAKE_REVIEWED}<span class="check-line caveat">Wake is a draft circuit without external review (WAKE-v1 §11). This badge is exploratory.</span>{/if}
              </details>
            </div>
          {:else if wake?.state === 'no_wake'}
            <div class="verify-badge unknown">
              No lineage proof for this unit
              <span class="verify-detail">{wake.detail} Without a lineage, nothing shows that this unit descends from the mint; the memo and artwork checks above say only what it claims to be.</span>
              {#if wake.detail.includes("has not been fetched")}
                <span class="verify-detail">The sender can save the lineage record as a file for you: open it under Settings → Lineage records.</span>
              {/if}
            </div>
          {:else if wake?.state === 'unverified'}
            <div class="verify-badge unknown">
              Lineage could not be verified right now
              <span class="verify-detail">{wake.detail}</span>
            </div>
          {:else if wake?.state === 'broken'}
            <div class="verify-badge bad">
              ✕ Lineage proof is broken ({wake.failure})
              <span class="verify-detail">{wake.detail}</span>
            </div>
          {/if}
          {#if copies && copies.length > 1}
            <div class="verify-badge neutral">
              {copies.length} copies of this unit in this wallet:
              {copies.filter((c) => c.state.state === 'verified' || c.state.state === 'provider_checked').length} check out,
              {copies.filter((c) => c.state.state === 'no_wake' || c.state.state === 'unverified').length} unproven,
              {copies.filter((c) => c.state.state === 'broken').length} broken.
              <details class="verify-details">
                <summary>each copy</summary>
                {#each copies as c}
                  <span class="check-line mono">{c.txid.slice(0, 12)}… #{c.output_index}: {c.state.state}{c.state.state === 'broken' ? ` (${c.state.failure})` : ''}</span>
                {/each}
                <span class="check-line caveat">A send spends the copy that checks out best; a broken copy is one someone sent you with a lineage that failed, and it never speaks for the others.</span>
              </details>
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
  .verify-badge.provider { background: rgba(120, 170, 255, 0.12); color: #9ec1ff; border: 1px solid rgba(120, 170, 255, 0.4); }
  .verify-badge.neutral { background: rgba(160, 160, 170, 0.12); color: #c9c9d1; border: 1px solid rgba(160, 160, 170, 0.35); }
  .verify-badge code.ik { font-size: 0.85em; opacity: 0.85; }
  .verify-badge.amber   { background: rgba(255, 179, 0, 0.14); color: #ffb300; border: 1px solid rgba(255, 179, 0, 0.45); }
  .verify-badge.unknown { background: rgba(210, 153, 34, 0.12); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.35); }
  .verify-badge.checking { background: rgba(139, 148, 158, 0.12); color: #8b949e; border: 1px solid rgba(139, 148, 158, 0.3); }
  .wake-chip { display: inline-block; margin-top: 0.25rem; font-size: 0.7em; padding: 0.1rem 0.45rem; border-radius: 999px; border: 1px solid; }
  .wake-chip.held    { color: #3fb950; border-color: rgba(46, 160, 67, 0.4); }
  .wake-chip.pending { color: #d29922; border-color: rgba(210, 153, 34, 0.35); }
  .wake-chip.none    { color: #8b949e; border-color: rgba(139, 148, 158, 0.3); }
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

  .verify-details { margin-top: 0.35rem; font-size: 0.8em; opacity: 0.85; }
  .verify-details summary { cursor: pointer; font-weight: normal; }
  .check-line {
    display: block;
    margin-top: 0.15rem;
  }
  /* Secondary, but present. The limits travel with the badge. */
  .verify-detail.caveat {
    margin-top: 0.5rem;
    padding-top: 0.5rem;
    border-top: 1px solid var(--border-color, #333);
    opacity: 0.8;
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
  .via-registry { opacity: 0.75; font-weight: 500; cursor: help; }
</style>