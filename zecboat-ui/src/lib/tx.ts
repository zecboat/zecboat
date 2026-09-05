// Shared transaction shape and formatting.
//
// Three components render transactions — the dashboard list, the receive page and
// the transactions page. They each had their own inline type, and when the backend
// changed (C1) they all silently broke: `date` became `block_time`, so every row
// rendered an undefined date with no error anywhere. One definition here means the
// next backend change is a compile error rather than a blank column.

export type ZmapAsset = { asset_id: string; name: string | null };

export type Tx = {
  /** Full txid in DISPLAY order — the one block explorers show. */
  id: string;
  type: "send" | "receive";
  amount: number;
  fee: number | null;
  /** Raw epoch seconds, or null when unmined. Formatted locally, never by SQL. */
  block_time: number | null;
  height: number | null;
  expiry_height: number | null;
  /** null when no node was reachable to age it — not zero. */
  confirmations: number | null;
  /** "Ironwood", "Transparent", … Sends only; receives have no sent_notes rows. */
  pool: string | null;
  /** Sends only. A shielded sender is not recoverable by anyone. */
  to_address: string | null;
  memo: string | null;
  assets: ZmapAsset[];
  asset: string;
};

export function shortId(id: string, n = 8): string {
  return id.length > n * 2 ? `${id.slice(0, n)}…${id.slice(-n)}` : id;
}

/** Local time. The backend deliberately returns epoch seconds so this can happen. */
export function formatDate(t: number | null): string {
  if (!t) return "Pending";
  return new Date(t * 1000).toLocaleString();
}

export function formatDateShort(t: number | null): string {
  if (!t) return "Pending";
  return new Date(t * 1000).toLocaleDateString();
}

/** Distinguishes "not yet mined" from "mined but we could not reach a node". */
export function confirmationsLabel(tx: Tx): string {
  if (tx.height === null) return "Unconfirmed";
  if (tx.confirmations === null) return `Block ${tx.height.toLocaleString()}`;
  if (tx.confirmations >= 100) return `${tx.confirmations.toLocaleString()} confirmations`;
  return `${tx.confirmations} confirmation${tx.confirmations === 1 ? "" : "s"}`;
}

/**
 * What is public about this transaction.
 *
 * A transparent leg is visible on chain — amount and counterparty both. Mixing one
 * with a shielded leg links the two, which is the case worth naming rather than
 * leaving a user to infer.
 */
export function privacyLabel(tx: Tx): { text: string; level: "shielded" | "mixed" | "public" | "unknown" } {
  if (!tx.pool) return { text: "Shielded — details are private", level: "unknown" };
  const hasTransparent = tx.pool.includes("Transparent");
  const hasShielded = /Ironwood|Orchard|Sapling/.test(tx.pool);
  if (hasTransparent && hasShielded)
    return { text: "Mixed — the transparent side is public and links to the shielded side", level: "mixed" };
  if (hasTransparent) return { text: "Transparent — amount and addresses are public on chain", level: "public" };
  return { text: `Shielded (${tx.pool}) — amount, address and memo are private`, level: "shielded" };
}

/** Free-text match across everything a person might paste or half-remember. */
export function matchesQuery(tx: Tx, q: string): boolean {
  const s = q.trim().toLowerCase();
  if (!s) return true;
  return (
    tx.id.toLowerCase().includes(s) ||
    (tx.to_address ?? "").toLowerCase().includes(s) ||
    (tx.memo ?? "").toLowerCase().includes(s) ||
    (tx.pool ?? "").toLowerCase().includes(s) ||
    tx.type.includes(s) ||
    tx.amount.toString().includes(s) ||
    (tx.height?.toString() ?? "").includes(s) ||
    formatDate(tx.block_time).toLowerCase().includes(s) ||
    tx.assets.some(a => (a.name ?? "").toLowerCase().includes(s) || a.asset_id.toLowerCase().includes(s))
  );
}
