#!/usr/bin/env bash
#
# launch.sh — start the Zecboat desktop app.
#
# Usage:
#   ./launch.sh                  # preflight, then run the BUILT app if present
#   ./launch.sh dev              # force dev mode (rebuilds; needs the toolchain)
#   ./launch.sh build            # build a release binary (Tauri CLI, no bundle)
#   ./launch.sh --no-preflight   # skip the node-stack check
#
# This does NOT start zebrad or zainod. If you are running your own node, bring
# those up first. Using a public lightwalletd instead? Nothing to start.
#
# WHAT CHANGED (2026-08-10) AND WHY
# ---------------------------------
# * The Tauri CLI is invoked as `npx tauri` by default. Set RUN_TAURI to a wrapper
#   script if your `node` is a rebranded build — the CLI matches argv[0] against
#   node|nodejs|bun|electron, and anything else is parsed as the subcommand instead.
#
# * `pkill -9 -f vite` and friends are gone. A loose -f pattern also matches the
#   shell running this script, which is a good way to kill your own session, and
#   -9 denies the app a clean shutdown.

set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# On most machines the Tauri CLI is simply `npx tauri`. It fails only where `node`
# is a rebranded build (N|Solid, for instance): the CLI matches argv[0] against
# node|nodejs|bun|electron and anything else falls through, so the interpreter path
# gets parsed as the subcommand. Set RUN_TAURI to a wrapper if you hit that.
RUN_TAURI="${RUN_TAURI:-}"

PREFLIGHT=1
# Empty means "decide later": run the built binary if one exists, else fall back to
# dev. Defaulting to dev made `./launch.sh` recompile for ~50 minutes on a fresh
# checkout even when a finished binary was sitting right there.
TAURI_CMD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-preflight)  PREFLIGHT=0; shift ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    build|dev) TAURI_CMD="$1"; shift ;;
    *) echo "Unknown argument: $1 (try --help)" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m[launch]\033[0m %s\n' "$*"; }
info() { printf '         %s\n' "$*"; }
warn() { printf '         \033[33m%s\033[0m\n' "$*"; }
die()  { printf '\n\033[31m[launch] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

say "Zecboat"

# --- preflight: is there anything to connect to? ---------------------------
#
# The app is useless without a node behind it, and a wallet that cannot reach
# its indexer looks broken in ways that waste time to diagnose. Warn early.

if [[ "$PREFLIGHT" -eq 1 ]]; then
  pgrep -x zebrad >/dev/null 2>&1 \
    && info "zebrad:  running" \
    || warn "zebrad:  NOT running (fine if you use a public lightwalletd)"

  if pgrep -x zainod >/dev/null 2>&1; then
    # Report the port zainod is actually bound to, rather than assuming: the two
    # configs differ (zaino.conf :8137 LAN, zaino-local.conf :9067 loopback).
    ZCONF="$(pgrep -a -x zainod | grep -oE '\-c [^ ]+' | awk '{print $2}' | head -1)"
    ZADDR="$(sed -e 's/#.*//' "${ZCONF:-/dev/null}" 2>/dev/null \
             | grep -E '^[[:space:]]*listen_address[[:space:]]*=' \
             | tail -1 | sed -E 's/.*=[[:space:]]*"?([^"]*)"?[[:space:]]*$/\1/')"
    info "zainod:  running on ${ZADDR:-unknown}"
    [[ -n "$ZADDR" ]] && info "         → select this address in Settings, or the app cannot sync"
  else
    warn "zainod:  NOT running — the app will show 'Disconnected'"
  fi

  [[ -f "$HOME/.AppVault/data/wallet.db" ]] \
    && info "wallet:  present" \
    || warn "wallet:  ~/.AppVault/data/wallet.db missing — you will get the setup wizard"
fi

# --- stop any previous instance --------------------------------------------
#
# Match the built binary by path, never a loose -f pattern.

for PAT in "$DIR/zecboat-ui/src-tauri/target/debug/zecboat-ui" \
           "$DIR/zecboat-ui/src-tauri/target/release/zecboat-ui"; do
  PIDS="$(pgrep -f "^$PAT" 2>/dev/null || true)"
  [[ -n "$PIDS" ]] && { say "Stopping previous app instance ($PIDS)"; kill $PIDS 2>/dev/null; }
done

# Vite holds :1420. Free it by port rather than by process name.
if fuser -s 1420/tcp 2>/dev/null; then
  info "freeing port 1420 (vite)"
  fuser -k 1420/tcp 2>/dev/null
fi

# --- node and registry ------------------------------------------------------
#
# Both have compiled-in defaults that are wrong today, and both fail in ways that
# look like the wallet is broken rather than misconfigured. Set here so launching
# the app does not depend on remembering to export them (2026-08-31).
#
#   ZECBOAT_PROVIDER  the lightwalletd to sync from. It MUST serve Ironwood
#                     (NU6.3) — an endpoint without it reports a ZERO BALANCE for
#                     funds that are really there, which reads as data loss.
#                     zec.rocks verified 2026-08-26.
#
#   ZECBOAT_REGISTRY  where asset artwork is fetched from, as
#                     <registry>/collection/<asset_id>.png. The compiled default
#                     is https://zecboat.com, whose /collection/* answers 301, so
#                     every thumbnail fails and falls back to the placeholder
#                     logo. That is exactly what happened on 2026-08-31.
#
# Both are overridable: export either before running this script and the value
# you set is kept. Remove the ZECBOAT_REGISTRY default once zecboat.com/collection
# resolves — at that point the compiled-in default is correct again.

export ZECBOAT_PROVIDER="${ZECBOAT_PROVIDER:-https://zec.rocks:443}"
# ZECBOAT_REGISTRY is deliberately NOT set here.
#
# It used to default to https://ocean.zecboat.com, which does not respond — so the
# launcher printed a registry line that looked configured while every artwork
# thumbnail silently failed. Announcing a dead host is worse than announcing
# nothing: it sends you looking for the fault in the wallet.
#
# Set it yourself if you have a registry:  export ZECBOAT_REGISTRY=https://your.host

# Transparent-address scanning is OFF unless asked for. See transparent_scan_enabled()
# in zecboat-core/src/rpc.rs — GetTaddressTxids names the address to the server, which
# is the one query that undoes what shielded scanning protects.
info "provider: $ZECBOAT_PROVIDER"
info "transparent scan: ${ZECBOAT_TRANSPARENT_SCAN:+ON (addresses are sent to the node by name)}${ZECBOAT_TRANSPARENT_SCAN:-off}"
info "registry: ${ZECBOAT_REGISTRY:-not set — asset artwork will not load}"

# --- run the app ------------------------------------------------------------

if [[ -n "$RUN_TAURI" && ! -x "$RUN_TAURI" ]]; then
  die "RUN_TAURI is set to '$RUN_TAURI' but that is not executable."
fi

[[ -d "$DIR/zecboat-ui/node_modules" ]] \
  || die "frontend dependencies missing. Run: cd $DIR/zecboat-ui && npm install"

export DISPLAY="${DISPLAY:-:0}"
export PATH="$HOME/bin:$PATH"

BUILT="$DIR/zecboat-ui/src-tauri/target/release/zecboat-ui"

# No explicit subcommand: run what has already been built. This script previously
# knew this path only well enough to KILL it (see the stop loop above) and had no
# way to start it, so `./launch.sh` after a successful build still went to dev mode.
if [[ -z "$TAURI_CMD" ]]; then
  if [[ -x "$BUILT" ]]; then
    # A binary built with plain `cargo build` compiles fine but embeds no frontend,
    # so it falls back to the dev server at :1420 and shows a blank white window.
    # Cheap to detect, miserable to diagnose — so check before launching.
    if command -v strings >/dev/null 2>&1 \
       && [[ "$(strings -a "$BUILT" | grep -c _app/immutable)" -eq 0 ]]; then
      warn "the built binary contains no frontend — it would open a blank white window."
      warn "it was probably built with 'cargo build' instead of the Tauri CLI."
      warn "rebuild with:  ./launch.sh build"
      die  "refusing to launch a binary that cannot render."
    fi
    say "Starting built app — DISPLAY=$DISPLAY"
    info "(use './launch.sh dev' for the dev server, './launch.sh build' to rebuild)"
    exec "$BUILT"
  fi
  info "no built binary found — falling back to dev mode"
  info "build one with:  ./launch.sh build"
  TAURI_CMD="dev"
fi

say "Starting UI (tauri $TAURI_CMD) — DISPLAY=$DISPLAY"
[[ "$TAURI_CMD" == "build" ]] && info "first build after a clean checkout takes ~50 minutes"

# `--no-bundle` for build: the binary is what this script runs, and skipping the
# .deb/AppImage packaging saves several minutes. Drop it if you want installers.
if [[ -n "$RUN_TAURI" ]]; then
  if [[ "$TAURI_CMD" == "build" ]]; then "$RUN_TAURI" build --no-bundle; else "$RUN_TAURI" "$TAURI_CMD"; fi
else
  ( cd "$DIR/zecboat-ui" \
    && if [[ "$TAURI_CMD" == "build" ]]; then npx tauri build --no-bundle; else npx tauri "$TAURI_CMD"; fi )
fi

if [[ "$TAURI_CMD" == "build" && -x "$BUILT" ]]; then
  say "Built. Run it with:  ./launch.sh"
fi
