#!/usr/bin/env bash
#
# uninstall_zecboat_deb.sh — remove Zecboat installed from the .deb package.
#
#   ./uninstall_zecboat_deb.sh                 # show what is there, remove nothing
#   ./uninstall_zecboat_deb.sh --yes           # remove the package only
#   ./uninstall_zecboat_deb.sh --yes --wallet  # also remove THIS user's wallet
#   ./uninstall_zecboat_deb.sh --yes --wallet --all-users
#   ./uninstall_zecboat_deb.sh --yes --wallet --params
#
# This is for the apt/dpkg install. If you built from the source tarball instead,
# use uninstall_zecboat.sh — that one removes ~/zecboat-0.6.3-beta, which this
# script knows nothing about.
#
# WHAT THE PACKAGE OWNS  (removed by apt)
#   /usr/bin/zecboat-ui
#   /usr/share/applications/Zecboat.desktop
#   /usr/share/icons/hicolor/{32x32,128x128,256x256@2}/apps/zecboat-ui.png
#
# WHAT THE PACKAGE DOES NOT OWN  (apt will NEVER remove these)
#   ~/.AppVault/        THE WALLET — created at runtime, one per user account
#   ~/.zcash-params/    Sapling proving parameters, shared by any Zcash wallet
#
# That distinction is the whole reason this script exists. `apt remove zecboat`
# looks like a complete uninstall and silently leaves every wallet on the machine
# in place. Conversely, someone expecting apt to have cleaned up may delete the
# home directory later without realising the keys were still in it.
#
# ---------------------------------------------------------------------------
# ~/.AppVault/data/wallet.db and encryption-identity.txt ARE the wallet. Deleting
# them destroys the only copy of the spending keys on this machine. If the seed
# phrase was written down, funds are recoverable from that phrase on any wallet.
# If it was not, deletion is permanent.
#
# So --wallet:
#   * refuses if the wallet holds a balance, unless --wallet-is-empty
#   * archives to ~/zecboat-uninstalled-<date>.tar.gz first, unless --no-archive
# ---------------------------------------------------------------------------

set -uo pipefail

PKG="zecboat"
DO_IT=0; WALLET=0; PARAMS=0; ALL_USERS=0; ARCHIVE=1; EMPTY_ASSERTED=0; PURGE=0

for a in "$@"; do
  case "$a" in
    --yes|-y)          DO_IT=1 ;;
    --wallet)          WALLET=1 ;;
    --params)          PARAMS=1 ;;
    --all-users)       ALL_USERS=1 ;;
    --purge)           PURGE=1 ;;
    --no-archive)      ARCHIVE=0 ;;
    --wallet-is-empty) EMPTY_ASSERTED=1 ;;
    -h|--help)         sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $a (try --help)" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    \033[33m%s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

say "Zecboat uninstall (apt/deb) — $(hostname)"
[[ "$DO_IT" -eq 1 ]] || warn "DRY RUN. Nothing will be removed. Add --yes to act."

# --- is the package installed? ---------------------------------------------
say "Package"
INSTALLED=0
if dpkg-query -W -f='${Status}' "$PKG" 2>/dev/null | grep -q "install ok installed"; then
  INSTALLED=1
  info "$PKG $(dpkg-query -W -f='${Version}' "$PKG" 2>/dev/null) is installed"
  dpkg-query -L "$PKG" 2>/dev/null | grep -E '^/usr/(bin|share/applications)' | sed 's/^/      /'
else
  info "$PKG is not installed via dpkg"
  # A stray binary here means someone copied it in by hand; apt cannot remove it.
  [[ -e /usr/bin/zecboat-ui ]] && \
    warn "but /usr/bin/zecboat-ui exists and is not owned by any package — remove it by hand"
fi

# --- wallets on this machine ------------------------------------------------
# Balance is an UPPER BOUND: a note counts unless a spend row exists, and anything
# unreadable is UNKNOWN. Both lean the same way — over-reporting costs an argument,
# under-reporting deletes somebody's money.
read_balance() {
  python3 - "$1" <<'PY' 2>/dev/null
import sqlite3, sys
POOLS = ("orchard", "sapling", "ironwood")
try:
    c = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
    have = {r[0] for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    total, seen = 0, False
    for pool in POOLS:
        notes, spends = f"{pool}_received_notes", f"{pool}_received_note_spends"
        if notes not in have:
            continue
        seen = True
        if spends in have:
            q = (f"SELECT COALESCE(SUM(value),0) FROM {notes} "
                 f"WHERE id NOT IN (SELECT {pool}_received_note_id FROM {spends})")
        else:
            q = f"SELECT COALESCE(SUM(value),0) FROM {notes}"
        total += c.execute(q).fetchone()[0] or 0
    for t in ("transparent_received_outputs", "utxos"):
        if t in have:
            cols = {r[1] for r in c.execute(f"PRAGMA table_info({t})").fetchall()}
            vc = "value_zat" if "value_zat" in cols else ("value" if "value" in cols else None)
            if vc:
                total += c.execute(f"SELECT COALESCE(SUM({vc}),0) FROM {t}").fetchone()[0] or 0
    print(total if seen else "UNKNOWN")
except Exception:
    print("UNKNOWN")
PY
}

say "Wallets"
declare -a VAULTS
if [[ "$ALL_USERS" -eq 1 ]]; then
  # The package is system-wide, so every account that ran it has its own wallet.
  for h in /home/* /root; do
    [[ -d "$h/.AppVault" ]] && VAULTS+=("$h/.AppVault")
  done
else
  [[ -d "$HOME/.AppVault" ]] && VAULTS+=("$HOME/.AppVault")
fi

if [[ "${#VAULTS[@]}" -eq 0 ]]; then
  info "no ~/.AppVault found$([[ "$ALL_USERS" -eq 0 ]] && echo " for $USER (try --all-users)")"
else
  for v in "${VAULTS[@]}"; do
    db="$v/data/wallet.db"
    if [[ -r "$db" ]]; then
      BAL="$(read_balance "$db")"
      case "$BAL" in
        0)       info "$(printf '%-10s %s  — appears empty' "$(du -sh "$v" 2>/dev/null | cut -f1)" "$v")" ;;
        UNKNOWN) warn "$(printf '%-10s %s  — BALANCE UNREADABLE' "$(du -sh "$v" 2>/dev/null | cut -f1)" "$v")" ;;
        *)       warn "$(printf '%-10s %s  — HOLDS %s zat (%.8f ZEC)' "$(du -sh "$v" 2>/dev/null | cut -f1)" "$v" "$BAL" "$(awk "BEGIN{print $BAL/100000000}")")" ;;
      esac
    else
      warn "$(printf '%-10s %s  — wallet.db not readable by %s' "-" "$v" "$USER")"
    fi
  done
fi

[[ "$PARAMS" -eq 1 && -d "$HOME/.zcash-params" ]] && \
  info "$(printf '%-10s %s' "$(du -sh "$HOME/.zcash-params" | cut -f1)" "$HOME/.zcash-params")"

# --- dry run stops here -----------------------------------------------------
if [[ "$DO_IT" -eq 0 ]]; then
  say "Dry run complete"
  info "Remove the package only:        $0 --yes"
  info "Package and this user's wallet: $0 --yes --wallet"
  info "Every user's wallet too:        $0 --yes --wallet --all-users"
  exit 0
fi

# --- stop it if running -----------------------------------------------------
if pgrep -x zecboat-ui >/dev/null 2>&1; then
  # Match by exact name. Never pkill -f on a pattern that appears in this
  # script's own command line — that matches the shell running it.
  info "stopping zecboat-ui (pid $(pgrep -x zecboat-ui | tr '\n' ' '))"
  pkill -x zecboat-ui; sleep 2
  pgrep -x zecboat-ui >/dev/null && die "could not stop Zecboat — close it and rerun"
fi

# --- remove the package -----------------------------------------------------
if [[ "$INSTALLED" -eq 1 ]]; then
  say "Removing the package"
  if [[ "$PURGE" -eq 1 ]]; then
    sudo apt-get purge -y "$PKG" || die "apt purge failed"
  else
    sudo apt-get remove -y "$PKG" || die "apt remove failed"
  fi
  info "removed"
  # Desktop menus cache .desktop files; without this the icon lingers.
  command -v update-desktop-database >/dev/null && sudo update-desktop-database -q 2>/dev/null
  command -v gtk-update-icon-cache  >/dev/null && sudo gtk-update-icon-cache -q -f /usr/share/icons/hicolor 2>/dev/null
  info "desktop and icon caches refreshed"
fi

# --- wallets ----------------------------------------------------------------
if [[ "$WALLET" -eq 1 && "${#VAULTS[@]}" -gt 0 ]]; then
  say "Wallets — this is the irreversible part"
  warn "After this, recovery is possible ONLY from the seed phrase."
  read -r -p "    Type the word 'remove' to continue: " ans
  [[ "$ans" == "remove" ]] || { info "Aborted. No wallet was touched."; exit 0; }

  for v in "${VAULTS[@]}"; do
    db="$v/data/wallet.db"
    BAL="UNKNOWN"; [[ -r "$db" ]] && BAL="$(read_balance "$db")"
    if [[ "$BAL" != "0" && "$EMPTY_ASSERTED" -ne 1 ]]; then
      warn "SKIPPING $v — balance is $BAL"
      warn "  Move the funds out, or rerun with --wallet-is-empty if the seed"
      warn "  phrase is written down and you intend to destroy this copy."
      continue
    fi

    if [[ "$ARCHIVE" -eq 1 ]]; then
      ARC="$HOME/zecboat-uninstalled-$(basename "$(dirname "$v")")-$(date +%Y%m%d-%H%M).tar.gz"
      if tar -czf "$ARC" -C "$(dirname "$v")" .AppVault 2>/dev/null; then
        chmod 600 "$ARC"
        info "archived $v -> $ARC ($(du -h "$ARC" | cut -f1), mode 600)"
        warn "  that archive holds KEY MATERIAL. Delete it deliberately: rm -f $ARC"
      else
        warn "SKIPPING $v — could not archive it, and refusing to delete without a copy."
        warn "  Rerun with --no-archive if you genuinely do not want one."
        continue
      fi
    fi

    if rm -rf -- "$v" 2>/dev/null; then
      info "removed $v"
    else
      warn "could not remove $v — try again with sudo (it belongs to another user)"
    fi
  done
fi

if [[ "$PARAMS" -eq 1 && -d "$HOME/.zcash-params" ]]; then
  rm -rf -- "$HOME/.zcash-params" && info "removed $HOME/.zcash-params"
fi

# 0.7.2 (stranger test 2026-10-12, item 8): the app's WebKit data and the saved node choice
# live in ~/.local/share/com.zcash.zecboat and were left behind by every uninstall. No key
# material is in there (the wallet is ~/.AppVault, handled above), so it goes with the package.
WEBDATA="$HOME/.local/share/com.zcash.zecboat"
if [[ -d "$WEBDATA" ]]; then
  rm -rf -- "$WEBDATA" && info "removed $WEBDATA (window data, saved node choice)"
fi

# --- what is left -----------------------------------------------------------
say "Left in place"
[[ "$WALLET" -eq 0 ]] && warn "wallets — apt does NOT remove them. Rerun with --wallet to delete."
[[ "$PARAMS" -eq 0 ]] && info "~/.zcash-params — shared by any Zcash wallet; --params removes it"
info "the runtime libraries apt installed as dependencies:  sudo apt autoremove"

say "Done"
