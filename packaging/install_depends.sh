#!/usr/bin/env bash
#
# install_depends.sh — everything Zecboat needs that the package cannot provide.
#
#   bash install_depends.sh          # check what is missing, install it
#   bash install_depends.sh --check  # report only, change nothing
#
# WHY THIS IS SEPARATE FROM install.sh
#
# The .deb declares its runtime libraries, so `apt install` pulls those in on its
# own. Two things it cannot do:
#
#   1. THE SAPLING PROVING PARAMETERS. ~50 MB, downloaded from z.cash, and they
#      live in your home directory rather than in any package. Without them the
#      wallet installs, syncs, and shows balances perfectly — then fails the
#      moment you try to send. That failure looks like a broken wallet, not a
#      missing file, which is why this script exists.
#
#   2. AppImage users get no dependency resolution at all. An AppImage bundles
#      most of its libraries but still needs the system's GTK/WebKit stack.
#
# Run this BEFORE install.sh, or run install.sh which calls it for you.

set -uo pipefail

CHECK_ONLY=0
for a in "$@"; do
  case "$a" in
    --check)   CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $a" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    \033[33m%s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

MISSING=0

# --- 1. runtime libraries ---------------------------------------------------
#
# These are what the .deb's Depends line names. Listed here too because the
# AppImage has no package manager behind it, and because a missing one produces a
# linker error that names a .so rather than a package.
LIBS=(
  libwebkit2gtk-4.1-0
  libjavascriptcoregtk-4.1-0
  libgtk-3-0
  libayatana-appindicator3-1
  librsvg2-2
)

# A package may be satisfied by a DIFFERENT package that Provides its name.
# Debian 13 renamed several libraries for the 64-bit time_t transition:
# libgtk-3-0 no longer exists as a real package — libgtk-3-0t64 provides it.
# apt resolves that fine, but `dpkg-query -W libgtk-3-0` does not, so a naive
# check reports a missing dependency on a working machine and sends the user
# after a package that cannot be installed.
have_pkg() {
  local want="$1"
  dpkg-query -W -f='${Status}' "$want" 2>/dev/null | grep -q "install ok installed" && return 0
  # Anything installed that Provides it?
  local provider
  for provider in $(apt-cache showpkg "$want" 2>/dev/null \
                    | sed -n '/Reverse Provides:/,$p' | awk 'NR>1{print $1}' | sort -u); do
    dpkg-query -W -f='${Status}' "$provider" 2>/dev/null \
      | grep -q "install ok installed" && { echo "$provider"; return 0; }
  done
  return 1
}

say "Runtime libraries"
NEED=()
for p in "${LIBS[@]}"; do
  if via="$(have_pkg "$p")"; then
    if [[ -n "$via" && "$via" != "$p" ]]; then
      info "$p (provided by $via)"
    else
      info "$p"
    fi
  else
    warn "$p — MISSING"
    NEED+=("$p")
  fi
done

if [[ "${#NEED[@]}" -gt 0 ]]; then
  MISSING=1
  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    info ""
    info "install with: sudo apt install ${NEED[*]}"
  else
    info ""
    info "installing ${#NEED[@]} package(s); this needs sudo"
    sudo apt update
    sudo apt install -y "${NEED[@]}" || die "apt install failed.
    If a package name was not found, this Debian version calls it something else —
    that is a real finding, please report which one."
  fi
fi

# --- 2. Sapling proving parameters ------------------------------------------
say "Sapling proving parameters"
PARAMS="$HOME/.zcash-params"
FILES=(sapling-spend.params sapling-output.params)

NEED_P=()
for f in "${FILES[@]}"; do
  if [[ -s "$PARAMS/$f" ]]; then
    info "$f ($(du -h "$PARAMS/$f" | cut -f1))"
  else
    warn "$f — MISSING"
    NEED_P+=("$f")
  fi
done

if [[ "${#NEED_P[@]}" -gt 0 ]]; then
  MISSING=1
  warn ""
  warn "Without these the wallet syncs and displays balances correctly, then fails"
  warn "on the first send. It looks like a wallet bug and is not one."
  if [[ "$CHECK_ONLY" -eq 1 ]]; then
    info "fetch them by running this script without --check"
  else
    mkdir -p "$PARAMS"
    for f in "${NEED_P[@]}"; do
      info "downloading $f (this is large; it is fetched once)"
      curl -# -fL -o "$PARAMS/$f.part" "https://download.z.cash/downloads/$f" \
        || die "could not download $f — check the network and rerun"
      # Only move into place once complete. A truncated params file fails at
      # proving time with an error that says nothing about downloads.
      mv "$PARAMS/$f.part" "$PARAMS/$f"
      info "  done ($(du -h "$PARAMS/$f" | cut -f1))"
    done
  fi
fi

# --- 3. a graphical session -------------------------------------------------
say "Display"
if [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
  info "DISPLAY=${DISPLAY:-unset}  WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-unset}"
else
  MISSING=1
  warn "No display detected. Zecboat is a desktop application and needs a"
  warn "graphical session — it will not run over a plain SSH connection."
fi

say "Done"
if [[ "$MISSING" -eq 0 ]]; then
  info "Everything Zecboat needs is present."
elif [[ "$CHECK_ONLY" -eq 1 ]]; then
  info "Items above are missing. Rerun without --check to install them."
else
  info "Dependencies handled. Next:  bash install.sh"
fi
