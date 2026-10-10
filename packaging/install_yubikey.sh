#!/usr/bin/env bash
#
# install_yubikey.sh — install the YubiKey plugin Zecboat needs for a YubiKey-protected wallet.
#
#   bash install_yubikey.sh          # check, install what is missing, verify
#   bash install_yubikey.sh --check  # report only, change nothing
#
# WHAT THIS IS FOR
#
# Zecboat can seal the wallet's identity file to a YubiKey (PIV applet, YubiKey 4 and 5).
# It does that through `age-plugin-yubikey`, a separate program by the author of `age`,
# which Zecboat looks for on the PATH. Without it the YubiKey option does not appear in the
# setup wizard; nothing breaks, nothing advertises itself. This script puts it there.
#
# WHY IT IS BUILT HERE AND NOT SHIPPED
#
# The plugin has no Linux binary release (its releases are macOS and Windows) and Debian
# does not package it. Shipping a binary we built would make us the ones vouching for a
# third party's build, for every user including those who will never own a YubiKey. So it is
# built on your machine from the published source, at a pinned version, with Cargo's lock
# file honoured, and installed where the desktop launcher can see it.
#
# WHAT IT CHANGES
#   apt:   pcscd, libpcsclite-dev, pkg-config, build-essential (the smart-card daemon the
#          plugin talks to, and what compiling it needs)
#   rust:  if `cargo` is not installed, rustup (the official installer, downloaded from
#          static.rust-lang.org and checked against the SHA-256 published beside it). It
#          installs into your home directory only. You are asked first.
#   plugin: `cargo install age-plugin-yubikey --version 0.5.1 --locked`, then a copy in
#          /usr/local/bin so a wallet started from the desktop menu finds it (the menu's PATH
#          does not include ~/.cargo/bin)
#   pcscd: enabled and started
#
# It does not touch any wallet. It does not read your YubiKey. Turning YubiKey protection on
# is done in the wallet's setup wizard, afterwards, on a NEW wallet.

set -uo pipefail

PLUGIN_VERSION="0.5.1"
RUSTUP_URL="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"

CHECK_ONLY=0
for a in "$@"; do
  case "$a" in
    --check)   CHECK_ONLY=1 ;;
    -h|--help) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $a" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    \033[33m%s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(uname -m)" = "x86_64" ] || die "this script is for x86_64 Linux; on $(uname -m) build the plugin by hand: cargo install age-plugin-yubikey --version $PLUGIN_VERSION --locked"
command -v apt-get >/dev/null || die "this script is for Debian and Ubuntu (apt)"

# --- 0. already there? ------------------------------------------------------
say "YubiKey plugin"
have=""
if command -v age-plugin-yubikey >/dev/null 2>&1; then
  have="$(age-plugin-yubikey --version 2>/dev/null | awk '{print $2}')"
  info "age-plugin-yubikey $have is on the PATH ($(command -v age-plugin-yubikey))"
  if [ -x /usr/local/bin/age-plugin-yubikey ]; then
    info "and in /usr/local/bin, where the desktop launcher finds it"
  else
    warn "but not in /usr/local/bin: a wallet started from the desktop menu will not find it"
  fi
else
  info "not installed"
fi
if [ "$CHECK_ONLY" -eq 1 ]; then
  [ -n "$have" ] && [ -x /usr/local/bin/age-plugin-yubikey ] && { info "nothing to do"; exit 0; }
  info "run without --check to install"; exit 1
fi
if [ "$have" = "$PLUGIN_VERSION" ] && [ -x /usr/local/bin/age-plugin-yubikey ]; then
  info "nothing to do"; exit 0
fi

# --- 1. system packages ------------------------------------------------------
say "System packages (this needs sudo)"
info "pcscd (smart-card daemon), libpcsclite-dev, pkg-config, build-essential"
sudo apt-get install -y pcscd libpcsclite-dev pkg-config build-essential || die "apt-get install failed; read the message above"

# --- 2. a Rust toolchain -----------------------------------------------------
if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi
if ! command -v cargo >/dev/null 2>&1; then
  say "Rust toolchain"
  info "cargo is not installed. The plugin is compiled from source, which needs it."
  info "rustup installs Rust into $HOME/.cargo and $HOME/.rustup, nothing system-wide."
  info "Installer: $RUSTUP_URL"
  info "It is checked against the SHA-256 published beside it on the same host; compare that"
  info "line with https://rust-lang.org if you want a second source."
  printf '    Install rustup now? [y/N] '
  read -r yn
  [ "$yn" = "y" ] || [ "$yn" = "Y" ] || die "stopped: install Rust yourself (https://rustup.rs), then run this script again"
  tmp="$(mktemp -d)"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/rustup-init" "$RUSTUP_URL" || die "download failed"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/rustup-init.sha256" "$RUSTUP_URL.sha256" || die "download of the checksum failed"
  expected="$(awk '{print $1}' "$tmp/rustup-init.sha256")"
  actual="$(sha256sum "$tmp/rustup-init" | awk '{print $1}')"
  info "published sha256: $expected"
  [ "$expected" = "$actual" ] || die "rustup-init does not match its published checksum ($actual); not run"
  chmod +x "$tmp/rustup-init"
  "$tmp/rustup-init" -y --profile minimal --no-modify-path || die "rustup failed"
  rm -rf "$tmp"
  export PATH="$HOME/.cargo/bin:$PATH"
  command -v cargo >/dev/null || die "cargo is still not on the PATH; open a new terminal and run this script again"
fi
info "cargo: $(cargo --version)"

# --- 3. the plugin, pinned ---------------------------------------------------
say "Building age-plugin-yubikey $PLUGIN_VERSION (a few minutes)"
cargo install age-plugin-yubikey --version "$PLUGIN_VERSION" --locked || die "cargo install failed; read the message above"
built="$HOME/.cargo/bin/age-plugin-yubikey"
[ -x "$built" ] || die "cargo reported success but $built is missing"
info "built: $built ($("$built" --version))"

# --- 4. where the desktop launcher looks -----------------------------------
say "Installing to /usr/local/bin (this needs sudo)"
sudo install -m 0755 "$built" /usr/local/bin/age-plugin-yubikey || die "could not copy to /usr/local/bin"
info "sha256 $(sha256sum /usr/local/bin/age-plugin-yubikey | cut -c1-16)…"

# --- 5. the smart-card daemon ---------------------------------------------
say "Smart-card daemon"
sudo systemctl enable --now pcscd >/dev/null 2>&1 && info "pcscd enabled and running" || warn "could not enable pcscd with systemctl; start it yourself before using the key"

# --- 6. verify ---------------------------------------------------------------
say "Done"
v="$(/usr/local/bin/age-plugin-yubikey --version 2>/dev/null | awk '{print $2}')"
[ "$v" = "$PLUGIN_VERSION" ] || die "the installed plugin reports version '$v', not $PLUGIN_VERSION"
info "age-plugin-yubikey $v is installed."
info ""
info "Next, with the YubiKey plugged in, create an identity on it once:"
info "  age-plugin-yubikey --generate"
info "Then start Zecboat and create a NEW wallet: the wizard now offers YubiKey protection."
info "It seals the wallet's identity file to the key; spending is still signed in software."
exit 0
