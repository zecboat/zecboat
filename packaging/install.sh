#!/usr/bin/env bash
#
# install.sh — install Zecboat from the .deb sitting beside this script.
#
#   bash install.sh              # deps, verify, install, then how to run it
#   bash install.sh --run        # …and launch it
#   bash install.sh --appimage   # no system install; just make the AppImage runnable
#   bash install.sh --no-deps    # skip install_depends.sh
#
# THE PACKAGE IS 'zecboat'. THE BINARY IS 'zecboat-ui'.
# To remove it:  sudo apt remove zecboat        (NOT zecboat-ui — no such package)
# Full uninstall, including the wallet:  bash uninstall_zecboat_deb.sh

set -uo pipefail

# DEB and APPIMAGE are NOT set here. They are discovered from the directory this script
# is in, after the cd below — see "finding the artifact".
PKG="zecboat"
BIN="zecboat-ui"

DO_RUN=0; DO_DEPS=1; APPIMAGE_ONLY=0
for a in "$@"; do
  case "$a" in
    --run)      DO_RUN=1 ;;
    --no-deps)  DO_DEPS=0 ;;
    --appimage) APPIMAGE_ONLY=1 ;;
    -h|--help)  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown argument: $a" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '    \033[33m%s\033[0m\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

cd "$(dirname "${BASH_SOURCE[0]}")" || die "cannot enter the script's directory"

# --- finding the artifact ---------------------------------------------------
# Discovered by glob, never hard-coded. 0.6.5-beta shipped with the previous release's
# DEB="Zecboat_0.6.3_amd64.deb" still in place: the installer looked for a file the zip
# did not contain and died at "is not in", so every download that followed the documented
# path failed. The version lives in exactly one place — the filename tauri produces — and
# a glob cannot fall out of step with it.
shopt -s nullglob
_debs=(Zecboat_*_amd64.deb)
_apps=(Zecboat_*_amd64.AppImage)
shopt -u nullglob

if [[ "$APPIMAGE_ONLY" -eq 1 ]]; then
  (( ${#_apps[@]} == 1 )) \
    || die "expected exactly one Zecboat_*_amd64.AppImage beside this script; found ${#_apps[@]} in $(pwd)"
else
  (( ${#_debs[@]} == 1 )) \
    || die "expected exactly one Zecboat_*_amd64.deb beside this script; found ${#_debs[@]} in $(pwd)"
fi
DEB="${_debs[0]-}"
APPIMAGE="${_apps[0]-}"

# --- verify the copy BEFORE anything else -----------------------------------
say "Verifying"
TARGET="$([[ "$APPIMAGE_ONLY" -eq 1 ]] && echo "$APPIMAGE" || echo "$DEB")"
[[ -f "$TARGET" ]] || die "$TARGET is not in $(pwd)"
# The sums are trusted only once their signature verifies under the release key. The key
# ships beside them so this check needs no network; its hex is printed so you can compare it
# with the one on zecboat.com/download, which is the comparison that makes it mean something.
# Nothing is installed without it (review 2026-10-09, session 4, Issue K).
[[ -f SHA256SUMS && -f SHA256SUMS.sig && -f release_public_key.hex ]] \
  || die "SHA256SUMS, SHA256SUMS.sig and release_public_key.hex must all be beside this script; refusing to install an unverified package"
command -v openssl >/dev/null || die "openssl is needed to verify the signature (apt install openssl)"
command -v python3 >/dev/null || die "python3 is needed to verify the signature"
PUBHEX="$(tr -d ' \n' < release_public_key.hex)"
[[ "$PUBHEX" =~ ^[0-9a-f]{64}$ ]] || die "release_public_key.hex is not a 64-hex Ed25519 key"
PDER="$(mktemp)"; PPEM="$(mktemp)"
python3 -c "import binascii,sys;open(sys.argv[1],'wb').write(binascii.unhexlify('302a300506032b6570032100'+sys.argv[2]))" "$PDER" "$PUBHEX"
openssl pkey -pubin -inform DER -in "$PDER" -out "$PPEM" 2>/dev/null || die "could not read the release public key"
if openssl pkeyutl -verify -pubin -inkey "$PPEM" -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig >/dev/null 2>&1; then
  info "SHA256SUMS signature OK under release key $PUBHEX"
  info "compare that key with the one published at https://zecboat.com/download"
else
  rm -f "$PDER" "$PPEM"
  die "SHA256SUMS.sig does NOT verify under the release key. Do not install this copy."
fi
rm -f "$PDER" "$PPEM"
# Only the file being installed; the other may not have been copied across.
if grep " $TARGET\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1; then
  info "$TARGET checksum OK"
else
  die "checksum MISMATCH on $TARGET.
  The copy is damaged. Recopy it. Installing a wallet binary you have not
  verified is not worth the minute it saves."
fi

# --- dependencies -----------------------------------------------------------
if [[ "$DO_DEPS" -eq 1 ]]; then
  [[ -x ./install_depends.sh ]] || die "install_depends.sh is missing — copy it alongside this script"
  bash ./install_depends.sh || die "dependency setup failed"
else
  say "Dependencies — SKIPPED (--no-deps)"
  warn "If the Sapling parameters are absent the wallet will sync fine and then"
  warn "fail on your first send. Check with: bash install_depends.sh --check"
fi

# --- AppImage path ----------------------------------------------------------
if [[ "$APPIMAGE_ONLY" -eq 1 ]]; then
  chmod +x "$APPIMAGE"
  say "AppImage ready"
  info "Run it with:  ./$APPIMAGE"
  info ""
  info "Nothing was installed system-wide, so there is nothing for apt to remove."
  info "To undo this, delete the file. Your wallet in ~/.AppVault is separate and"
  info "is not touched either way."
  [[ "$DO_RUN" -eq 1 ]] && exec "./$APPIMAGE"
  exit 0
fi

# --- already installed? -----------------------------------------------------
if dpkg-query -W -f='${Status}' "$PKG" 2>/dev/null | grep -q "install ok installed"; then
  say "Already installed"
  info "$PKG $(dpkg-query -W -f='${Version}' "$PKG") is present; apt will replace it in place."
  info "Your wallet in ~/.AppVault is not touched by installing or removing the package."
fi

# --- install ----------------------------------------------------------------
say "Installing"
info "this needs sudo"
sudo apt install -y "./$DEB" || die "apt install failed — read the message above.
    An unmet dependency here is a real finding: the package names something this
    Debian version calls by another name. Note which, and report it."
info "installed: package '$PKG', binary /usr/bin/$BIN"

# --- how to run -------------------------------------------------------------
say "Done"
info "Run it:            $BIN"
info ""
info "Syncs from the public node zec.rocks by default. Your own node instead:"
info "  ZECBOAT_PROVIDER=http://127.0.0.1:9067 $BIN"
info ""
info "Transparent addresses are NOT watched by default. Detecting a payment to a"
info "t-address means naming that address to the node, which tells it the address"
info "is yours — the one thing shielded scanning never does. If you hand one out:"
info "  ZECBOAT_TRANSPARENT_SCAN=1 $BIN"
info ""
info "Remove it:         sudo apt remove $PKG"
info "Remove everything: bash uninstall_zecboat_deb.sh --yes --wallet"

[[ "$DO_RUN" -eq 1 ]] && { say "Launching"; exec "$BIN"; }
exit 0
