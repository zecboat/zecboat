#!/usr/bin/env bash
#
# stage.sh — assemble a staged release, or refuse.
#
# WHY THIS EXISTS
# ---------------
# Staging was done by hand on 2026-09-07 and the artifacts came from two different
# builds. A reviewer was then pointed at the staging directory and passed binaries
# that had been built from a working wallet directory -- the exact tree the release
# process had just been restructured to eliminate. Nobody noticed until the file
# timestamps were compared.
#
# So: this script copies ONLY from the declared build output, records where every
# byte came from, and refuses if anything is missing, stale, or fails the gate.
#
# Usage: stage.sh <version>          e.g. stage.sh 0.6.3-beta
set -uo pipefail

V="${1:?usage: stage.sh <version>}"
SRC_REPO="${ZB_SRC_REPO:-$HOME/zebd/zecboat_github_release/wallet}"
BUILD="$SRC_REPO/zecboat-ui/src-tauri/target/release/bundle"
STAGE_ROOT="$HOME"/zecd/zecboat_staging
GATE="$SRC_REPO/tools/release-gate.sh"   # the clean tree owns the gate, not a working directory
KEY="$HOME"/zebd/zecboat_keys/release_signing/release_signing_key.pem
PUB="$HOME"/zebd/zecboat_keys/release_signing/release_public_key.hex
S="$STAGE_ROOT/$V"
VER="${V%-*}"

die() { echo "REFUSED: $*" >&2; exit 1; }

# --- preconditions -----------------------------------------------------------
cd "$SRC_REPO" || die "no source repo at $SRC_REPO"
[ -z "$(git status --porcelain)" ] || die "source tree is dirty -- commit or clean first"
[ "$(grep -m1 '^version' zecboat-core/Cargo.toml | cut -d'"' -f2)" = "$VER" ] \
  || die "source declares $(grep -m1 '^version' zecboat-core/Cargo.toml | cut -d'"' -f2), not $VER"
git rev-parse "v$V" >/dev/null 2>&1 || die "no tag v$V -- a release must be tagged"
[ -d "$S" ] && die "$S already exists; staging directories are immutable, cut a new version"

DEB="$BUILD/deb/Zecboat_${VER}_amd64.deb"
APP="$BUILD/appimage/Zecboat_${VER}_amd64.AppImage"
for f in "$DEB" "$APP"; do [ -f "$f" ] || die "missing build output: $f"; done

# Every artifact must be NEWER than the commit it claims to be built from. This is
# the check that would have caught the hand-staging error.
CT=$(git log -1 --format=%ct HEAD)
for f in "$DEB" "$APP"; do
  [ "$(stat -c%Y "$f")" -ge "$CT" ] || die "$(basename "$f") predates HEAD -- it is from an older build"
done

mkdir -p "$S/artifacts"
cp "$DEB" "$APP" "$S/artifacts/"
git archive --format=tar.gz --prefix="zecboat-$V/" -o "$S/artifacts/zecboat-$V-src.tar.gz" HEAD

# --- gate every artifact -----------------------------------------------------
{
  echo "# Gate report — $V"; echo
  echo "Built from: $SRC_REPO @ $(git rev-parse --short HEAD) (tag v$V)"
  echo "Staged:     $(date -Is)"; echo '```'
} > "$S/GATE.md"
FAIL=0
for a in "$S/artifacts/"*.deb "$S/artifacts/"*.AppImage "$S/artifacts/"*.tar.gz; do
  out=$("$GATE" "$a" 2>&1); rc=$?
  echo "$out" | sed 's/^/  /' >> "$S/GATE.md"; echo "  exit $rc" >> "$S/GATE.md"; echo >> "$S/GATE.md"
  [ $rc -ne 0 ] && { echo "  GATE REFUSED $(basename "$a")"; FAIL=1; }
done
echo '```' >> "$S/GATE.md"
[ $FAIL -eq 0 ] || { rm -rf "$S"; die "gate refused an artifact -- staging removed"; }

# --- hashes, signature, provenance -------------------------------------------
cd "$S/artifacts"
sha256sum ./*.deb ./*.AppImage ./*.tar.gz | sed 's|\./||' > SHA256SUMS
openssl pkeyutl -sign -inkey "$KEY" -rawin -in SHA256SUMS -out SHA256SUMS.sig || die "signing failed"
python3 -c "import binascii;open('/tmp/.p.der','wb').write(binascii.unhexlify('302a300506032b6570032100'+open('$PUB').read().strip()))"
openssl pkey -pubin -inform DER -in /tmp/.p.der -out /tmp/.p.pem 2>/dev/null
openssl pkeyutl -verify -pubin -inkey /tmp/.p.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig >/dev/null 2>&1 \
  || die "signature does not verify under the published key"
rm -f /tmp/.p.der /tmp/.p.pem

cd "$SRC_REPO"
{
  echo "# Build record — $V"; echo
  echo "| | |"; echo "|---|---|"
  echo "| Source | \`$SRC_REPO\` |"
  echo "| Commit | \`$(git rev-parse HEAD)\` |"
  echo "| Tag | v$V |"
  echo "| Staged | $(date -Is) |"
  echo "| rustc | $(rustc --version) |"
  echo "| node | $(node --version) |"; echo
  echo '```'; echo 'RUSTFLAGS="--remap-path-prefix=$HOME=/build"'; echo '[profile.release] strip = true'; echo '```'
} > "$S/BUILD.md"
cp CHANGELOG.md "$S/CHANGELOG-$V.md" 2>/dev/null || true
cd "$S" && find . -type f -not -name MANIFEST.sha256 | sort | xargs sha256sum > MANIFEST.sha256
echo "STAGED: $S"
