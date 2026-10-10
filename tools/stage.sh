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
[ -f "$DEB" ] || die "missing build output: $DEB"
# The AppImage is deliberately NOT released. It is 124 MB against the zip's 23 MB, and
# AWS gives 100 GB/month of free egress from EC2 -- roughly 800 AppImage downloads
# against 4,300 of the zip. Zecboat is a Debian desktop wallet; the .deb serves that
# audience directly and builders use the source tarball or git. Re-add it here if
# non-Debian distributions ever matter more than the bandwidth.

# Every artifact must be NEWER than the commit it claims to be built from. This is
# the check that would have caught the hand-staging error.
CT=$(git log -1 --format=%ct HEAD)
[ "$(stat -c%Y "$DEB")" -ge "$CT" ] || die "$(basename "$DEB") predates HEAD -- it is from an older build"

mkdir -p "$S/artifacts"

# The Debian download ships as a ZIP containing the .deb, its own SHA256SUMS, and the
# install scripts -- so a user verifies twice: the zip against the signed SHA256SUMS on
# the download page, then the .deb against the SHA256SUMS inside the zip. That shape is
# documented on zecboat.com/download and must not change silently.
ZIPDIR="$S/.zipwork/zecboat-$V-debian"
mkdir -p "$ZIPDIR"
cp "$DEB" "$ZIPDIR/"
for sc in install.sh install_depends.sh install_yubikey.sh uninstall_zecboat_deb.sh; do
  [ -f "$SRC_REPO/packaging/$sc" ] || die "missing packaging script: $sc"
  cp "$SRC_REPO/packaging/$sc" "$ZIPDIR/"; chmod +x "$ZIPDIR/$sc"
done
( cd "$ZIPDIR" && sha256sum ./*.deb ./*.sh | sed 's|\./||' > SHA256SUMS )
# The in-zip SHA256SUMS is signed too, and the public key travels with it, so install.sh can
# check the signature before trusting the sums it was shipped with (review 2026-10-09,
# session 4, Issue K: the inner file was unsigned and the installer proceeded without one).
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$ZIPDIR/SHA256SUMS" -out "$ZIPDIR/SHA256SUMS.sig" || die "signing the in-zip sums failed"
cp "$PUB" "$ZIPDIR/release_public_key.hex"
python3 - "$S/.zipwork" "$S/artifacts/zecboat-$V-debian.zip" <<'PYZIP'
import os, sys, zipfile
root, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for dirpath, _, files in os.walk(root):
        for f in sorted(files):
            full = os.path.join(dirpath, f)
            arc = os.path.relpath(full, root)
            zi = zipfile.ZipInfo(arc, date_time=(1980,1,1,0,0,0))
            zi.external_attr = (0o755 << 16) if f.endswith(".sh") else (0o644 << 16)
            zi.compress_type = zipfile.ZIP_DEFLATED
            with open(full, "rb") as fh: z.writestr(zi, fh.read())
PYZIP
rm -rf "$S/.zipwork"
git archive --format=tar.gz --prefix="zecboat-$V/" -o "$S/artifacts/zecboat-$V-src.tar.gz" HEAD

# --- gate every artifact -----------------------------------------------------
{
  echo "# Gate report — $V"; echo
  echo "Built from: $SRC_REPO @ $(git rev-parse --short HEAD) (tag v$V)"
  echo "Staged:     $(date -Is)"; echo '```'
} > "$S/GATE.md"
FAIL=0
for a in "$S/artifacts/"*.zip "$S/artifacts/"*.tar.gz; do
  out=$("$GATE" "$a" 2>&1); rc=$?
  echo "$out" | sed 's/^/  /' >> "$S/GATE.md"; echo "  exit $rc" >> "$S/GATE.md"; echo >> "$S/GATE.md"
  [ $rc -ne 0 ] && { echo "  GATE REFUSED $(basename "$a")"; FAIL=1; }
done
echo '```' >> "$S/GATE.md"
[ $FAIL -eq 0 ] || { rm -rf "$S"; die "gate refused an artifact -- staging removed"; }

# --- hashes, signature, provenance -------------------------------------------
cd "$S/artifacts"
sha256sum ./*.zip ./*.tar.gz | sed 's|\./||' > SHA256SUMS
openssl pkeyutl -sign -inkey "$KEY" -rawin -in SHA256SUMS -out SHA256SUMS.sig || die "signing failed"
# Private temporary names: fixed paths under /tmp could be pre-created by another user on a
# shared host and the check made to pass or fail at will (audit 2026-10-08, Zecboat N).
PDER="$(mktemp)"; PPEM="$(mktemp)"
python3 -c "import binascii,sys;open(sys.argv[1],'wb').write(binascii.unhexlify('302a300506032b6570032100'+open(sys.argv[2]).read().strip()))" "$PDER" "$PUB"
openssl pkey -pubin -inform DER -in "$PDER" -out "$PPEM" 2>/dev/null
openssl pkeyutl -verify -pubin -inkey "$PPEM" -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig >/dev/null 2>&1 \
  || die "signature does not verify under the published key"
rm -f "$PDER" "$PPEM"

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
