#!/usr/bin/env bash
#
# release-gate.sh — refuse to publish an artifact that carries the build machine.
#
# WHY THIS EXTRACTS FIRST
# -----------------------
# Scanning a packaged artifact is theatre. Measured on Zecboat 0.6.2 (2026-09-07):
#
#   Zecboat_0.6.2_amd64.deb    packaged: 0 hits    extracted: 1070 hits
#   Zecboat_0.6.2_amd64.AppImage  packaged: 1 hit  extracted: 1070 hits
#
# Compression hid 100% of the leaks in the .deb and all but one in the AppImage. An
# earlier version of this design scanned the containers and would have passed both.
#
# TWO PATTERN CLASSES, AND WHY
# ----------------------------
# STRICT patterns are never legitimate anywhere -- this machine's identifiers.
# BINARY_ONLY patterns (a generic /home/<user>/ path) are legitimate in documentation
# and installer scripts, so they are enforced only against compiled files. Without that
# split the gate fires on RUNBOOK.md, and a gate that cries wolf gets switched off.
#
# Usage:  release-gate.sh <artifact> [artifact...]
# Exit:   0 clean · 1 leak found · 2 usage/tooling error

set -uo pipefail

# Patterns are loaded from gate-patterns.local, which is git-ignored and never shipped.
# They are NOT embedded here: this script was itself refused by an earlier run because it
# contained the very identifiers it searches for, password included. A scanner that carries
# the secret list is the leak.
PATTERNS="${GATE_PATTERNS:-$(dirname "$0")/gate-patterns.local}"
[ -r "$PATTERNS" ] || { echo "missing pattern file: $PATTERNS (copy gate-patterns.example)" >&2; exit 2; }
STRICT=(); BINARY_ONLY=()
while read -r kind pat; do
  case "$kind" in
    STRICT) STRICT+=( "$pat" ) ;;
    BINARY) BINARY_ONLY+=( "$pat" ) ;;
  esac
done < <(grep -vE '^\s*#|^\s*$' "$PATTERNS")
[ "${#STRICT[@]}" -gt 0 ] || { echo "no STRICT patterns loaded" >&2; exit 2; }

VENDOR_RE='(^|/)(usr/lib|usr/share/glib-2\.0|usr/share/icons|usr/share/locale|usr/plugins)/'

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
FOUND=0; SCANNED=0

scan_file() {
  local f="$1" rel="$2" isbin=0
  file -b "$f" 2>/dev/null | grep -qiE 'ELF|executable|shared object|archive' && isbin=1
  SCANNED=$((SCANNED+1))
  # The generic home-directory pattern used to run on ELF files only, so a path baked into a
  # vite bundle, a config JSON or a .desktop launcher walked straight through. It now runs
  # on everything EXCEPT prose, where documentation legitimately spells out a user home
  # directory in an instruction to the reader.
  # Vendored third-party libraries stay exempt: they carry their packager's paths, which are
  # not our identity and not ours to fix. STRICT still applies to them.
  local pats=( "${STRICT[@]}" )
  case "$rel" in
    *.md|*.txt|*.markdown) ;;                       # prose: strict patterns only
    *) [[ "$rel" =~ $VENDOR_RE ]] || pats+=( "${BINARY_ONLY[@]}" ) ;;
  esac
  for p in "${pats[@]}"; do
    local n
    n=$(strings -a "$f" 2>/dev/null | grep -cE -- "$p")
    if [ "${n:-0}" -gt 0 ]; then
      # Full path, never truncated: a 52-column cut once displayed
      # "native_builder.rs.bak" as "native_builder.r", which reads as real source and
      # sent the operator looking for a defect in a file that does not have one.
      printf '  LEAK  %s\n          pattern %-28s %s hit(s)\n' "$rel" "$p" "$n"
      FOUND=$((FOUND+1))
    fi
  done
}

scan_tree() { local root="$1"
  while IFS= read -r f; do scan_file "$f" "${f#$root/}"; done \
    < <(find "$root" -type f 2>/dev/null)
}

for ART in "$@"; do
  [ -f "$ART" ] || { echo "  missing: $ART" >&2; exit 2; }
  base=$(basename "$ART"); out="$WORK/$base.x"; mkdir -p "$out"
  echo "== $base"
  case "$ART" in
    *.deb)      dpkg-deb -x "$ART" "$out" 2>/dev/null || { echo "  dpkg-deb failed" >&2; exit 2; } ;;
    *.AppImage) cp "$ART" "$out/app"; chmod +x "$out/app"
                ( cd "$out" && ./app --appimage-extract >/dev/null 2>&1 ) || { echo "  appimage extract failed" >&2; exit 2; }
                rm -f "$out/app" ;;
    *.tar.gz|*.tgz) tar xzf "$ART" -C "$out" 2>/dev/null || exit 2 ;;
    *.zip)      unzip -q "$ART" -d "$out" 2>/dev/null || exit 2 ;;
    *)          cp "$ART" "$out/" ;;
  esac
  # Recurse into nested containers to a bounded DEPTH, not one level.
  #
  # An external review defeated the previous single-level version with
  #   outer.tar.gz -> middle.tar.gz -> inner.tar.gz -> leaky file
  # The middle layer was extracted, the inner one was scanned as a flat file, and
  # compression hid its contents: verdict CLEAN. One level of recursion is the same
  # blindness as none, just further in.
  #
  # Depth is capped so a malicious deeply-nested archive cannot spin forever, and hitting
  # the cap is a REFUSAL, not a pass -- an artifact we cannot fully open is not clean.
  MAXDEPTH=8
  extract_recursive() {
    local dir="$1" depth="$2"
    if [ "$depth" -gt "$MAXDEPTH" ]; then
      echo "  NESTING DEPTH > $MAXDEPTH -- refusing rather than scanning unopened"
      FOUND=$((FOUND+1)); return
    fi
    local found_any=0
    while IFS= read -r inner; do
      [ -f "$inner" ] || continue
      found_any=1
      local ib io ok=0
      ib=$(basename "$inner"); io="$inner.x$depth"; mkdir -p "$io"
      case "$inner" in
        *.deb)          dpkg-deb -x "$inner" "$io" 2>/dev/null && ok=1 ;;
        *.tar.gz|*.tgz) tar xzf "$inner" -C "$io" 2>/dev/null && ok=1 ;;
        *.tar)          tar xf  "$inner" -C "$io" 2>/dev/null && ok=1 ;;
        *.zip)          unzip -q "$inner" -d "$io" 2>/dev/null && ok=1 ;;
        *.AppImage)     cp "$inner" "$io/a"; chmod +x "$io/a"
                        ( cd "$io" && ./a --appimage-extract >/dev/null 2>&1 ) && { rm -f "$io/a"; ok=1; } ;;
      esac
      if [ "$ok" -eq 1 ]; then
        echo "  (nested depth $depth: $ib)"
        rm -f "$inner"                     # replaced by its contents; do not scan the blob
        extract_recursive "$io" $((depth+1))
      else
        echo "  UNEXTRACTED NESTED ARCHIVE: $ib -- refusing rather than scanning it compressed"
        FOUND=$((FOUND+1)); rm -rf "$io"
      fi
    done < <(find "$dir" \( -name '*.deb' -o -name '*.zip' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.tar' -o -name '*.AppImage' \) 2>/dev/null)
    return 0
  }
  extract_recursive "$out" 1

  scan_tree "$out"
done

echo
if [ "$FOUND" -gt 0 ]; then
  echo "REFUSED — $FOUND leak(s) across $SCANNED file(s) scanned"; exit 1
fi
echo "CLEAN — $SCANNED file(s) scanned, no leaks"; exit 0
