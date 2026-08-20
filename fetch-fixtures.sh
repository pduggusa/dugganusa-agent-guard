#!/usr/bin/env bash
# Fetch the OFFICIAL C2PA test corpus for test-provenance.js.
#
# We do not vendor these into the repo: they are ~5 MB of somebody else's files,
# and testing a provenance parser against fixtures WE generated would only prove
# the parser agrees with itself. The corrupt E-* fixtures are the important ones.
set -euo pipefail
B="https://raw.githubusercontent.com/c2pa-org/public-testfiles/main/legacy/1.4/image/jpeg"
D="$(dirname "$0")/test-fixtures-c2pa"
mkdir -p "$D"
for f in adobe-20220124-CA.jpg adobe-20220124-E-sig-CA.jpg adobe-20220124-E-clm-CAICAI.jpg \
         adobe-20220124-E-dat-CA.jpg truepic-20230212-camera.jpg nikon-20221019-building.jpeg; do
  [ -f "$D/$f" ] || curl -fsSL "$B/$f" -o "$D/$f"
  echo "  $f"
done
echo "fixtures in $D"
