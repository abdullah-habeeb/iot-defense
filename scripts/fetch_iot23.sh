#!/bin/bash
# Download the IoT-23 captures used by evaluation/public_eval.py into data/external/iot23/ and verify them.
# The files are not in git (two exceed GitHub's 100 MB limit); they are attached to the GitHub release data-iot23-v1.
# IoT-23: Garcia, Parmisano, Erquiaga (2020), Stratosphere Laboratory, CTU Prague, CC BY 4.0,
# https://doi.org/10.5281/zenodo.4743746  -- please cite it if you use these files.
set -euo pipefail
cd "$(dirname "$0")/.."
BASE="https://github.com/abdullah-habeeb/iot-defense/releases/download/data-iot23-v1"
DEST=data/external/iot23
mkdir -p "$DEST"
cd "$DEST"
curl -fsSL -o SHA256SUMS.txt "$BASE/SHA256SUMS.txt"
while read -r _ name; do
  if [ -f "$name" ] && sha256sum --check --status <(grep " $name\$" SHA256SUMS.txt); then
    echo "ok (already present): $name"
    continue
  fi
  echo "downloading $name"
  curl -fL --retry 3 -o "$name" "$BASE/$name"
done < SHA256SUMS.txt
sha256sum --check SHA256SUMS.txt
