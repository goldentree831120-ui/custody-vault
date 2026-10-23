#!/usr/bin/env bash
# Downloads Bitcoin Core (Linux x86_64) into ~/.local/opt and checks its SHA-256 against the
# release's SHA256SUMS file. Free; about 50 MB. Nothing is installed system-wide and nothing runs.
#
# Note on trust: SHA256SUMS comes from the same server as the tarball, so this check catches a
# corrupted or truncated download, not a compromised server. For that, also verify
# SHA256SUMS.asc against the builders' keys (https://github.com/bitcoin-core/guix.sigs);
# see https://bitcoincore.org/en/download/ ("Verify your download"). For a regtest-only
# exercise with no real coins the checksum is enough; for anything holding value it isn't.
set -euo pipefail
VERSION=${VERSION:-31.1}
FILE="bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz"
BASE="https://bitcoincore.org/bin/bitcoin-core-${VERSION}"
DEST="$HOME/.local/opt"
mkdir -p "$DEST"
cd "$DEST"

if [ -x "bitcoin-${VERSION}/bin/bitcoind" ]; then
  echo "already installed: $DEST/bitcoin-${VERSION}/bin"
else
  curl -fsSLO "$BASE/$FILE"
  curl -fsSLo "SHA256SUMS-${VERSION}" "$BASE/SHA256SUMS"
  grep " $FILE\$" "SHA256SUMS-${VERSION}" | sha256sum -c - # exits non-zero (and stops) on a mismatch
  tar -xzf "$FILE"
  rm -f "$FILE"
fi
"$DEST/bitcoin-${VERSION}/bin/bitcoind" -version | head -1
echo
echo "Use it with:  export BITCOIN_BIN=$DEST/bitcoin-${VERSION}/bin"
