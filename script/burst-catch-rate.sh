#!/usr/bin/env bash
# How reliably does invariant_noBurstBeyondBucket catch an uncapped rate-limit bucket?
# Plants that one bug, runs the invariant with 10 fixed seeds (11-20), prints how many caught it.
set -uo pipefail
cd "$(dirname "$0")/.."
SRC=src/CustodyVault.sol
cp "$SRC" /tmp/CustodyVault.sol.burst
trap 'cp /tmp/CustodyVault.sol.burst "$SRC"; rm -rf cache/invariant' EXIT
perl -0pi -e 's/return uint128\(total < limit \? total : limit\);/return uint128(total);/' "$SRC"
cmp -s "$SRC" /tmp/CustodyVault.sol.burst && { echo "mutation did not apply"; exit 1; }
caught=0
for seed in $(seq 11 20); do
  rm -rf cache/invariant # don't replay a counterexample from the previous seed
  if FOUNDRY_FUZZ_SEED=$seed forge test --match-test invariant_noBurstBeyondBucket >/dev/null 2>&1; then
    echo "seed $seed: missed"
  else
    echo "seed $seed: caught"; caught=$((caught + 1))
  fi
done
echo "caught in $caught of 10 runs"
