#!/usr/bin/env bash
# Plants one bug at a time in CustodyVault.sol and checks that the test suite catches it.
# A test suite that still passes with a bug planted is not testing that rule.
set -uo pipefail
cd "$(dirname "$0")/.."
SRC=src/CustodyVault.sol
cp "$SRC" /tmp/CustodyVault.sol.orig
trap 'cp /tmp/CustodyVault.sol.orig "$SRC"' EXIT

mutate() { # name, perl substitution
  cp /tmp/CustodyVault.sol.orig "$SRC"
  perl -0pi -e "$2" "$SRC"
  if cmp -s "$SRC" /tmp/CustodyVault.sol.orig; then echo "?? $1: mutation did not apply"; return; fi
  forge test >/tmp/mut.log 2>&1
  local inv unit
  # Failing invariants = every invariant named in the log minus those marked [PASS].
  # Works for both forge output formats (older: name on its own line after "[FAIL: ...]";
  # newer: invariants grouped under one test as "[PASS] invariant_x" / "[FAIL: ...] invariant_x").
  inv=$(comm -23 <(grep -oE 'invariant_[A-Za-z]+' /tmp/mut.log | sort -u) \
                 <(grep -E '\[PASS\]' /tmp/mut.log | grep -oE 'invariant_[A-Za-z]+' | sort -u) | tr '\n' ' ')
  unit=$(grep -E '^\[FAIL' /tmp/mut.log | grep -oE '\] test[A-Za-z_]+' | sort -u | wc -l | tr -d ' ')
  if [ -z "$inv" ] && [ "$unit" = 0 ]; then
    echo "SURVIVED  $1"
  else
    echo "caught    $1"
    echo "          invariants: ${inv:-none}   unit/fuzz tests failing: $unit"
  fi
}

mutate "execute ignores threshold (needs 1 approval)" 's/if \(n < threshold\) revert NotEnoughApprovals/if (n < 1) revert NotEnoughApprovals/'
mutate "threshold check AND timelock start both use 1" 's/if \(n < threshold\) revert NotEnoughApprovals/if (n < 1) revert NotEnoughApprovals/; s/if \(n >= threshold && p\.thresholdReachedAt == 0\)/if (n >= 1 \&\& p.thresholdReachedAt == 0)/'
mutate "large withdrawals skip the timelock"          's/return p\.largeAtCreation \|\| p\.amount >= assetPolicy\[p\.asset\]\.largeThreshold;/return false;/'
mutate "rate-limit bucket is not capped"              's/return uint128\(total < limit \? total : limit\);/return uint128(total);/'
mutate "allowlist not checked at proposal or execution" 's/if \(!isAllowedDestination\[to\]\) revert DestinationNotAllowed\(to\);//; s/if \(!isAllowedDestination\[p\.to\]\) revert DestinationNotAllowed\(p\.to\);//'
mutate "pause does not block execution"               's/function _executeWithdrawal\(uint256 id, Proposal storage p\) internal \{\n        if \(paused\) revert IsPaused\(\);/function _executeWithdrawal(uint256 id, Proposal storage p) internal {/'
