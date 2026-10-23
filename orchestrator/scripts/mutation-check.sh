#!/usr/bin/env bash
# Plants one bug at a time in the orchestrator, the mock signer or the audit log and checks that the unit tests
# catch it. A suite that still passes with a security check removed is not testing that check.
# Usage: scripts/mutation-check.sh   (from orchestrator/; needs Maven)
set -uo pipefail
cd "$(dirname "$0")/.."
COMPILE_CMD=${COMPILE_CMD:-"mvn -q -B compile"}
TEST_CMD=${TEST_CMD:-"mvn -q -B test -Dtest=!AnvilEndToEndTest"}
TMP=$(mktemp -d)
FILES=(src/main/java/custody/orchestrator/Orchestrator.java
       src/main/java/custody/orchestrator/hsm/MockHsmSigner.java
       src/main/java/custody/orchestrator/crypto/Secp256k1.java
       src/main/java/custody/orchestrator/audit/AuditLog.java)
for f in "${FILES[@]}"; do cp "$f" "$TMP/$(basename "$f")"; done
restore() { for f in "${FILES[@]}"; do cp "$TMP/$(basename "$f")" "$f"; done; }
trap 'restore; rm -rf "$TMP"' EXIT

survived=0
mutate() { # name, file, perl substitution
  restore
  perl -0pi -e "$3" "$2"
  if cmp -s "$2" "$TMP/$(basename "$2")"; then echo "?? $1: mutation did not apply"; survived=1; return; fi
  # A mutant that doesn't compile proves nothing about the tests.
  if ! $COMPILE_CMD >"$TMP/log" 2>&1; then echo "?? $1: mutant does not compile"; survived=1; return; fi
  if $TEST_CMD >"$TMP/log" 2>&1; then
    echo "SURVIVED  $1"; survived=1
  else
    echo "caught    $1"
  fi
}

O=src/main/java/custody/orchestrator/Orchestrator.java
H=src/main/java/custody/orchestrator/hsm/MockHsmSigner.java
C=src/main/java/custody/orchestrator/crypto/Secp256k1.java
A=src/main/java/custody/orchestrator/audit/AuditLog.java

mutate "orchestrator: approval not compared with the proposal"  "$O" 's/if \(!p\.isWithdrawal\(\) \|\|/if (false \&\&/'
mutate "orchestrator: expired intents accepted"                 "$O" 's/if \(now > s\.intent\(\)\.deadline\(\)\)/if (false)/'
mutate "orchestrator: no limit on how far ahead a deadline is"  "$O" 's/if \(s\.intent\(\)\.deadline\(\) > now \+ policy/if (false \&\& s.intent().deadline() > now + policy/'
mutate "orchestrator: nonces never checked"                     "$O" 's/if \(nonces\.isUsed\(approver, s\.intent\(\)\.nonce\(\)\)\)/if (false)/; s/if \(!nonces\.markUsed\(approver, s\.intent\(\)\.nonce\(\)\)\)/if (false)/'
mutate "orchestrator: removed owners still used"               "$O" 's/if \(!chain\.isOwner\(owner\)\) throw/if (false) throw/'
mutate "orchestrator: allowlist not checked"                    "$O" 's/if \(!chain\.isAllowedDestination\(to\)\) throw/if (false) throw/'
mutate "orchestrator: own cap ignored"                          "$O" 's/if \(cap != null && amount\.compareTo\(cap\) > 0\)/if (false)/'
mutate "signer: calldata not compared with the intent"          "$H" 's/if \(!Arrays\.equals\(expected, data\)\) refuse/if (false) refuse/'
mutate "signer: any approver's intent accepted for any key"     "$H" 's/if \(signer == null \|\| !Address\.same\(signer, slot\.approver\(\)\)\)/if (signer == null)/'
mutate "signer: anything signed without an intent"              "$H" 's/if \(data\.length != 36 \|\| !Arrays\.equals/if (false \&\& !Arrays.equals/'
mutate "signer: other chains accepted"                          "$H" 's/if \(tx\.chainId\(\) != domain\.chainId\(\)\) refuse/if (false) refuse/'
mutate "signer: replayed intents accepted"                      "$H" 's/if \(!usedNonces\.add\(nonceKey\)\) refuse/usedNonces.add(nonceKey); if (false) refuse/'
mutate "crypto: high-s (malleable) signatures accepted"         "$C" 's/if \(s\.signum\(\) <= 0 \|\| s\.compareTo\(HALF_N\) > 0\)/if (s.signum() <= 0)/'
mutate "audit: signing not recorded before the signer is called" "$O" 's/audit\.record\("sign\.requested", req\);//'
mutate "audit: entry hashes not checked"                        "$A" 's/if \(!computed\.equals\(stored\)\)/if (false)/'
mutate "audit: prev links not checked"                          "$A" 's/if \(!prev\.equals\(e\.get\("prev"\)\)\)/if (false)/'
mutate "audit: sequence numbers not checked"                    "$A" 's/n\.longValue\(\) != lineNo \|\|/false \&\&/'
mutate "audit: anchors ignored"                                 "$A" 's/if \(s > hashes\.size\(\)\)/if (false)/; s/if \(!hashes\.get\(\(int\) s - 1\)\.equals\(m\.get\("hash"\)\)\)/if (false)/'
mutate "audit: a tampered log is opened anyway"                 "$A" 's/if \(!r\.ok\(\)\) throw new IllegalStateException/if (false) throw new IllegalStateException/'

exit $survived
