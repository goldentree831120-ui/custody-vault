#!/usr/bin/env bash
# P3 M6: a 2-of-3 P2WSH multisig on a private regtest chain, spent with PSBTs.
#
# Three signer wallets (A, B, C) each hold one key. A watch-only "coordinator" wallet knows only
# the three public keys: it can build transactions and track the balance but can't sign. Spending
# goes coordinator -> signers -> combine -> finalize -> broadcast, and the script checks every rule
# along the way. Regtest only: a throwaway chain in a temp directory, coins with no value, no
# connection to any other node.
#
# Needs bitcoind + bitcoin-cli (Bitcoin Core 26+; see install-bitcoin-core.sh) and jq.
set -euo pipefail

BITCOIN_BIN=${BITCOIN_BIN:-}
BITCOIND=${BITCOIN_BIN:+$BITCOIN_BIN/}bitcoind
CLI=${BITCOIN_BIN:+$BITCOIN_BIN/}bitcoin-cli
command -v "$BITCOIND" >/dev/null || { echo "bitcoind not found (run ./install-bitcoin-core.sh, or set BITCOIN_BIN)"; exit 1; }
command -v jq >/dev/null || { echo "jq not found: sudo apt install -y jq"; exit 1; }

DATA=$(mktemp -d)
RPCPORT=${RPCPORT:-18943}
cli() { "$CLI" -regtest -datadir="$DATA" -rpcport="$RPCPORT" "$@"; }
w() { local wallet=$1; shift; cli -rpcwallet="$wallet" "$@"; }
cleanup() { cli stop >/dev/null 2>&1 || true; sleep 1; rm -rf "$DATA"; }
trap cleanup EXIT

CHECKS=0
ok() { CHECKS=$((CHECKS + 1)); echo "   ok  $1"; }
check() { # description, then a command that must succeed
  local what=$1; shift
  if "$@"; then ok "$what"; else echo "CHECK FAILED: $what"; exit 1; fi
}
eq() { [ "$1" = "$2" ] || { echo "     expected <$2>, got <$1>"; return 1; }; }
# Amounts compared as numbers in satoshis (bitcoind prints 0.40000000, jq may print 0.4).
sats() { awk -v a="$1" 'BEGIN { printf "%.0f", a * 100000000 }'; }
amount_eq() { eq "$(sats "$1")" "$(sats "$2")"; }

echo "== setup: private regtest node ($("$BITCOIND" -version | head -1))"
"$BITCOIND" -regtest -datadir="$DATA" -rpcport="$RPCPORT" -listen=0 -connect=0 -dnsseed=0 \
  -fallbackfee=0.0002 -daemonwait >/dev/null
check "chain is regtest" eq "$(cli getblockchaininfo | jq -r .chain)" "regtest"

for name in signerA signerB signerC outsider miner recipient; do cli createwallet "$name" >/dev/null; done
# The coordinator has no private keys at all (disable_private_keys=true, blank=true).
cli -named createwallet wallet_name=coord disable_private_keys=true blank=true >/dev/null

echo
echo "== 1. build the 2-of-3 descriptor from the signers' public keys"
# Each signer shares one extended PUBLIC key with its origin ([fingerprint/path]tpub...).
# (A production setup would use a dedicated BIP 48 multisig path; this follows Bitcoin Core's
# multisig tutorial and reuses each wallet's BIP 84 account key.)
xpub() { w "$1" listdescriptors | jq -r '[.descriptors[] | select(.desc | startswith("wpkh(") and contains("/0/*"))][0].desc' \
         | sed -E 's/^wpkh\((.*)\/0\/\*\)#.*$/\1/'; }
XA=$(xpub signerA); XB=$(xpub signerB); XC=$(xpub signerC)
echo "   A: ${XA:0:40}..."; echo "   B: ${XB:0:40}..."; echo "   C: ${XC:0:40}..."
check "three different signer keys" test "$(printf '%s\n' "$XA" "$XB" "$XC" | sort -u | wc -l)" -eq 3
check "no private key material was shared (tpub only, no tprv)" bash -c "! printf '%s' '$XA$XB$XC' | grep -q tprv"

desc() { cli getdescriptorinfo "wsh(sortedmulti(2,$XA/$1/*,$XB/$1/*,$XC/$1/*))" | jq -r .descriptor; }
RECV=$(desc 0)   # receive addresses
CHANGE=$(desc 1) # change addresses
IMPORT=$(jq -nc --arg r "$RECV" --arg c "$CHANGE" \
  '[{desc:$r, active:true, internal:false, timestamp:"now", range:[0,100]},
    {desc:$c, active:true, internal:true,  timestamp:"now", range:[0,100]}]')
check "coordinator imported the receive and change descriptors" \
  eq "$(w coord importdescriptors "$IMPORT" | jq -c '[.[].success]')" "[true,true]"

ADDR=$(w coord getnewaddress "vault" bech32)
check "every party derives the same first address from the descriptor" \
  eq "$(cli deriveaddresses "$RECV" "[0,0]" | jq -r '.[0]')" "$ADDR"
INFO=$(w coord getaddressinfo "$ADDR")
check "it's P2WSH: witness v0 with a 32-byte script hash ($ADDR)" \
  eq "$(jq -r '"\(.iswitness) \(.witness_version) \(.witness_program | length)"' <<<"$INFO")" "true 0 64"
check "the coordinator watches it but holds no keys" \
  eq "$(jq -r '"\(.ismine) \(.solvable)"' <<<"$INFO") $(w coord getwalletinfo | jq -r .private_keys_enabled)" "true true false"

echo
echo "== 2. fund the multisig"
MINER=$(w miner getnewaddress)
cli generatetoaddress 101 "$MINER" >/dev/null # coinbase coins mature after 100 blocks
w miner sendtoaddress "$ADDR" 1.0 >/dev/null
cli generatetoaddress 1 "$MINER" >/dev/null
check "coordinator sees 1.0 BTC in the multisig" amount_eq "$(w coord getbalance)" "1.00000000"

echo
echo "== 3. coordinator builds the spend (0.4 BTC to the recipient) as a PSBT"
DEST=$(w recipient getnewaddress)
PSBT=$(w coord -named walletcreatefundedpsbt inputs='[]' outputs="[{\"$DEST\":0.4}]" \
  options='{"includeWatching":true}' | jq -r .psbt)
DEC=$(cli decodepsbt "$PSBT")
check "the witness script is OP_2 <3 pubkeys> OP_3 OP_CHECKMULTISIG" \
  eq "$(jq -r '.inputs[0].witness_script.asm | split(" ") | "\(.[0]) \(length) \(.[-2]) \(.[-1])"' <<<"$DEC")" "2 6 3 OP_CHECKMULTISIG"
check "the PSBT tells each signer which of its keys is involved (3 BIP32 paths)" \
  eq "$(jq '.inputs[0].bip32_derivs | length' <<<"$DEC")" "3"
# Before anyone signs: what exactly is being paid? Every output must be the recipient or our own change.
OUTS=$(jq -r '.tx.vout[] | "\(.scriptPubKey.address) \(.value)"' <<<"$DEC")
CHANGE_ADDR=$(awk -v d="$DEST" '$1 != d {print $1}' <<<"$OUTS")
check "exactly two outputs: the recipient and one change output" test "$(wc -l <<<"$OUTS")" -eq 2
check "recipient gets exactly 0.4 BTC" amount_eq "$(awk -v d="$DEST" '$1 == d {print $2}' <<<"$OUTS")" "0.4"
check "the change goes back to the multisig (coordinator's change descriptor)" \
  eq "$(w coord getaddressinfo "$CHANGE_ADDR" | jq -r '"\(.ismine) \(.ischange)"')" "true true"
FEE=$(jq -r .fee <<<"$DEC")
check "fee is sane ($FEE BTC)" awk -v f="$FEE" 'BEGIN { exit !(f > 0 && f < 0.001) }'

echo
echo "== 4. signing"
sigs() { cli decodepsbt "$1" | jq '.inputs[0].partial_signatures // {} | length'; }
CO=$(w coord walletprocesspsbt "$PSBT" | jq -r .psbt)
check "the coordinator can't sign (0 signatures)" eq "$(sigs "$CO")" "0"
OUT=$(w outsider walletprocesspsbt "$PSBT" | jq -r .psbt)
check "a wallet that isn't one of the three adds nothing (0 signatures)" eq "$(sigs "$OUT")" "0"

PA=$(w signerA walletprocesspsbt "$PSBT" | jq -r .psbt)
check "signer A signed (1 signature)" eq "$(sigs "$PA")" "1"
check "one signature is not enough: finalize says incomplete" eq "$(cli finalizepsbt "$PA" | jq -r .complete)" "false"
check "analyzepsbt: still needs a signer" eq "$(cli analyzepsbt "$PA" | jq -r .next)" "signer"

PB=$(w signerB walletprocesspsbt "$PSBT" | jq -r .psbt) # B signs its own copy, in parallel
check "signer B signed its own copy (1 signature)" eq "$(sigs "$PB")" "1"
COMBINED=$(cli combinepsbt "[\"$PA\",\"$PB\"]")
check "combined: 2 signatures" eq "$(sigs "$COMBINED")" "2"
FIN=$(cli finalizepsbt "$COMBINED")
check "2 of 3: finalize says complete" eq "$(jq -r .complete <<<"$FIN")" "true"
HEX=$(jq -r .hex <<<"$FIN")
check "the node accepts it (testmempoolaccept)" eq "$(cli testmempoolaccept "[\"$HEX\"]" | jq -r '.[0].allowed')" "true"

echo
echo "== 5. tampering after signing"
# The signatures commit to the outputs (SIGHASH_ALL). Move 0.05 BTC from the change output to the
# recipient in the SIGNED transaction (totals unchanged, so only the signatures can catch it).
le() { printf '%016x' "$1" | fold -w2 | tac | tr -d '\n'; } # 8-byte little-endian amount
CHG_SATS=$(sats "$(awk -v c="$CHANGE_ADDR" '$1 == c {print $2}' <<<"$OUTS")")
OLD_R=$(le 40000000); NEW_R=$(le 45000000)
OLD_C=$(le "$CHG_SATS"); NEW_C=$(le $((CHG_SATS - 5000000)))
check "both amounts appear exactly once in the signed transaction" \
  test "$(grep -o "$OLD_R" <<<"$HEX" | wc -l) $(grep -o "$OLD_C" <<<"$HEX" | wc -l)" = "1 1"
BAD=${HEX/$OLD_R/$NEW_R}
BAD=${BAD/$OLD_C/$NEW_C}
check "the edited transaction decodes: recipient 0.45, outputs total unchanged" \
  amount_eq "$(cli decoderawtransaction "$BAD" | jq -r --arg d "$DEST" '.vout[] | select(.scriptPubKey.address == $d) | .value')" "0.45"
REJECT=$(cli testmempoolaccept "[\"$BAD\"]" | jq -r '.[0]["reject-reason"]')
check "the node rejects it because the signatures no longer match: $REJECT" bash -c "[[ '$REJECT' == *script-verify* ]]"

echo
echo "== 6. broadcast the real one"
TXID=$(cli sendrawtransaction "$HEX")
cli generatetoaddress 1 "$MINER" >/dev/null
check "confirmed in a block ($TXID)" test "$(w coord gettransaction "$TXID" | jq .confirmations)" -ge 1
check "recipient received 0.4 BTC" amount_eq "$(w recipient getbalance)" "0.40000000"
check "the multisig holds the rest (1.0 - 0.4 - fee)" \
  eq "$(sats "$(w coord getbalance)")" "$(( $(sats 1.0) - $(sats 0.4) - $(sats "$FEE") ))"

echo
echo "== 7. any two of the three: A and C spend the change"
PSBT2=$(w coord -named walletcreatefundedpsbt inputs='[]' outputs="[{\"$DEST\":0.1}]" options='{"includeWatching":true}' | jq -r .psbt)
S1=$(w signerA walletprocesspsbt "$PSBT2" | jq -r .psbt)
S2=$(w signerC walletprocesspsbt "$S1" | jq -r .psbt) # this time signed in sequence: A, then C
FIN2=$(cli finalizepsbt "$S2")
check "A + C is complete too" eq "$(jq -r .complete <<<"$FIN2")" "true"
cli sendrawtransaction "$(jq -r .hex <<<"$FIN2")" >/dev/null
cli generatetoaddress 1 "$MINER" >/dev/null
check "recipient now has 0.5 BTC" amount_eq "$(w recipient getbalance)" "0.50000000"

echo
echo "all $CHECKS checks passed"
