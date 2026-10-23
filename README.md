# Custody Vault

[![CI](https://github.com/goldentree831120-ui/custody-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/goldentree831120-ui/custody-vault/actions/workflows/ci.yml)

A multisig custody vault with a policy engine: M-of-N approvals, a timelock on large
withdrawals and on every configuration change, per-asset rate limits, a destination
allowlist and an emergency pause. Solidity + Foundry, with a Java signing orchestrator in front.

Status: **M1** threat model ([`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)), **M2** vault + tests,
**M3** Slither ([`docs/SLITHER_TRIAGE.md`](docs/SLITHER_TRIAGE.md)), **M4** signing orchestrator
([`orchestrator/`](orchestrator/README.md); mock HSM, test keys only) and **M5** hash-chained audit
log ([`orchestrator/README.md#audit-log-m5`](orchestrator/README.md#audit-log-m5)) and **M6** Bitcoin
2-of-3 P2WSH multisig with PSBTs on regtest ([`bitcoin/`](bitcoin/README.md)) are done. M7 README is next.

```bash
# after cloning: fetch the pinned dependencies (forge-std v1.17.0, OpenZeppelin v5.1.0, git submodules)
git submodule update --init --recursive
forge test               # 35 unit/fuzz tests + 7 invariants, ~10 s
FOUNDRY_PROFILE=deep forge test --match-path 'test/invariant/*'   # 2,000 runs x 200 calls, ~2-3 min
./script/mutation-check.sh   # plants 6 bugs one at a time; the suite must catch each
pip install slither-analyzer==0.11.6 && slither . --exclude-dependencies --filter-paths "lib/|test/|script/" --fail-low
cd orchestrator && ./demo.sh  # Java 21 + Maven: EIP-712 intents, mock HSM, Anvil, and a verified audit log
cd bitcoin && ./install-bitcoin-core.sh && BITCOIN_BIN=~/.local/opt/bitcoin-31.1/bin ./regtest-multisig.sh
```

On Windows, run these in WSL or Git Bash (Foundry: https://getfoundry.sh).

## How a withdrawal works

```
 owner A                owners B..M                      any owner
 proposeWithdrawal ──▶  approve ... (M reached) ──▶ [timelock if large] ──▶ execute
   checks: not paused,                                 checks again: M approvals from
   destination allowlisted,                            current owners, timelock passed,
   amount <= daily limit                               not paused, still allowlisted,
                                                       rate-limit bucket has room
                    any single owner can cancel() at any point before execute
```

Configuration changes (owners, threshold, allowlist, limits, unpause) use the same flow
with `proposeConfig(calldata)`. They are **always** timelocked, and the calldata can only
target the six `onlySelf` functions. There is no admin key.

## Design decisions

| Decision | Why | Trade-off |
|---|---|---|
| Approvals are on-chain transactions, not off-chain signatures | No signature replay surface in the contract; every approval is logged with its sender | Each approval costs gas. The M4 orchestrator puts EIP-712 intents (nonce, deadline, chain id and vault in the domain) in front, off-chain, and still approves on-chain |
| **Token bucket** rate limit, not a fixed daily window | A fixed window lets 2x the limit out across midnight. A bucket never holds more than one day's limit | Slightly more state. Rounding is floor, so it always errs toward the vault |
| New assets start with an **empty** bucket | Total outflow since configuration is provably `<= limit * days` | First withdrawal of a new asset waits for refill |
| Lowering a limit clamps immediately; raising it refills gradually | Tightening should be instant, loosening should not create a burst | |
| Timelock applies if the withdrawal was large **when proposed or** is large under the current policy | Changing the policy can make a pending withdrawal stricter, never looser | |
| Any single owner can `cancel` and `pause` | One honest owner can stop M compromised keys during the timelock | One malicious owner can grief (pause/cancel repeatedly). Recovery is removing them via M-of-N, which they can also cancel: documented in the threat model |
| Unpause needs M-of-N + timelock | A stolen single key cannot undo a pause | Slow recovery after a false alarm |
| Owner/threshold change invalidates all open proposals (`ownerSetVersion`) | Approvals given under the old owner set cannot be carried over | Pending proposals must be re-proposed |
| Approval window 14 days, execution window 7 days after becoming executable | Old approvals can't be used months later | |
| Allowlist checked at propose **and** execute | Removing a destination stops proposals already approved for it | |

Out of scope for M2: fee-on-transfer and rebasing tokens, ERC-777 hooks, upgradeability,
key storage. See the threat model.

## Tests

`test/CustodyVault.t.sol`: one test per rule, plus two fuzz tests.

`test/invariant/`: a handler drives random sequences of propose / approve / revoke /
cancel / execute / pause / unpause / time jumps across 5 owners (threshold 3), an
outsider, two allowlisted destinations and one that is not. The handler keeps its **own
model** of approvals and timelocks, built only from calls that succeeded, and checks
the vault against it. Invariants:

| Invariant | Meaning |
|---|---|
| `noExecutionWithoutMApprovals` | every executed proposal had M approvals from current owners (by the model's count); the outsider never executed anything |
| `withdrawalsNeverExceedRateLimit` | total outflow per asset `<= dailyLimit * days since policy set` |
| `noBurstBeyondBucket` | for any window between two withdrawals, outflow `<= limit + refill during the window` |
| `largeWithdrawalsRespectTimelock` | large withdrawals never ran before M approvals + delay |
| `nothingExecutesWhilePaused` | |
| `onlyAllowlistedDestinationsReceiveFunds` | outsider, owners and the non-allowlisted address never received anything |
| `conservation` | vault + destinations always equals deposits |

**Do the invariants actually catch bugs?** `script/mutation-check.sh` plants six bugs
(ignore the threshold, skip the timelock, uncap the bucket, drop the allowlist check,
ignore pause...) and confirms each one makes the suite fail. Result in
`docs/mutation-report.txt`. Writing it found two real weaknesses in the first
version of the tests: removing the bucket cap passed every invariant (the cumulative
bound still held), which is why `noBurstBeyondBucket` exists; and removing only the
threshold check was hidden by the timelock gate, so it is caught by the unit tests rather
than the invariants.
