# Slither triage (P3 M3)

Slither 0.11.6 (crytic-compile 0.4.2), 102 detectors. Raw output: [`reports/slither.txt`](../reports/slither.txt).

```bash
pip install slither-analyzer==0.11.6
slither . --exclude-dependencies --filter-paths "lib/|test/|script/" --fail-low
```

CI runs exactly this on every push (`.github/workflows/ci.yml`). `--fail-low` means any **new**
Low, Medium or High finding fails the build. Findings reviewed below are either fixed or
annotated in the code with `// slither-disable-next-line <detector> -- <reason>`, so the
justification sits next to the line it covers.

## Results

| | First run | After triage |
|---|---|---|
| High / Medium | 0 | 0 |
| Low | 5 (`timestamp`) | 0: reviewed and annotated |
| Optimization | 1 (`cache-array-length`) | 0: **fixed** |
| Informational, vault code | 3 | 3: reviewed, below |
| Informational, OpenZeppelin | 10 | excluded with `--filter-paths lib/` (audited library code) |

## Each finding

| Detector | Where | Decision | Reasoning |
|---|---|---|---|
| `timestamp` (Low) | `execute` timelock check, `_open` expiry windows, `_executeWithdrawal` and `_refilled` rate limit, `setAssetPolicy` bucket clamp | **Accepted, annotated** | Time is the point of these controls (timelock, 14/7-day windows, a bucket that refills per 24 h). A block producer can skew the timestamp by seconds; the shortest timelock is 1 hour, and a few seconds move the rate limit by a negligible amount. Slither flags any comparison that depends on time, including `p.amount > available` and `total < limit`, because `available` is computed from the timestamp. |
| `cache-array-length` (Optimization) | `approvalCount` loop over `_owners` | **Fixed** | Read `_owners.length` once instead of on every iteration. A small gas saving on every approve/execute. |
| `low-level-calls` (Info) | `execute`: `address(this).call(p.data)` | **Accepted** | This is how an approved config proposal runs one of the six `onlySelf` functions. The selector is whitelisted at proposal time (`_isConfigSelector`, `test_proposeConfig_rejectsArbitraryCalldata`), and the return value is checked (`ConfigCallFailed`). |
| `low-level-calls` (Info) | `_executeWithdrawal`: `p.to.call{value: amount}("")` | **Accepted** | The standard way to send ETH without a 2300-gas stipend, so a contract destination (e.g. a Safe) can receive. The return value is checked; reentrancy is blocked by `nonReentrant` plus checks-effects-interactions (`test_reentrancyThroughEthReceiver_isBlocked`). |
| `costly-loop` (Info) | `removeOwner`: `_owners.pop()` inside a loop | **False positive** | The loop `break`s right after the single `pop()`, and the owner count is capped at 20 (`MAX_OWNERS`). |
| `pragma`, `solc-version`, `assembly`, `dead-code`, `low-level-calls` | OpenZeppelin v5.1.0 | **Out of scope** | Audited library code: open `^0.8.20` pragmas (the listed compiler bugs don't affect 0.8.26, which is what's used), inline assembly in `SafeERC20`/`Address`, and unused internal helpers. |

## What Slither can't tell you

Slither matches code patterns. It found nothing about the questions that matter most for this
vault: whether M stolen keys can drain it faster than the rate limit, whether a config change
can skip the timelock, or whether one owner can freeze it (they can, by design, see
[`THREAT_MODEL.md`](THREAT_MODEL.md) §4.6). Those are answered by the threat model and checked
by the invariant tests and `script/mutation-check.sh`, not by static analysis.

## Foundry's linter (`forge lint`)

Newer Foundry versions also lint during `forge build` (the warnings printed before
`orchestrator/demo.sh` starts). They were reviewed in M7 against the same code; none needs a
code change.

| Lint | Where | Decision | Reasoning |
|---|---|---|---|
| `block-timestamp` (×3), `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-events`, `arbitrary-send-eth` | timelock / expiry / bucket checks; `execute`'s two external calls; `Withdrawn` event | **Same as Slither above** | Time-based by design; `execute` is `nonReentrant` with effects before interactions; the ETH destination must be on the allowlist (M-of-N + timelock to add). The event after the transfer can't be reordered by re-entry because re-entry reverts. |
| `missing-events-access-control` (×3) | `hasApproved[...] = true/false` in `approve`, `revoke`, `_newProposal` | **False positive** | Each write is followed by an `Approved` or `Revoked` event in the same function. |
| `unsafe-typecast` (×6) | `uint64(block.timestamp)`; `uint128(p.amount)`; `uint128(total < limit ? total : limit)` | **Safe** | A `uint64` holds Unix time until the year ~584 billion. `p.amount <= available`, which is a `uint128`, is checked on the line before the cast; the bucket value is capped at the `uint128` limit. |
| `non-reentrant-not-first` | `execute(...) onlyOwner nonReentrant` | **Accepted** | `onlyOwner` only reads storage and makes no external call, so running it before the guard can't be exploited. |
| `require-revert-in-loop` | constructor owner validation | **Accepted** | Runs once, at deployment, over at most 20 owners; reverting on the first bad owner is the intent. |
| `environment-read-across-mutation` (×3) | `test/CustodyVault.t.sol` | **Test code** | The tests read `block.timestamp` before `skip()` on purpose, to compute deadlines relative to the start. |
