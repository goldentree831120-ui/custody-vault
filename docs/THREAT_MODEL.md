# Threat model: CustodyVault

Scope: `src/CustodyVault.sol` (M2). Evidence: the tests in `test/` (35 unit/fuzz tests,
7 invariants) and `script/mutation-check.sh`. Line numbers refer to `src/CustodyVault.sol`.

> **Decisions marked ⚖️ are judgement calls, not facts.** They're the parts an interviewer
> will push on, so each one says what was chosen and why.

## 1. System and scope

The vault holds ETH and ERC-20 tokens on behalf of a small group of owners (1–20). Nothing
moves without **M of N owners** approving on-chain. Large withdrawals and every configuration
change also wait out a **timelock** fixed at deployment (1 hour–30 days), and every
withdrawal is limited by a **destination allowlist** and a **per-asset daily rate limit**.
Any single owner can **pause** withdrawals or **cancel** any pending proposal. There's no
admin key, no upgrade path and no `delegatecall`. The only way to change settings is an
approved, timelocked proposal that calls one of six whitelisted functions.

**In scope:** the Solidity contract and its rules. **Out of scope:** how owners store keys
(HSM/MPC, M4 uses mocked test keys), the Java signing orchestrator (M4), the Bitcoin
2-of-3 path (M6), any front end, and the organisation's process for deciding *what* to
withdraw.

**Assumptions:** Ethereum consensus is honest and transactions are eventually included;
block timestamps can drift by seconds, never hours; standard ERC-20 tokens behave as
specified; owners notice on-chain events (`Proposed`, `ThresholdReached`) within a known
reaction time (§6).

## 2. Assets

| Asset | Why it matters | Worst realistic loss |
|---|---|---|
| ETH / ERC-20 balances | The point of the vault | Everything, if the controls below fail |
| Owner set and threshold | Whoever controls these controls every future decision | Permanent loss of control |
| Destination allowlist | The only addresses funds can ever go to | Funds sent to an attacker's address |
| Asset policies (daily limit, large threshold) | They bound how much can leave and how fast | Higher limits let a compromise drain faster |
| Availability | A vault that can't pay out when needed is also a failure | Funds stuck while paused or deadlocked (§4.6) |

## 3. Actors and trust

| Actor | Can do in the contract | Trusted for | Not trusted for |
|---|---|---|---|
| One owner (one key) | propose, approve, revoke, **cancel any proposal**, **pause** | raising the alarm: veto and pause | moving funds or changing settings alone |
| M owners together | everything an owner can do, plus execute | normal operations | bypassing the timelock, allowlist or rate limit |
| Fewer than M owners | as one owner | as one owner | as one owner |
| Outsider (any address) | deposit; read state | nothing | everything else reverts with `NotOwner` (`test_outsiderCannotDoAnything`) |
| Allowlisted destination | receives funds; if it's a contract, runs code on receipt | being the intended recipient | not re-entering the vault (§4.7) |
| ERC-20 token contract | the vault calls `transfer` / `balanceOf` on it | following the ERC-20 standard | see §4.8 for non-standard tokens |
| Block producer / MEV searcher | orders, delays or censors transactions; nudges timestamps by seconds | eventual inclusion | timely inclusion |

**Trust boundaries:** owner key → vault (every action is signed by an owner); vault → token
contract (an external call); vault → destination (an external call, possibly to a contract).

## 4. Attack paths

### 4.1 One key stolen
The attacker can propose withdrawals (only to allowlisted addresses, only up to the daily
limit), add their one approval, cancel any proposal, and pause.
**They can't** execute anything unless M = 1: `execute` requires `approvalCount ≥ threshold`,
counting only *current* owners (lines 245–246).
**Control:** M-of-N (`invariant_noExecutionWithoutMApprovals`, `testFuzz_executionIffThresholdMet`,
`test_smallWithdrawal_needsMApprovals_thenExecutesImmediately`).
**Residual:** the attacker can pause and cancel, which is a denial of service, covered in §4.6.
⚖️ **Deploy with M ≥ 2.** The constructor accepts M = 1, which would make one key a full compromise.

### 4.2 M keys stolen (or M insiders collude)
The fastest drain, using the test policy as an example (2-of-3, 2-day timelock, USD limit
1,000,000/day, large threshold 250,000):
1. The attacker proposes withdrawals **just below 250,000** to an *already allowlisted*
   address and approves them. Below the large threshold there's **no timelock**, so they
   execute at once (`test_justBelowLarge_isNotTimelocked`).
2. They repeat until the rate-limit bucket is empty: **at most 1,000,000 immediately**
   (`invariant_noBurstBeyondBucket`). After that the bucket refills at 1,000,000/24 h ≈
   **41,700 per hour** (`test_bucketDrainsThenRefillsLinearly`, `invariant_withdrawalsNeverExceedRateLimit`).
3. Anything **≥ 250,000** in one withdrawal waits 2 days (`invariant_largeWithdrawalsRespectTimelock`),
   and one honest owner can `cancel` it in that window (`test_singleOwnerCanVetoDuringTimelock`).
4. Sending to a **new** address needs a config proposal (`setDestination`), which is always
   timelocked and cancellable by one owner (`test_configChangesAreAlwaysTimelocked`).
   So funds can only ever reach addresses that were allowlisted **before** the attack
   (`invariant_onlyAllowlistedDestinationsReceiveFunds`).

**How an honest owner stops it:** `pause()` is instant and blocks every execution
(`invariant_nothingExecutesWhilePaused`). Unpausing needs M approvals **and** the timelock
(`test_unpauseNeedsMofNAndTimelock`), and the honest owner can cancel that too.

**Maximum loss before anyone reacts:** one full bucket per asset (here 1,000,000 USD and
100 ETH), plus the refill rate × the reaction time, and only to pre-approved destinations. If
every allowlisted address is controlled by the organisation (its own exchange or cold-wallet
accounts), the attacker moves the funds but can't take them.

⚖️ **Policy choice:** keep the large threshold well below the daily limit and allowlist only
organisation-controlled addresses. Those two settings decide the real worst case.

### 4.3 Replay
Approvals are **on-chain state**, not signatures: `hasApproved[id][owner]` belongs to one
proposal in one vault, so it can't be reused on another proposal, chain or deployment.
Approving twice reverts, and an executed proposal is closed before any funds move
(`test_cannotApproveTwice_orExecuteTwice`). When the owner set or threshold changes, every open
proposal becomes stale, so approvals from removed owners can't be carried forward
(`test_ownerChange_invalidatesOpenProposals`).
**If M4 adds off-chain EIP-712 signatures,** the signed message must include the chain id, the
vault address, the proposal id and a deadline; otherwise replay becomes a real risk.

### 4.4 Malicious or wrong destination
Adding an address to the allowlist is a config change: M approvals plus the timelock, and any
single owner can cancel it. The allowlist is checked when proposing **and again at execution**,
so removing a destination stops pending withdrawals to it
(`test_destinationRemovedAfterProposal_blocksExecution`). The zero address and the vault itself
can never be allowlisted (`test_vaultCannotAllowlistItselfOrZero`).
**Typo'd address:** it would have to survive M approvals and the timelock, so the timelock
doubles as a review window.
**Residual:** if an *allowlisted* address is later compromised (say an exchange account is
hacked), withdrawals to it are lost. Mitigation: pause at once (instant), then remove it
(timelocked). **Accepted risk:** the vault can't know an external account was compromised.

### 4.5 Configuration takeover
Adding an attacker as owner, lowering the threshold, raising limits or adding a destination
all go through `proposeConfig`. It only accepts the six whitelisted functions
(`test_proposeConfig_rejectsArbitraryCalldata`), those functions can't be called directly
(`test_configFunctionsCannotBeCalledDirectly_evenByOwners`), and every config change is
timelocked and cancellable by one owner.
Changes that make things stricter still apply to pending withdrawals: lowering the daily limit
shrinks the bucket immediately (`test_loweringLimit_clampsBucketImmediately`), and lowering the
large threshold timelocks pending withdrawals (`test_loweringLargeThreshold_makesPendingWithdrawalTimelocked`).
Changes that loosen things don't apply to pending withdrawals: raising the large threshold
doesn't release a pending large withdrawal (`test_raisingLargeThreshold_doesNotUnlockPendingLargeWithdrawal`).
The owner count can't drop below the threshold (`test_cannotRemoveOwnerBelowThreshold`).

### 4.6 Griefing and denial of service
One malicious owner can **pause** the vault and **cancel** every proposal, including the
proposal to unpause **and** the proposal to remove them. That's a liveness deadlock: funds are
safe, but they can't move.
⚖️ **Trade-off chosen: safety over liveness.** Giving every owner an instant veto is what lets
one honest owner stop M stolen keys (§4.2). The price is that one dishonest owner can freeze
the vault. For a custody vault, frozen beats drained. **Accepted risk**, with off-chain recovery
(legal or organisational).
Alternatives if liveness mattered more: require K > 1 owners to cancel; don't let an owner
cancel a proposal that removes *them*; or let a pause expire unless re-confirmed by M owners.

### 4.7 Reentrancy and external calls
The vault calls out in two places: the ETH transfer to the destination, and the ERC-20 transfer.
`execute` is `nonReentrant`, and it marks the proposal executed and updates the rate-limit
bucket **before** the external call (checks-effects-interactions: line 253, and lines 438–440 before the transfer on line 444).
A malicious contract destination that re-enters is blocked
(`test_reentrancyThroughEthReceiver_isBlocked`). The vault holds no other balances that could
fall out of sync (`invariant_conservation`).

### 4.8 Token behaviour
Tokens that return `false` instead of reverting are handled by OpenZeppelin `SafeERC20`. A
balance check runs before every transfer (`test_insufficientVaultBalance`). ERC-777-style hooks
are covered by the reentrancy guard. **Out of scope:** fee-on-transfer and rebasing tokens (the
vault's accounting assumes the amount sent is the amount received), and tokens with blocklists
(USDC/USDT can freeze the vault's address, which is an availability risk set by the token's
issuer). An asset can only be withdrawn once a policy is set for it
(`test_unconfiguredAssetCannotBeWithdrawn`), so owners choose which tokens are supported.

### 4.9 Time and stale state
A proposal must reach M approvals within **14 days** and be executed within **7 days** of
becoming executable, or it expires (`test_unapprovedProposalExpires`,
`test_approvedProposalMustExecuteWithinWindow`), so old approvals can't be used months later.
If an approval is revoked and the count drops below M, the timelock clock restarts
(`test_revokeAndReapprove_restartsTimelock`). Timestamp drift of seconds is negligible next to
a timelock of at least one hour. A block producer can *delay* an honest owner's `pause` or
`cancel`, but only for a short time on a live chain. That's part of the reaction time in §6.

## 5. Controls summary

| Control | Addresses | Enforced in | Proven by |
|---|---|---|---|
| M-of-N approvals | 4.1, 4.2 | `execute`, `approvalCount` | `invariant_noExecutionWithoutMApprovals`, `testFuzz_executionIffThresholdMet` |
| Timelock (large withdrawals, all config) | 4.2, 4.4, 4.5 | `executableAt`, `_needsTimelock` | `invariant_largeWithdrawalsRespectTimelock`, `test_configChangesAreAlwaysTimelocked` |
| Single-owner veto (`cancel`) | 4.2, 4.4, 4.5 | `cancel` | `test_singleOwnerCanVetoDuringTimelock` |
| Destination allowlist (checked at propose and execute) | 4.2, 4.4 | `proposeWithdrawal`, `_executeWithdrawal` | `invariant_onlyAllowlistedDestinationsReceiveFunds`, `test_destinationRemovedAfterProposal_blocksExecution` |
| Token-bucket rate limit | 4.2 | `_refilled`, `_executeWithdrawal` | `invariant_withdrawalsNeverExceedRateLimit`, `invariant_noBurstBeyondBucket`, `testFuzz_rateLimitHolds` |
| Emergency pause / M-of-N unpause | 4.2, 4.4 | `pause`, `unpause` (config only) | `invariant_nothingExecutesWhilePaused`, `test_unpauseNeedsMofNAndTimelock` |
| Owner-set versioning (stale proposals die) | 4.3, 4.9 | `_open`, `_bumpOwnerSet` | `test_ownerChange_invalidatesOpenProposals` |
| Approval and execution windows | 4.9 | `_open` | `test_unapprovedProposalExpires`, `test_approvedProposalMustExecuteWithinWindow` |
| ReentrancyGuard + checks-effects-interactions | 4.7 | `execute` | `test_reentrancyThroughEthReceiver_isBlocked`, `invariant_conservation` |

`script/mutation-check.sh` removes six of these controls one at a time; the tests fail every time.

## 6. Residual risks and assumptions

- **M keys stolen and no honest owner reacts in time:** loss up to one daily bucket per asset,
  plus refill, to pre-approved destinations only (§4.2). The real numbers depend on the
  deployed policy and on how quickly owners are alerted. The vault doesn't alert anyone;
  monitoring of `Proposed` / `ThresholdReached` events is needed and is out of scope.
- **All N keys stolen:** after the timelock, the attacker can reconfigure anything. Nothing
  on-chain prevents this; it's a key-management problem (out of scope).
- **One dishonest owner freezes the vault** (§4.6): accepted by design, with off-chain recovery.
- **An allowlisted external account is compromised** (§4.4): accepted; pause limits the damage.
- **Non-standard tokens** (fee-on-transfer, rebasing, blocklists): not supported (§4.8).
- **Not formally verified, not audited.** The guarantees are what the tests and invariants
  check (thousands of random action sequences per run), no more.
