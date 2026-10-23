# Threat model: CustodyVault

> **Status: outline for you to write.** Everything in *italics* is a prompt, not content.
> Replace the prompts with your own sentences, delete what doesn't apply, and keep it to
> 1–2 pages. When you're done, send it to me for review. I'll check it against the list at the bottom.
>
> Rule of thumb: every attack path should end in either a control (with the line of code
> or test that enforces it) or an explicit "accepted risk" with a reason. A threat model
> that only lists attacks is half done.

## 1. System and scope

*One paragraph: what the vault holds, who uses it, what is in scope (the Solidity vault,
M2) and what is out of scope for now (the Java signing orchestrator M4, key storage /
HSM, the Bitcoin path M6, the front end). Say what you assume about the chain itself
(e.g. Ethereum consensus is honest; block timestamps can drift by a few seconds).*

## 2. Assets

*What is worth protecting, ranked. Think beyond "the tokens".*

| Asset | Why it matters | Worst realistic loss |
|---|---|---|
| *ETH / ERC-20 balances* | | |
| *The owner set and threshold* | *Whoever controls this controls everything later* | |
| *The destination allowlist* | | |
| *Asset policies (limits, large thresholds)* | | |
| *Availability: ability to withdraw when needed* | *A vault nobody can withdraw from is also a failure* | |

## 3. Actors and trust

*For each actor: what can it do, and what do you assume about it?*

| Actor | Capabilities in the contract | Trusted for | Not trusted for |
|---|---|---|---|
| *Owner (one key)* | *propose, approve, revoke, cancel, execute, pause* | | |
| *M owners colluding / M keys stolen* | | | |
| *Fewer than M owners colluding* | | | |
| *Outsider (any address)* | | | |
| *Allowlisted destination (e.g. an exchange deposit address)* | *receives funds; if it is a contract, runs code on receipt* | | |
| *Token contract (ERC-20)* | *the vault calls it* | | |
| *Block producer / MEV searcher* | *orders and delays transactions, sets timestamp within bounds* | | |

*Trust boundaries: draw (or describe) where control crosses from one actor to another:
owner key → vault, vault → token contract, vault → destination.*

## 4. Attack paths

*For each: how it would work step by step, which control stops it, and what remains.*
*Required by the brief: key theft, insider approval, replay, malicious destination.*
*Worth adding: config takeover, griefing / denial of service, reentrancy, token quirks,
stale approvals.*

### 4.1 Key theft (one key)
*Attacker has one owner key. What can they do alone? (Hint: they can pause, cancel and
propose, but not execute.) Is "pause and cancel everything forever" a problem?*

### 4.2 Insider approval / M keys compromised
*Attacker controls M keys. Walk through the fastest way to drain the vault, step by step,
with timings. Which controls slow them down (rate limit, timelock, allowlist), and which
single control lets one honest owner stop them? What is the maximum they can take before
anyone can react?*

### 4.3 Replay
*Could an approval or an execution be used twice, on another proposal, or on another
chain or vault deployment? Note that approvals here are on-chain transactions, not
signatures. Would that change if you moved to off-chain EIP-712 signatures (M4)?*

### 4.4 Malicious or wrong destination
*An attacker gets their address onto the allowlist, or an allowlisted address is later
compromised. What does it cost them and how long does it take? What about a typo'd address?*

### 4.5 Configuration takeover
*Using config proposals to: add an attacker owner, lower the threshold, raise limits,
add a destination. What delays each one? What can an honest owner do in that window?*

### 4.6 Griefing and denial of service
*One malicious owner pausing repeatedly or cancelling every proposal. Is that acceptable?
What is the recovery path (hint: removeOwner through a config proposal, which they can
also cancel...)? This is a real design trade-off; say which side you chose and why.*

### 4.7 Reentrancy and external calls
*Where does the vault call out (ETH transfer, ERC-20 transfer)? What stops a contract
destination re-entering? Which test shows it?*

### 4.8 Token behaviour
*Fee-on-transfer, rebasing, tokens that return false, tokens with blocklists, tokens with
hooks (ERC-777). Which are handled, which are out of scope?*

### 4.9 Time and stale state
*Old proposals executed months later; approvals from an owner who has since been removed;
timestamp manipulation around the timelock boundary.*

## 5. Controls summary

*Table mapping each control to the threats it addresses and the test that proves it.
The tests already exist in `test/`; reference them by name.*

| Control | Addresses | Enforced in | Proven by |
|---|---|---|---|
| *M-of-N approvals* | | *`execute`, `approvalCount`* | *`invariant_noExecutionWithoutMApprovals`, `testFuzz_executionIffThresholdMet`* |
| *Timelock (large withdrawals, all config)* | | | |
| *Single-owner veto (`cancel`)* | | | |
| *Destination allowlist (checked at propose and execute)* | | | |
| *Token-bucket rate limit* | | | |
| *Emergency pause / M-of-N unpause* | | | |
| *Owner-set versioning (stale proposals die)* | | | |
| *Approval and execution windows* | | | |
| *ReentrancyGuard + checks-effects-interactions* | | | |

## 6. Residual risks and assumptions

*What you are knowingly NOT defending against, and why that is acceptable for this
project. Be specific: "M keys stolen AND the honest owners offline for longer than the
timelock" is a residual risk; "hacks" is not.*

---

### What I will check when reviewing

- Every attack path ends in a control or an explicit accepted risk.
- Each control points at code and at a test that would fail without it.
- The M-compromised scenario has concrete numbers (max loss per day, time to react).
- Griefing by a single owner is discussed honestly as a trade-off, not hidden.
- Out-of-scope items (key storage, orchestrator, Bitcoin) are named so nobody assumes they're covered.
- No claim the tests can't support (e.g. "formally verified").
