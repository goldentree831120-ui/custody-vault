# Signing orchestrator (M4)

A Java 21 service between the people who approve withdrawals and the CustodyVault contract.
Approvers sign **intents** (EIP-712 typed data) on their own devices. The orchestrator checks
each intent against the vault's on-chain state and policy, then asks the **signer** to sign the
matching vault transaction with that approver's owner key.

> **Test keys only.** The signer here is `MockHsmSigner`, a stand-in for an HSM or MPC signing
> service. It holds Anvil's public development keys in memory and refuses to run on any chain
> other than the local Anvil chain (31337). It shows the interface and the policy a real signer
> should have. It is not secure key storage.

```
 approver device (A, B, C)             orchestrator (this service)                 signer (MockHsmSigner)          chain
 ─────────────────────────             ─────────────────────────────               ──────────────────────          ─────
 sign EIP-712 intent  ──POST /v1/intents──▶ 1 recover signer → approver → key slot
   WithdrawalRequest                       2 deadline (≤ 1 h ahead), nonce unused
   WithdrawalApproval                      3 owner key still a vault owner
   Cancellation                            4 vault state + policy (allowlist, daily
                                             limit, pause, proposal matches intent,
                                             not already approved, own stricter cap)
                                           5 simulate the exact call (eth_call)
                                           6 use up the nonce (durably)
                                           7 build tx ─── tx + intent ──────────────▶  re-checks on its own:
                                                                                       intent signed by the approver
                                                                                       bound to this key, unexpired,
                                                                                       nonce unused, calldata == the
                                                                                       call the intent describes,
                                                                                       to == vault, value 0, chain 31337
                                                       ◀── signed tx ───────────────   sign
                                           8 send, wait for receipt ───────────────────────────────────────────▶  vault enforces
                                                                                                                   every rule again
```

## Run it

Needs Java 21, Maven and Foundry (Anvil). In WSL: `sudo apt install -y openjdk-21-jdk-headless maven`.

```bash
cd orchestrator
./demo.sh                          # fresh Anvil + the real vault + the HTTP API: 20 checks
mvn test                           # 52 unit tests + the end-to-end test on Anvil (needs `forge build` in the repo root)
./scripts/mutation-check.sh        # plants 13 bugs in the security checks; every one must make a test fail
```

`./demo.sh` deploys a 2-of-3 vault (timelock 1 h for withdrawals from 5 ETH, 10 ETH/day) and runs:
a small withdrawal (request, approve, execute at once); a large one (refused before the timelock,
executed after); eight requests the orchestrator refuses (mismatched approval, replay, destination
not allowlisted, over the daily limit, unknown approver, a signature for another vault, expired, a
deadline a week away); three the signer refuses even when called directly, bypassing the
orchestrator; and a one-owner veto.

## Trust model

| Component | Trusted for | If compromised |
|---|---|---|
| Approver device key | its owner's approvals | can approve as that owner only; M-of-N and the timelock still apply |
| Orchestrator | liveness, early clear errors | can delay, drop or reorder requests. **Can't** get a transaction signed without a valid approver intent, because the signer re-checks it |
| Signer (HSM / MPC) | key custody, its own policy | holds keys: this is why each owner's key should be in a **separate** signer run by different people, not one process as in this demo |
| Vault contract | final enforcement | the threat model's subject (`docs/THREAT_MODEL.md`) |

The most important decision: **the signer does not trust the orchestrator.** A signing service
that signs whatever the application server sends turns an application-server breach into a key
breach. Here the signer only signs the exact calldata an approver authorised.

## Intents

Domain: `{name: "CustodyVault Orchestrator", version: "1", chainId, verifyingContract: <vault>}`.
A signature for another vault or chain recovers to a different address and is refused as an
unknown approver.

| Type | Fields | Becomes |
|---|---|---|
| `WithdrawalRequest` | asset, to, amount, nonce, deadline | `proposeWithdrawal(asset, to, amount)` (counts as the proposer's approval) |
| `WithdrawalApproval` | proposalId, asset, to, amount, nonce, deadline | `approve(proposalId)`, only if the on-chain proposal has exactly this asset, destination and amount |
| `Cancellation` | proposalId, nonce, deadline | `cancel(proposalId)`: one owner is enough |

The approval carries the content, not only the proposal id, so an approver can't be tricked into
approving "proposal 7" when 7 is a different withdrawal. Nonces are per approver and single use;
deadlines more than 1 hour ahead are refused, so a signed intent can't be kept and used later.
Numbers are decimal strings in JSON (no float rounding); unknown fields are refused.

`execute(id)` needs no intent. It only carries out what M owners approved, after the timelock,
and the contract re-checks everything.

## API

Bound to 127.0.0.1. Errors are `{"error": {"code", "message"}}`; 500s never include internal details.

| Route | |
|---|---|
| `GET /health` | chain, vault, and that the signer is the mock |
| `GET /v1/domain` | the EIP-712 domain and types, for wallets and clients |
| `POST /v1/intents` | `{"type", "message", "signature"}` → the transaction hash, approvals, executable time |
| `GET /v1/proposals/{id}` | state, approvals, threshold, executable time |
| `POST /v1/proposals/{id}/execute` | executes when ready, otherwise `NOT_READY` |

Rejection codes: `BAD_SIGNATURE`, `UNKNOWN_APPROVER`, `EXPIRED`, `DEADLINE_TOO_FAR`, `NONCE_REUSED`,
`NOT_AN_OWNER`, `UNKNOWN_PROPOSAL`, `PROPOSAL_MISMATCH`, `PROPOSAL_CLOSED`, `ALREADY_APPROVED`,
`NOT_READY`, `PAUSED`, `ZERO_AMOUNT`, `DESTINATION_NOT_ALLOWED`, `OVER_DAILY_LIMIT`,
`OVER_ORCHESTRATOR_CAP`, `ON_CHAIN_REVERT` (with the vault's custom error name), `SIGNER_REFUSED`, `TX_FAILED`.

## Tests

| Suite | What | Count |
|---|---|---|
| `CryptoVectorsTest` | Keccak, addresses, EIP-712 signature and a signed EIP-1559 transaction **byte-for-byte equal to Foundry's `cast`** (an independent implementation); low-s, malleability and malformed signatures | 9 |
| `EncodingTest` | RLP vectors, ABI encoding (checked against `cast abi-encode`), strict JSON | 5 |
| `IntentsAndNoncesTest` | intent JSON strictness; the nonce file survives a restart | 3 |
| `MockHsmSignerTest` | every signer refusal: other chains, other contracts, ETH value, calldata ≠ intent, wrong approver, expired, replay, no-intent calls other than execute; key material never printed | 10 |
| `OrchestratorTest` | every rejection code, and that **nothing is sent** when a request is rejected; rejected intents keep their nonce, failed transactions use it up | 21 |
| `HttpApiTest` | routing, content type, body size limit, error shape, no internal details in 500s | 4 |
| `AnvilEndToEndTest` | the demo above on a real Anvil chain with the real vault | 1 |

`scripts/mutation-check.sh` removes 13 security checks one at a time (in the orchestrator, the
signer and signature parsing) and requires a failing test for each. CI runs all of it, and the
end-to-end test can't be skipped there (`-DrequireAnvil=true`).

## Design notes

- **One dependency.** Bouncy Castle provides Keccak-256 and secp256k1 ECDSA. The Ethereum
  layer on top (EIP-712, RLP, EIP-1559 transactions, public-key recovery, the ABI subset,
  JSON-RPC, JSON) is small and written here, so every byte that gets signed is visible in this
  repository. Because hand-written encoding is where bugs hide, it's pinned to vectors from
  Foundry's `cast`.
- Deterministic nonces (RFC 6979) and low-s signatures (EIP-2); high-s signatures are refused.
- Requests are processed one at a time, which keeps owner-account transaction nonces in order.
- The intent nonce is recorded (and flushed to disk) **before** signing. If anything later fails,
  the approver signs a new intent: failing closed is better than any chance of a double use.

## Not covered (a real deployment would need these)

- Real key custody: an HSM (PKCS#11, cloud KMS) or MPC, with one independent signer per owner,
  keys generated inside it, a trusted clock and persistent replay state. The mock keeps its nonce
  set in memory, so after a restart only the orchestrator's nonce file blocks replays.
- Authenticated, TLS-protected access to the API, and approver devices that show the decoded
  intent (hardware wallets, passkeys) instead of test keys in a script.
- Stuck or replaced transactions (fee bumping), reorgs, and more than one orchestrator instance.
- State can change between the simulation and the transaction being mined. The vault re-checks
  everything, so the cost is a failed transaction, not a bypass.
- A tamper-evident record of every decision: that is M5 (hash-chained audit log).
