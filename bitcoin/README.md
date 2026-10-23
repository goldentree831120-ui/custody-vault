# Bitcoin: 2-of-3 P2WSH multisig with PSBTs (M6)

The Ethereum vault enforces "M of N owners" in a contract. Bitcoin has no contracts in that sense:
the rule is written into the **output script** itself, and a spend is valid only if it carries
enough signatures. This folder runs that on a private **regtest** chain with Bitcoin Core: three
signers, a watch-only coordinator, and a spend that is passed between them as a **PSBT**
(Partially Signed Bitcoin Transaction, BIP 174/370).

Regtest only: a throwaway chain in a temporary directory, with no connection to any other node,
and coins that exist only on this laptop.

## Run it

```bash
./install-bitcoin-core.sh                         # Bitcoin Core 31.1 into ~/.local/opt, SHA-256 checked (~50 MB, free)
export BITCOIN_BIN=$HOME/.local/opt/bitcoin-31.1/bin
./regtest-multisig.sh                             # needs jq: sudo apt install -y jq
```

## What happens

```
 signer A        signer B        signer C               coordinator (watch-only: public keys only)
 ────────        ────────        ────────               ──────────────────────────────────────────
 tpubA ─────────────────────────────────────────▶
                 tpubB ─────────────────────────▶       wsh(sortedmulti(2, tpubA/0/*, tpubB/0/*, tpubC/0/*))
                                 tpubC ─────────▶       → bcrt1q… (P2WSH), receives 1.0 BTC
                                                        builds the spend: unsigned PSBT
        ◀──────────────── PSBT ─────────────────────────
 sign (1 sig)    sign (1 sig)                           combine → 2 sigs → finalize → broadcast
```

| Step | Checked |
|---|---|
| 1. Descriptor | three different keys; only extended **public** keys leave the signers; every party derives the same address; it's P2WSH (witness v0, 32-byte script hash); the coordinator holds no private keys |
| 2. Fund | 1.0 BTC to the multisig, seen by the watch-only coordinator |
| 3. Build | witness script is `OP_2 <pk> <pk> <pk> OP_3 OP_CHECKMULTISIG`; the PSBT carries all three keys' derivation paths; **before anyone signs**: exactly two outputs, the recipient gets exactly 0.4, the other output is the multisig's own change address, the fee is sane |
| 4. Sign | the coordinator adds 0 signatures; an outsider wallet adds 0; A alone → `finalizepsbt` incomplete; B signs a separate copy in parallel; `combinepsbt` → 2 signatures → complete; the node would accept it |
| 5. Tamper | in the **signed** transaction, move 0.05 BTC from the change to the recipient (0.4 → 0.45; totals unchanged): the node rejects it with `script-verify-flag-failed`, because the signatures commit to the outputs |
| 6. Broadcast | confirmed; recipient has 0.4; the multisig holds 1.0 − 0.4 − fee |
| 7. Any two | A and C (signing one after the other this time) spend from the change |

31 checks, about 5 seconds. The node is stopped and its data deleted at the end.

**A test that passed for the wrong reason.** The first version of the tamper test only raised the
recipient's amount. The node rejected it, but with `bad-txns-in-belowout` (outputs now exceeded
inputs), not because of the signatures. So the test now moves value between the two outputs,
keeping the total unchanged, and requires a signature-verification error specifically.

## Bitcoin multisig vs the Ethereum vault

| | Ethereum `CustodyVault` | Bitcoin 2-of-3 P2WSH |
|---|---|---|
| Where the rule lives | contract code (can be upgraded only by redeploying) | the output script, fixed when the coins are received |
| Approvals | on-chain transactions, one per owner | signatures collected off-chain in the PSBT; one transaction on-chain |
| Timelock, daily limit, allowlist | in the contract | **not available** in plain multisig. Timelocks are possible in script (`OP_CHECKSEQUENCEVERIFY`, e.g. a delayed recovery key); limits and allowlists need the signers' own policy (like the M4 signer) or covenants Bitcoin doesn't have |
| Pause / cancel | any owner, on-chain | no on-chain pause; a signer "cancels" by not signing, or the coins are moved first |
| Changing owners | config proposal + timelock | move the coins to a new multisig address |
| What signers must check | the intent (M4) | the PSBT's outputs and amounts before signing: step 3 above. A signer that signs blindly defeats the multisig |

## Notes and limits

- Keys come from each wallet's BIP 84 account (as in Bitcoin Core's `doc/multisig-tutorial.md`).
  A real setup uses a dedicated multisig path (BIP 48), keys on separate devices or HSMs, and
  a backup of the **descriptor**: losing it makes the coins hard to find even with the keys.
- `sortedmulti` sorts the public keys, so every party gets the same script whatever order the keys
  were collected in.
- The download check in `install-bitcoin-core.sh` is a checksum from the same server; verifying
  the release signatures is described there.
