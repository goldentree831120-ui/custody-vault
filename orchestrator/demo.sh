#!/usr/bin/env bash
# Runs the end-to-end demo: a fresh local Anvil chain, the real CustodyVault, the orchestrator's
# HTTP API and the mock signer. Local only; no keys, accounts or network access beyond Maven.
set -euo pipefail
cd "$(dirname "$0")"
command -v anvil >/dev/null || { echo "anvil not found (install Foundry)"; exit 1; }
command -v mvn >/dev/null || { echo "mvn not found: sudo apt install -y openjdk-21-jdk-headless maven"; exit 1; }
PORT=${PORT:-8545}
if (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null; then
  echo "port $PORT is already in use (another anvil?). Stop it or run PORT=8546 ./demo.sh"; exit 1
fi
(cd .. && forge build >/dev/null)
anvil --port "$PORT" --silent &
ANVIL=$!
trap 'kill $ANVIL 2>/dev/null' EXIT
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.1; done
RPC_URL=http://127.0.0.1:$PORT mvn -q -B compile exec:java -Dexec.args=demo
