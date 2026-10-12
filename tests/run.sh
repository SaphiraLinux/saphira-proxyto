#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "Building..."
make -B 2>&1 | grep -v "warning:" | grep -v "note:" || true

# Protocol and forwarding behaviour.
echo "Running protocol tests..."
python3 tests/test_proxy.py ./proxyto

# Trust boundary. Kept as a separate suite: it covers the properties the
# PROXY protocol's security model rests on (only a configured peer may assert
# a source identity, and an empty trust list must not mean "trust everybody"),
# and it reports every failure rather than stopping at the first, because a
# half-reported security suite is worse than none.
  echo "Running trust boundary tests..."
  python3 tests/test_trust.py ./proxyto

  # Operational hardening: concurrency cap, accept backoff, config strictness,
  # and the absence of comment-only "checks" in the parser.
  echo "Running operational hardening tests..."
  python3 tests/test_limits.py ./proxyto

  # Shipped service definitions. Static, so it runs before/without a daemon
  # and catches unit-file defects that otherwise only appear on restart.
  echo "Running service definition tests..."
  python3 tests/test_unit.py

