#!/usr/bin/env bash

set -euo pipefail

# Keep the legacy entry point working by forwarding to the broader dependency fixer.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "${SCRIPT_DIR}/fix-dependencies.sh" "$@"
