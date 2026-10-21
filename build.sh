#!/usr/bin/env bash

set -euo pipefail

# Resolve paths relative to the repository root so the script works from any cwd.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<EOF
Usage: $(basename "$0") [make arguments]

Fix local dependencies under bin/libs and build noxim from bin/.
Any extra arguments are passed to make.
EOF
}

if [[ $# -gt 0 ]]; then
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
    esac
fi

# Keep the manual post-clone flow to one command: fix local deps, then build.
"${SCRIPT_DIR}/other/setup/fix-dependencies.sh"
make -C "${SCRIPT_DIR}/bin" "$@"
