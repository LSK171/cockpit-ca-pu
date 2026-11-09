#!/bin/sh
set -eu
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$PROJECT_DIR/deploy/install.sh" "$@"
