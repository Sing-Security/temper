#!/usr/bin/env bash
#
# Refresh this tree from the temper crate inside a CrucibleOS checkout, where
# the crate is developed. The copy is verbatim: both trees carry the same
# package name (`temper-rs` — crates.io's `temper` belongs to an unrelated
# project) and the same library name (`temper`), so nothing is transformed
# here and nothing can drift apart by a rename forgotten on one side.
#
#   scripts/refresh-from-crucibleos.sh [PATH_TO_CRUCIBLEOS]
#
# Defaults to $CRUCIBLEOS, then to a sibling ../CrucibleOS.

set -euo pipefail

usage() {
	echo "usage: refresh-from-crucibleos.sh [PATH_TO_CRUCIBLEOS]" >&2
	exit 2
}

case $# in
0) FROM="${CRUCIBLEOS:-}" ;;
1) FROM=$1 ;;
*) usage ;;
esac

[ -n "$FROM" ] || FROM=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../CrucibleOS" && pwd)
CRATE="$FROM/crucible/runtime/temper"
if [ ! -f "$CRATE/Cargo.toml" ]; then
	echo "no temper crate under '$FROM' (looked for crucible/runtime/temper)" >&2
	exit 2
fi

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

# scripts/ is this repository's own and is protected by --exclude; everything
# else — including .github and the rustfmt config — mirrors the source of
# truth exactly, so drift cannot accumulate file by file.
rsync -a --delete \
	--exclude .git/ \
	--exclude target/ \
	--exclude Cargo.lock \
	--exclude scripts/ \
	"$CRATE/" .

# The in-tree directory has no lock of its own; regenerate one for this
# standalone build so `--locked` invocations and the committed lock stay
# meaningful.
cargo metadata --format-version 1 > /dev/null

echo "refreshed from $CRATE"
git status --short
