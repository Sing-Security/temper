#!/usr/bin/env bash
#
# Refresh this tree from the temper crate inside a CrucibleOS checkout, where
# the crate is developed. Everything copies verbatim except one line: the
# package name. This repository publishes the crate as `temper-protocol`
# because crates.io's `temper` belongs to someone else; CrucibleOS develops
# it as `temper`, and every consumer there uses path dependencies, so the
# public name exists only here. The rename is applied by this script rather
# than left to memory — a refresh that forgets it does not fail silently:
# `cargo publish` refuses to overwrite someone else's crate.
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
	--exclude scripts/ \
	"$CRATE/" .

# Two edits, one intent: the package publishes as `temper-protocol`, while the
# library target keeps the name `temper`. The second line is load-bearing —
# without it the lib target defaults to the package name and every
# `use temper::` in the examples, benches, and any consumer breaks.
sed -i -e 's/^name = "temper"$/name = "temper-protocol"/' \
	-e 's/^\[lib\]$/[lib]\nname = "temper"/' Cargo.toml

if [ "$(sed -n 's/^name = "\(.*\)"$/\1/p' Cargo.toml | head -1)" != "temper-protocol" ]; then
	echo "rename failed — Cargo.toml does not carry the publish name" >&2
	exit 2
fi

echo "refreshed from $CRATE"
git status --short
