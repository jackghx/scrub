#!/usr/bin/env bash
#
# Install the Scrub pre-commit hook into the current git repository.
#
#   ./hooks/install.sh
#
# Or do it by hand (the one-liner this script automates):
#   cp hooks/pre-commit "$(git rev-parse --show-toplevel)/.git/hooks/pre-commit" \
#     && chmod +x "$(git rev-parse --show-toplevel)/.git/hooks/pre-commit"
#
# The hook needs the `scrub` command on PATH: pip install -e .  (from the repo root).

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
hook_src="$(cd "$(dirname "$0")" && pwd)/pre-commit"
dst="$repo_root/.git/hooks/pre-commit"

if [ -e "$dst" ] && ! cmp -s "$hook_src" "$dst"; then
  echo "A different pre-commit hook already exists at:" >&2
  echo "  $dst" >&2
  echo "Refusing to overwrite. Back it up or merge manually." >&2
  exit 1
fi

cp "$hook_src" "$dst"
chmod +x "$dst"
echo "Installed Scrub pre-commit hook -> $dst"
echo "Remember: it needs 'scrub' on PATH (pip install -e .), and is bypassable with --no-verify."
