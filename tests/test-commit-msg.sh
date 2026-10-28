#!/bin/bash
# Tests for git-hooks/commit-msg in a throwaway repository.
# Run: bash tests/test-commit-msg.sh

HOOKS="$(cd "$(dirname "$0")/.." && pwd)/git-hooks"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git -C "$T" init -q
git -C "$T" config user.name test
git -C "$T" config user.email test@example.com
git -C "$T" config core.hooksPath "$HOOKS"

pass=0; fail=0
n=0
# commit <message> -> sets OUT to the stored message
commit() {
  n=$((n+1)); echo "$n" >"$T/f"; git -C "$T" add f
  git -C "$T" commit -q -F - <<<"$1" >/dev/null 2>&1
  OUT=$(git -C "$T" log -1 --format=%B)
}
has() { [[ "$OUT" == *"$1"* ]]; }
lacks() { ! has "$1"; }
ok() { if "$@"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $DESC"; printf '%s\n---\n' "$OUT"; fi; }

commit $'Fix the parser\n\nExplain why.\n\nClaude-Session: https://claude.ai/code/session_01AbCdEf'
DESC="session trailer removed"; ok lacks "claude.ai/code"
DESC="rest of message kept"; ok has "Explain why."

commit $'Add tests\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
DESC="Claude credit line removed"; ok lacks "Co-Authored-By"

commit $'Docs\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)'
DESC="Generated-with line removed"; ok lacks "Generated with"

commit $'Merge work\n\nCo-Authored-By: Jane Doe <jane@example.com>'
DESC="human co-author kept"; ok has "Co-Authored-By: Jane Doe"

commit $'See https://claude.ai/code/session_XYZ for the chat\nReal body line'
DESC="inline session link line removed"; ok lacks "session_XYZ"
DESC="other body line kept"; ok has "Real body line"

commit $'Mention claude.ai in prose is fine'
DESC="prose mentioning claude.ai kept"; ok has "claude.ai in prose"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
