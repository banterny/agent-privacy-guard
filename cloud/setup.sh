#!/bin/bash
# agent-privacy-guard: setup script for Claude Code cloud sessions.
#
# Cloud sessions run on Anthropic's machines from a fresh clone of your
# repository. They do not read your ~/.claude/settings.json or your global
# CLAUDE.md, so attribution settings made on your own computer do not reach
# them, and by default they add a "Claude-Session: https://claude.ai/code/..."
# line to commits and a session link to pull requests.
#
# Paste this into your cloud environment: claude.ai/code > your environment >
# Setup script. It runs before each new session starts (or once, if the
# environment is cached) and sets three layers:
#   1. ~/.claude/CLAUDE.md: tells Claude to add no attribution or session
#      links. Claude Code's docs say your own attribution instructions take
#      precedence over its commit and pull request lines.
#   2. ~/.claude/settings.json: the attribution settings themselves, in case
#      the session reads a user settings file in the cloud machine.
#   3. A global git commit-msg hook that deletes any session link or AI
#      credit line from a commit message as the commit is made. This is the
#      guarantee for commits; pull request text relies on layers 1 and 2.
# It never exits non-zero, so it cannot stop a session starting.

mkdir -p ~/.claude ~/.config/git/hooks || true

cat >~/.claude/CLAUDE.md <<'EOF'
# Attribution
- Never add a session link (no `Claude-Session:` trailer, no claude.ai/code URL) to a commit message, pull request, issue or comment.
- Never add a credit line for any AI tool: no `Co-Authored-By` trailer for Claude or any other AI, no "Generated with" line.
EOF

if [ ! -s ~/.claude/settings.json ]; then
  cat >~/.claude/settings.json <<'EOF'
{
  "attribution": { "commit": "", "pr": "", "sessionUrl": false }
}
EOF
fi

cat >~/.config/git/hooks/commit-msg <<'EOF'
#!/bin/sh
MSG="$1"
[ -n "$MSG" ] && [ -f "$MSG" ] || exit 0
TMP="$MSG.privacy-guard.$$"
grep -v -i -E \
  -e '^[[:space:]]*Claude-Session:' \
  -e 'claude\.ai/code/session_' \
  -e '^[[:space:]]*Co-Authored-By:.*(claude|anthropic|codex|openai|opencode)' \
  -e '^[[:space:]]*(🤖[[:space:]]*)?Generated (with|by) \[?(Claude|Codex|OpenCode)' \
  "$MSG" >"$TMP"
[ "$?" -le 1 ] && cat "$TMP" >"$MSG"
rm -f "$TMP"
exit 0
EOF
chmod +x ~/.config/git/hooks/commit-msg || true
git config --global core.hooksPath ~/.config/git/hooks || true

exit 0
