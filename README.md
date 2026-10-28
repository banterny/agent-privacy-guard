# agent-privacy-guard

Keeps your email address and other personal identifiers from leaking out of
AI coding agents (Claude Code, Codex, OpenCode) into web requests.

Sibling of [claude-code-secret-guard](https://github.com/banterny/claude-code-secret-guard),
which stops secrets reaching git history. This one stops personal data
reaching third-party servers.

## The problem

1. **Claude Code puts your login email in every conversation.** When you sign
   in with claude.ai it adds a `userEmail` context block ("The user's email
   address is …"). No setting turns it off.
2. **Your own instruction files may add more.** A global `CLAUDE.md` or
   `AGENTS.md` that mentions your addresses or name puts them in every
   session of every agent that loads it.
3. **Web content can ask agents to identify their user** (prompt injection),
   and some real APIs (Crossref, NCBI, Unpaywall, SEC) ask for a contact email.
   An agent with your address in context may comply in a header, a query
   string or a form.

## What this does

| Layer | Where | What |
| --- | --- | --- |
| Context | Claude Code mod `privacy-guard` | Drops the `userEmail` block, and blanks any listed identifier in loaded instruction files (`CLAUDE.md`, memory). Has a fail-closed handler for the email block (not exercised by the tests). |
| Outbound | `hooks/deny-personal-data.sh` (Claude Code, Codex) and `opencode/privacy-guard.js` (OpenCode) | Refuses a tool call that would send a listed identifier off the machine: `WebFetch`, `WebSearch`, MCP tools, and shell commands that can reach the network (`curl`, `wget`, `gh`, `ssh`, AI CLIs, scripts using HTTP libraries, any URL). Also refuses a network command that reads `~/.claude.json`. |

Your identifiers live in one private file, `~/.config/agent-privacy-guard/identifiers.txt`,
never in this repository. See `identifiers.example.txt`.

## Install

```bash
mkdir -p ~/.config/agent-privacy-guard
cp identifiers.example.txt ~/.config/agent-privacy-guard/identifiers.txt
chmod 600 ~/.config/agent-privacy-guard/identifiers.txt
# then edit it with your own values
```

**Outbound hook** (needs `jq`). Copy `hooks/deny-personal-data.sh` somewhere
stable (these instructions use `~/.agents/hooks/`) and make it executable.

- Claude Code, in `~/.claude/settings.json` under `hooks.PreToolUse`:

  ```json
  { "matcher": "Bash|WebFetch|WebSearch|mcp__.*",
    "hooks": [{ "type": "command", "command": "\"$HOME/.agents/hooks/deny-personal-data.sh\" claude", "timeout": 10 }] }
  ```

- Codex, in `~/.codex/hooks.json` under `hooks.PreToolUse`, then approve the
  new hook in Codex (`/hooks`): Codex skips a hook until you trust it.

  ```json
  { "matcher": "^(Bash|mcp__.*)$",
    "hooks": [{ "type": "command", "command": "/Users/YOU/.agents/hooks/deny-personal-data.sh codex", "timeout": 10 }] }
  ```

- OpenCode: copy `opencode/privacy-guard.js` to `~/.config/opencode/plugins/`.
  It runs the same script from `~/.agents/hooks/`.

**Context mod** (Claude Code only). `claude-mod/privacy-guard/` is a plugin.
Add it to a local marketplace, or try it for one session with
`claude --plugin-dir claude-mod/privacy-guard`. It does not run where Claude
Code's built-in guard loads (Team or Enterprise login, or a machine with
managed settings): there, plugins may not change the context.

## Test

```bash
bash tests/test-deny-personal-data.sh      # the shell hook
node tests/test-opencode-plugin.mjs        # the OpenCode wrapper
(cd claude-mod/privacy-guard && claude plugin test)   # the mod
```

All three use fake identifiers in a throwaway home folder.

To check the mod in a real session, start one with `claude -p` and one with
`claude -p --safe-mode` (mods off), then search each session's transcript
(`~/.claude/projects/…/<session id>.jsonl`) for your address: it should
appear only in the safe-mode one.

Blocked calls are logged, without the value, to
`~/.local/state/agent-privacy-guard/blocked.log`.

## Limits

- The outbound hook reads the text of the tool call. It does not see a value
  built at run time: a variable, base64, or a script written to a file first
  and run later. It is a tripwire for the common case, not a sandbox. For
  hard limits, use Claude Code's sandbox with a network allowlist.
- It checks the whole command, so a command that both reaches the network
  and mentions an identifier for a local reason (say `claude -p … ; grep you@…`)
  is refused. Split it into two commands.
- Codex's built-in web search runs on OpenAI's side and cannot be hooked.
- Your home folder name and file paths still reveal your username; nothing
  here hides those.
- The mod reads one file and makes no network calls; the hook and plugin
  fail open (allow) if `jq` or the identifiers file is missing.

## Credits

The context mod builds on the approach of AlexErrant's
[claude-code-no-email](https://github.com/AlexErrant/claude-code-no-email)
(MIT): filtering the `userEmail` block out in a `prompt.context` hook. This
version adds a fail-closed handler, blanks listed identifiers in instruction
files, and pairs it with the outbound guard.

## Licence

MIT
