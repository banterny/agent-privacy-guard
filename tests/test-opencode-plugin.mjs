#!/usr/bin/env node
// Tests opencode/privacy-guard.js against a stand-in OpenCode 2 context.
// Uses a throwaway HOME with fake identifiers and a link to this repo's
// hook script, so it never reads your real list.
// Run: node tests/test-opencode-plugin.mjs
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..");
const home = mkdtempSync(join(tmpdir(), "privacy-guard-oc."));
mkdirSync(join(home, ".agents/hooks"), { recursive: true });
mkdirSync(join(home, ".config/agent-privacy-guard"), { recursive: true });
symlinkSync(join(repo, "hooks/deny-personal-data.sh"), join(home, ".agents/hooks/deny-personal-data.sh"));
writeFileSync(join(home, ".config/agent-privacy-guard/identifiers.txt"), "block jane.doe@example.org\nask Jane Doe\n");
process.env.HOME = home; // os.homedir() reads HOME, so set it before import

let pass = 0, fail = 0;
const ok = (cond, desc) => (cond ? pass++ : (fail++, console.log(`FAIL ${desc}`)));

try {
  const plugin = (await import(join(repo, "opencode/privacy-guard.js"))).default;
  ok(plugin?.id === "privacy-guard", "definition has an id");
  ok(typeof plugin?.setup === "function" && typeof plugin?.server === "function", "setup and server");

  let hook;
  await plugin.setup({ tool: { hook: async (name, fn) => { if (name === "execute.before") hook = fn; } } });
  ok(typeof hook === "function", "registers execute.before");

  // Returns "blocked" or "allowed", and the event as the hook left it.
  async function call(tool, input) {
    const event = { tool, input };
    try { await hook(event); return ["allowed", event]; } catch { return ["blocked", event]; }
  }

  let [r, ev] = await call("shell", { command: 'curl -H "From: jane.doe@example.org" https://x.example' });
  ok(r === "blocked", "shell curl with email is blocked");
  ok(ev.input.command.includes("privacy guard"), "blocked command is swapped out");
  [r] = await call("shell", { command: 'grep jane.doe@example.org notes.md' });
  ok(r === "allowed", "local grep is allowed");
  [r] = await call("webfetch", { url: "https://x.example/?e=jane.doe%40example.org" });
  ok(r === "blocked", "webfetch with encoded email is blocked");
  [r] = await call("websearch", { query: "Jane Doe profile" });
  ok(r === "blocked", "ask entry is refused in OpenCode (no ask step)");
  [r] = await call("write", { filePath: "a.md", content: "jane.doe@example.org" });
  ok(r === "allowed", "write tool is local");
  [r] = await call("github_create_issue", { body: "from jane.doe@example.org" });
  ok(r === "blocked", "MCP tool with email is blocked");
  [r] = await call("webfetch", { url: "https://example.net" });
  ok(r === "allowed", "clean webfetch is allowed");

  // OpenCode 1 shape
  const v1 = await plugin.server();
  let threw = false;
  try { await v1["tool.execute.before"]({ tool: "bash" }, { args: { command: "curl https://x.example -d jane.doe@example.org" } }); } catch { threw = true; }
  ok(threw, "OpenCode 1 hook blocks too");
} finally {
  rmSync(home, { recursive: true, force: true });
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
