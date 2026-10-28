// OpenCode plugin for agent-privacy-guard.
// Refuses a tool call that would send one of your personal identifiers
// (listed in ~/.config/agent-privacy-guard/identifiers.txt) to a third party.
//
// All the matching lives in one shell script shared with Claude Code and
// Codex: ~/.agents/hooks/deny-personal-data.sh. This plugin only translates
// OpenCode's tool call into that script's input and acts on its answer.
//
// Install: copy to ~/.config/opencode/plugins/ (loaded automatically).
// Fails open (allows) when the script or jq is missing, as the script does.
// Written for OpenCode 2 (`setup`), with `server` for OpenCode 1.18.29+.

import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";

const SCRIPT = path.join(os.homedir(), ".agents/hooks/deny-personal-data.sh");

// Built-in tools that only touch this computer. Everything else (web fetch,
// web search, MCP tools) is treated as able to reach a third party.
// `batch` is deliberately absent: it runs other tools, so its whole input
// is checked.
const LOCAL_TOOLS = new Set([
  "read", "write", "edit", "multiedit", "patch", "apply_patch", "glob",
  "grep", "list", "ls", "todowrite", "todoread", "task", "skill",
  "question", "lsp", "invalid", "plan_enter", "plan_exit",
]);

// (Not exported: OpenCode 1 calls every exported function as a plugin.)
// Maps an OpenCode tool call to the hook JSON the script reads, or null to
// skip it. "opencode" mode: refusals only, since OpenCode has no ask step.
function toHookInput(tool, args) {
  const name = String(tool ?? "").toLowerCase();
  if (!name) return null;
  // Local tools are still sent, so the script can refuse any that touch the
  // identifiers folder; it checks nothing else for them.
  if (LOCAL_TOOLS.has(name)) return { tool_name: `local__${name}`, tool_input: args ?? {} };
  if (name === "shell" || name === "bash") {
    const command = typeof args?.command === "string" ? args.command : "";
    return command ? { tool_name: "Bash", tool_input: { command } } : null;
  }
  return { tool_name: `mcp__opencode__${name}`, tool_input: args ?? {} };
}

// Resolves to the refusal reason, or null to allow.
function check(tool, args, script = SCRIPT) {
  const input = toHookInput(tool, args);
  if (!input) return Promise.resolve(null);
  return new Promise((resolve) => {
    let err = "";
    let child;
    try {
      child = spawn("bash", [script, "opencode"], { stdio: ["pipe", "ignore", "pipe"] });
    } catch {
      resolve(null);
      return;
    }
    child.stderr.on("data", (d) => (err += d));
    child.on("error", () => resolve(null));
    child.on("close", (code) => resolve(code === 2 ? err.trim() || "Blocked by the agent privacy guard." : null));
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(input));
  });
}

const BLOCKED_COMMAND =
  "echo 'Blocked by the agent privacy guard: the original command was not run.' >&2; exit 1";

// OpenCode 2.
async function setup(ctx) {
  if (typeof ctx?.tool?.hook !== "function") return;
  try {
    await ctx.tool.hook("execute.before", async (event) => {
      const input = event?.input ?? {};
      const reason = await check(event?.tool, input);
      if (!reason) return;
      // Swap the command out first, so it cannot run even if a host ignored
      // the error, then reject the call.
      if (typeof input.command === "string") event.input = { ...input, command: BLOCKED_COMMAND };
      throw new Error(reason);
    });
  } catch {
    // Hook API not as expected: load without the guard rather than fail.
  }
}

// OpenCode 1 (1.18.29+).
async function server() {
  return {
    "tool.execute.before": async (input, output) => {
      const reason = await check(input?.tool, output?.args ?? input?.args);
      if (reason) throw new Error(reason);
    },
  };
}

export default {
  id: "privacy-guard",
  setup,
  server,
};
