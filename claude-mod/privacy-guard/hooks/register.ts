import type { Hook, Register } from 'claude-code'
import { containsAny, parseIdentifiers, redact } from './redact.ts'

// Claude Code adds a `userEmail` block (your claude.ai login email) to the
// context of every conversation. No setting turns it off.
const EMAIL_BLOCK = 'userEmail'

type Block = { name: string; text: string }

function withoutEmailBlock<T extends { blocks: readonly Block[] }>(r: T): T {
  return { ...r, blocks: r.blocks.filter(b => b.name !== EMAIL_BLOCK) }
}

// Missing or unreadable file: no values, so only the userEmail block goes.
async function loadIdentifiers($: Parameters<Hook<'prompt.context'>>[0]): Promise<string[]> {
  try {
    const home = await $.env.get('HOME')
    if (!home) return []
    const text = await $.fs.read(`${home}/.config/agent-privacy-guard/identifiers.txt`)
    return typeof text === 'string' ? parseIdentifiers(text) : []
  } catch {
    return []
  }
}

export const register: Register = on => {
  on('prompt.context', async ($, e, next) => {
    const values = await loadIdentifiers($)

    // On the way down: blank the identifiers in each instruction file, so
    // the claudeMd text the engine renders from them never holds them.
    const files = e.instructionFiles?.map(f =>
      containsAny(f.content, values) ? { ...f, content: redact(f.content, values) } : f,
    )
    const result = await next(files ? { ...e, instructionFiles: files } : e)

    // On the way up: drop the email block, and blank anything a hook below
    // added that still carries an identifier.
    const out = withoutEmailBlock(result)
    if (values.length === 0) return out
    return {
      ...out,
      blocks: out.blocks.map(b =>
        containsAny(b.text, values) ? { ...b, text: redact(b.text, values) } : b,
      ),
    }
  }).catch(async ($, e, next) => {
    // Fail closed: whatever went wrong, the email block still goes.
    return withoutEmailBlock(await next(e))
  })
}
