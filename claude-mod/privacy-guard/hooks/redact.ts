// Pure helpers, kept apart from register.ts so they hold no `$` calls.

export const PLACEHOLDER = '[withheld by privacy-guard]'

// The identifiers file: one entry per line, `block <value>` or `ask <value>`.
// Blank lines and lines starting with # are ignored. A bare value counts as
// `block`. The mod blanks every value, whatever its action.
export function parseIdentifiers(text: string): string[] {
  const values: string[] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (line === '' || line.startsWith('#')) continue
    const m = /^(block|ask)\s+(.+)$/i.exec(line)
    const value = (m ? m[2] : line).trim()
    // Very short values would blank ordinary words; refuse them.
    if (value.length >= 5) values.push(value)
  }
  return values
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// Replaces every listed value, ignoring case, with the placeholder.
export function redact(text: string, values: readonly string[]): string {
  let out = text
  for (const v of values) {
    out = out.replace(new RegExp(escapeRegExp(v), 'gi'), PLACEHOLDER)
  }
  return out
}

export function containsAny(text: string, values: readonly string[]): boolean {
  const lower = text.toLowerCase()
  return values.some(v => lower.includes(v.toLowerCase()))
}
