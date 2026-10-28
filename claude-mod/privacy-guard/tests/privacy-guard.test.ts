import { expect, mock, test } from 'claude-code/testing'
import { parseIdentifiers, redact } from '../hooks/redact.ts'

// Fake identifiers only: real ones live in the user's private file.
const IDS = 'block jane.doe@example.org\nask  Jane Doe\n# comment\n\nabc\n'
const EMAIL = { name: 'userEmail', text: "The user's email address is jane.doe@example.org." }
const DATE = { name: 'currentDate', text: "Today's date is 2026-10-28." }
const FILE = {
  path: '/home/u/.claude/CLAUDE.md',
  kind: 'user' as const,
  content: 'Commits as JANE.DOE@example.org; signed Jane Doe.',
}

// Stands for Claude Code: renders claudeMd from the files it is handed.
function engine(on: any) {
  on('prompt.context', ($: any, e: any) => ({
    blocks: [
      { name: 'claudeMd', text: (e.instructionFiles ?? []).map((f: any) => f.content).join('\n') },
      EMAIL,
      DATE,
    ],
  }))
}

test('parseIdentifiers reads block/ask lines and skips comments and short values', () => {
  expect(parseIdentifiers(IDS)).toEqual(['jane.doe@example.org', 'Jane Doe'])
})

test('redact ignores case', () => {
  expect(redact('Mail JANE.DOE@EXAMPLE.ORG now', ['jane.doe@example.org'])).toBe(
    'Mail [withheld by privacy-guard] now',
  )
})

test('drops userEmail and blanks identifiers in instruction files', async ($, on) => {
  mock.env(on, { HOME: '/home/u' })
  on('fs.read', ($: any, e: any) => ({ value: e.path.endsWith('identifiers.txt') ? IDS : '' }))
  engine(on)

  const ctx = await $.prompt.context({ blocks: [], instructionFiles: [FILE] })

  expect(ctx.blocks.map(b => b.name)).toEqual(['claudeMd', 'currentDate'])
  expect(ctx.blocks[0].text).toBe(
    'Commits as [withheld by privacy-guard]; signed [withheld by privacy-guard].',
  )
})

test('with no identifiers file, still drops userEmail and leaves the rest alone', async ($, on) => {
  mock.env(on, { HOME: '/home/u' })
  on('fs.read', () => ({ deny: 'ENOENT' }))
  engine(on)

  const ctx = await $.prompt.context({ blocks: [], instructionFiles: [FILE] })

  expect(ctx.blocks.map(b => b.name)).toEqual(['claudeMd', 'currentDate'])
  expect(ctx.blocks[0].text).toBe(FILE.content)
})

test('identifiers with regex characters are matched literally', () => {
  expect(redact('a 1+jane@x.org b 1Xjane@x.org', ['1+jane@x.org'])).toBe(
    'a [withheld by privacy-guard] b 1Xjane@x.org',
  )
})
