#!/usr/bin/env node
/**
 * scan-agent-instructions — find invisible Unicode hidden in AI agent instruction files.
 *
 * WHY (2026-08-17): the TrapDoor supply-chain campaign (original research: Socket,
 * socket.dev) ships poisoned `.cursorrules` and `CLAUDE.md` files containing
 * zero-width Unicode. That is prompt injection delivered through the config an AI
 * coding agent reads on EVERY invocation — not through a dependency, through the
 * agent's own instructions. The text is invisible in an editor, invisible in a diff
 * as rendered by most review tools, and fully visible to the model.
 *
 * A human reviewing that pull request sees nothing.
 *
 * This is a checker, so it EXITS NON-ZERO on findings — the deliberate exception to
 * the house rule that producers exit 0 regardless of what they find.
 *
 *   node scripts/scan-agent-instructions.js                 # scan cwd
 *   node scripts/scan-agent-instructions.js <dir> [--json]  # scan a path
 *   node scripts/scan-agent-instructions.js --all           # every text file, not just agent configs
 *   node scripts/scan-agent-instructions.js --strip         # rewrite files, removing the characters
 */
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const JSON_OUT = args.includes('--json');
const SCAN_ALL = args.includes('--all');
const STRIP = args.includes('--strip');
const ROOT = args.find(a => !a.startsWith('--')) || '.';

// The files an AI coding agent reads as INSTRUCTIONS. Poisoning one of these is
// materially different from poisoning source: the content is prompt, not program.
const AGENT_FILES = new Set([
  'CLAUDE.md', 'AGENTS.md', 'AGENT.md', '.cursorrules', '.clinerules',
  '.windsurfrules', '.github/copilot-instructions.md', 'GEMINI.md',
  '.aider.conf.yml', '.continuerules', 'system-prompt.md', 'llms.txt',
]);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'vendor', 'coverage']);

// Codepoints that carry no visible glyph but ARE delivered to the model.
// Each entry: [codepoint, name, severity]
const INVISIBLE = new Map([
  [0x200B, ['ZERO WIDTH SPACE', 'high']],
  [0x200C, ['ZERO WIDTH NON-JOINER', 'high']],
  [0x200D, ['ZERO WIDTH JOINER', 'context']],   // legitimate inside emoji sequences
  [0x200E, ['LEFT-TO-RIGHT MARK', 'high']],
  [0x200F, ['RIGHT-TO-LEFT MARK', 'high']],
  [0x202A, ['LEFT-TO-RIGHT EMBEDDING', 'critical']],
  [0x202B, ['RIGHT-TO-LEFT EMBEDDING', 'critical']],
  [0x202C, ['POP DIRECTIONAL FORMATTING', 'critical']],
  [0x202D, ['LEFT-TO-RIGHT OVERRIDE', 'critical']],
  [0x202E, ['RIGHT-TO-LEFT OVERRIDE', 'critical']],  // the Trojan Source character
  [0x2060, ['WORD JOINER', 'high']],
  [0x2061, ['FUNCTION APPLICATION', 'high']],
  [0x2062, ['INVISIBLE TIMES', 'high']],
  [0x2063, ['INVISIBLE SEPARATOR', 'high']],
  [0x2064, ['INVISIBLE PLUS', 'high']],
  [0x00AD, ['SOFT HYPHEN', 'medium']],
  [0x061C, ['ARABIC LETTER MARK', 'high']],
  [0x180E, ['MONGOLIAN VOWEL SEPARATOR', 'high']],
  [0xFEFF, ['ZERO WIDTH NO-BREAK SPACE / BOM', 'context']], // legitimate as a leading BOM
]);

// Rough emoji test. ZWJ between two emoji is a family/profession sequence, not an
// attack — flagging those would bury the real signal in noise and get the tool
// switched off, which is the only outcome that actually helps an attacker.
const isEmoji = (cp) => cp !== undefined && (
  (cp >= 0x1F300 && cp <= 0x1FAFF) || (cp >= 0x2600 && cp <= 0x27BF) ||
  (cp >= 0x1F000 && cp <= 0x1F2FF) || cp === 0xFE0F || (cp >= 0x1F1E6 && cp <= 0x1F1FF)
);

function scanText(text, file) {
  const findings = [];
  const cps = Array.from(text);
  let line = 1, col = 1;
  for (let i = 0; i < cps.length; i++) {
    const ch = cps[i];
    const cp = ch.codePointAt(0);
    if (ch === '\n') { line++; col = 1; continue; }
    const hit = INVISIBLE.get(cp);
    if (hit) {
      const [name, sev] = hit;
      let severity = sev;
      if (cp === 0x200D) {
        // ZWJ: legitimate only when it actually joins two emoji.
        const prev = cps[i - 1]?.codePointAt(0), next = cps[i + 1]?.codePointAt(0);
        if (isEmoji(prev) && isEmoji(next)) { col++; continue; }
        severity = 'high';
      }
      if (cp === 0xFEFF) {
        if (i === 0) { col++; continue; }   // leading BOM is ordinary
        severity = 'high';                  // mid-file it is hiding something
      }
      const ctx = text.split('\n')[line - 1] || '';
      findings.push({
        file, line, column: col, severity,
        codepoint: 'U+' + cp.toString(16).toUpperCase().padStart(4, '0'),
        name,
        context: ctx.replace(/[​-‏‪-‮⁠-⁤﻿­؜᠎]/g, '␣').trim().slice(0, 100),
      });
    }
    col++;
  }
  return findings;
}

const STRIP_RE = /[​‌‎‏‪-‮⁠-⁤­؜᠎]/g;

function walk(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name.startsWith('.') && SKIP_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(full, out);
    } else if (e.isFile()) {
      const rel = path.relative(ROOT, full);
      if (SCAN_ALL) {
        if (/\.(md|txt|ya?ml|json|js|ts|py|sh|rules|conf)$/i.test(e.name)) out.push(full);
      } else if (AGENT_FILES.has(e.name) || AGENT_FILES.has(rel)) {
        out.push(full);
      }
    }
  }
  return out;
}

const files = walk(ROOT);
let all = [];
for (const f of files) {
  let text;
  try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }
  const found = scanText(text, path.relative(ROOT, f) || f);
  if (found.length && STRIP) {
    fs.writeFileSync(f + '.bak-preclean', text);   // never destroy the evidence
    fs.writeFileSync(f, text.replace(STRIP_RE, ''));
  }
  all = all.concat(found);
}

if (JSON_OUT) {
  console.log(JSON.stringify({ scanned: files.length, findings: all }, null, 2));
} else {
  console.log(`scanned ${files.length} agent instruction file(s)${SCAN_ALL ? ' (--all: every text file)' : ''}\n`);
  if (!all.length) {
    console.log('✅ no invisible Unicode found.');
    console.log('   (ZWJ inside emoji sequences and a leading BOM are ignored on purpose —');
    console.log('    a checker that cries wolf gets switched off, which only helps an attacker.)');
  } else {
    const bySev = { critical: [], high: [], medium: [] };
    for (const f of all) (bySev[f.severity] ||= []).push(f);
    for (const sev of ['critical', 'high', 'medium']) {
      for (const f of bySev[sev] || []) {
        console.log(`${sev.toUpperCase().padEnd(8)} ${f.file}:${f.line}:${f.column}  ${f.codepoint} ${f.name}`);
        console.log(`         ${f.context}`);
      }
    }
    console.log(`\n${all.length} finding(s). Invisible in an editor. Fully visible to the model.`);
    if (STRIP) console.log('Stripped. Originals preserved as *.bak-preclean.');
    else console.log('Re-run with --strip to remove them (originals preserved).');
  }
}
// Checker semantics: non-zero when something is wrong.
process.exit(all.length ? 1 : 0);
