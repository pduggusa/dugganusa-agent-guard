#!/usr/bin/env node
// Tests for scan-provenance.js, run against the OFFICIAL C2PA test corpus
// (c2pa-org/public-testfiles) rather than fixtures we invented. Synthetic
// fixtures only prove the parser agrees with itself.
'use strict';
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SCANNER = path.join(__dirname, 'scan-provenance.js');
const FIX = path.join(__dirname, 'test-fixtures-c2pa');
let pass = 0, fail = 0;
const check = (name, ok) => { ok ? (pass++, console.log(`  ✅ ${name}`)) : (fail++, console.log(`  ❌ ${name}`)); };
const scan = (t) => {
  try { return JSON.parse(execFileSync('node', [SCANNER, t, '--json'], { encoding: 'utf8', maxBuffer: 64e6 })); }
  catch (e) { return JSON.parse(e.stdout || '{"results":[]}'); }
};

if (!fs.existsSync(FIX)) {
  console.log('test fixtures missing — fetch them with:');
  console.log('  npm run fetch-fixtures');
  process.exit(0);
}

console.log('\nDETECTION (official C2PA corpus)\n');
const r = scan(FIX);
const byName = Object.fromEntries(r.results.map(x => [path.basename(x.file), x]));
check('every corpus file is detected as carrying a manifest',
      r.results.length > 0 && r.results.every(x => x.manifest));
check('multi-segment APP11 manifests are reassembled, not truncated',
      r.results.some(x => x.segments > 1));
check('JUMBF box tree is walked', r.results.every(x => x.boxes > 0));
check('c2pa assertions are surfaced',
      r.results.every(x => Array.isArray(x.assertions) && x.assertions.length > 0));

console.log('\nDELIBERATELY CORRUPT FIXTURES\n');
// These are the important cases. This tool does NOT check signatures, so it must
// report a tampered file the same way it reports a good one. Claiming otherwise
// would be inventing a verification it never performed.
for (const bad of ['adobe-20220124-E-sig-CA.jpg', 'adobe-20220124-E-dat-CA.jpg', 'adobe-20220124-E-clm-CAICAI.jpg']) {
  if (byName[bad]) check(`${bad}: manifest still detected (we do not silently drop tampered files)`, byName[bad].manifest === true);
}
const human = (() => {
  try { return execFileSync('node', [SCANNER, FIX], { encoding: 'utf8', maxBuffer: 64e6 }); }
  catch (e) { return e.stdout || ''; }
})();
check('output never uses the words "valid" or "authentic"',
      !/\b(valid|authentic|verified signature)\b/i.test(human.replace(/does not check|cannot tell you/gi, '')));
check('output states the signature was not checked',
      /does not check the\s*\n?signature|cannot tell you the claim is true/i.test(human));

console.log('\nNEGATIVE CONTROLS\n');
const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'prov-'));
// A 1x1 PNG with no provenance whatsoever.
fs.writeFileSync(path.join(tmp, 'plain.png'), Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64'));
fs.writeFileSync(path.join(tmp, 'notanimage.jpg'), Buffer.from('this is not a jpeg at all'));
const neg = scan(tmp);
check('a plain PNG reports NO manifest', neg.results.find(x => x.file.endsWith('plain.png'))?.manifest === false);
check('a malformed file does not crash and reports NO manifest',
      neg.results.find(x => x.file.endsWith('notanimage.jpg'))?.manifest === false);
fs.rmSync(tmp, { recursive: true, force: true });

console.log(`\npass ${pass} | fail ${fail}`);
process.exit(fail ? 1 : 0);
