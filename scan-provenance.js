#!/usr/bin/env node
/**
 * scan-provenance.js — does this image carry a C2PA provenance manifest, and what
 * does it claim?
 *
 * Zero dependencies. One file. MIT. Runs locally — nothing leaves your machine.
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS DOES NOT DO — read this first
 * ---------------------------------------------------------------------------
 * This tool does NOT verify the cryptographic signature, and it will never tell
 * you an image is "authentic" or "verified".
 *
 * Real C2PA validation means parsing the COSE signature, walking the certificate
 * chain, checking it against a trust list, and re-hashing every asserted byte
 * range. That is a large surface, and a tool that LOOKS authoritative while
 * skipping signature validation is worse than no tool at all — it manufactures
 * confidence it has not earned. For actual validation use c2patool from the
 * Content Authenticity Initiative.
 *
 * What this DOES answer, which nothing on most people's machines currently
 * answers at all:
 *
 *   - Is there a provenance manifest in this file, yes or no?
 *   - Where is it, how big is it, how many manifests are chained?
 *   - What does the manifest CLAIM — which tool generated it, which assertions
 *     it carries, whether it declares AI generation.
 *
 * The distinction this tool is built around: **"a claim is present" and "the
 * claim is true" are different facts, and conflating them is the entire failure
 * mode of provenance tooling.** Every line of output is phrased as the former.
 * ---------------------------------------------------------------------------
 *
 * Verified against the official C2PA test corpus (c2pa-org/public-testfiles),
 * including the deliberately-corrupt E-sig / E-clm / E-dat / E-uri fixtures. Those
 * are the important cases: a detector that reports them the same way it reports a
 * good file is being honest, because it is not checking signatures. One that
 * called them valid would be lying.
 *
 * Usage:
 *   node scan-provenance.js <file-or-directory> [--json]
 */

'use strict';
const fs = require('fs');
const path = require('path');

const JSON_OUT = process.argv.includes('--json');
const TARGET = process.argv.slice(2).find(a => !a.startsWith('--')) || '.';

const IMAGE_EXT = new Set(['.jpg', '.jpeg', '.png', '.webp', '.avif', '.heic', '.tif', '.tiff', '.gif', '.svg']);

// JUMBF (ISO/IEC 19566-5) content-type UUIDs that matter here. The C2PA manifest
// store is identified by the ASCII tag 'c2pa' at the head of its description box.
const C2PA_TAG = Buffer.from('c2pa', 'latin1');
const JUMB = Buffer.from('jumb', 'latin1');
const JUMD = Buffer.from('jumd', 'latin1');

/**
 * JPEG: the manifest rides in APP11 segments (0xFFEB). Large manifests are SPLIT
 * across multiple APP11 segments which must be concatenated in order — a
 * single-segment reader silently truncates a real-world manifest, which is the
 * commonest way these parsers get quietly wrong.
 */
function extractJpegJumbf(buf) {
  const parts = [];
  let i = 2; // skip SOI
  while (i < buf.length - 4) {
    if (buf[i] !== 0xFF) { i++; continue; }
    const marker = buf[i + 1];
    if (marker === 0xD8 || (marker >= 0xD0 && marker <= 0xD9)) { i += 2; continue; }
    if (marker === 0xDA) break; // start of scan — image data from here
    const len = buf.readUInt16BE(i + 2);
    if (len < 2) break;
    if (marker === 0xEB) {      // APP11
      const seg = buf.subarray(i + 4, i + 2 + len);
      // APP11 payload: 'JP' + box instance + packet seq + payload
      if (seg.length > 8 && seg[0] === 0x4A && seg[1] === 0x50) {
        parts.push({ seq: seg.readUInt32BE(4), data: seg.subarray(8), offset: i });
      } else {
        parts.push({ seq: parts.length, data: seg, offset: i });
      }
    }
    i += 2 + len;
  }
  if (!parts.length) return null;
  parts.sort((a, b) => a.seq - b.seq);
  return { buf: Buffer.concat(parts.map(p => p.data)), segments: parts.length, offset: parts[0].offset };
}

/** PNG: the manifest lives in a `caBX` ancillary chunk. */
function extractPngJumbf(buf) {
  let i = 8; // skip signature
  while (i + 8 <= buf.length) {
    const len = buf.readUInt32BE(i);
    const type = buf.toString('latin1', i + 4, i + 8);
    if (type === 'caBX') return { buf: buf.subarray(i + 8, i + 8 + len), segments: 1, offset: i };
    if (type === 'IEND') break;
    i += 12 + len;
  }
  return null;
}

/** Generic fallback: locate a JUMBF superbox anywhere (WebP/AVIF/HEIF/TIFF). */
function extractGenericJumbf(buf) {
  const at = buf.indexOf(JUMB);
  if (at < 4) return null;
  return { buf: buf.subarray(at - 4), segments: 1, offset: at - 4 };
}

/**
 * Walk the JUMBF box tree and collect labels. Box: [4B length][4B type][payload].
 * A `jumd` description box carries a 16-byte content UUID, a 1-byte toggle, then a
 * NUL-terminated label — the labels are what make the output human-readable.
 */
function walkJumbf(buf, depth = 0, out = { labels: [], boxes: 0, c2pa: false }) {
  let i = 0;
  while (i + 8 <= buf.length && depth < 12) {
    let len = buf.readUInt32BE(i);
    const type = buf.subarray(i + 4, i + 8);
    if (len === 0) break;
    if (len === 1) { i += 16; continue; }        // 64-bit length: skip, rare here
    if (len < 8 || i + len > buf.length) break;
    out.boxes++;
    const payload = buf.subarray(i + 8, i + len);
    if (type.equals(JUMD)) {
      if (payload.subarray(0, 4).equals(C2PA_TAG)) out.c2pa = true;
      const nul = payload.indexOf(0, 17);
      if (nul > 17) {
        const label = payload.toString('utf8', 17, nul).trim();
        if (label && label.length < 120 && /^[\x20-\x7E]+$/.test(label)) out.labels.push(label);
      }
    } else if (type.equals(JUMB)) {
      walkJumbf(payload, depth + 1, out);
    }
    i += len;
  }
  return out;
}

/**
 * Pull readable strings out of the CBOR-encoded claim without a full CBOR parser.
 * This is deliberately heuristic and is only used for DISPLAY — nothing downstream
 * depends on it being complete, and it is never presented as verified fact.
 */
function claimStrings(buf) {
  const s = buf.toString('utf8');
  const found = new Set();
  const re = /(?:c2pa\.[a-z0-9._-]+|[A-Za-z][A-Za-z0-9 ._/-]{3,60}\/\d+\.\d+[.\d]*)/g;
  let m;
  while ((m = re.exec(s)) !== null) found.add(m[0].trim());
  return [...found];
}

function scanFile(file) {
  let buf;
  try { buf = fs.readFileSync(file); } catch { return null; }
  const ext = path.extname(file).toLowerCase();

  let box = null;
  if (ext === '.jpg' || ext === '.jpeg') box = extractJpegJumbf(buf);
  else if (ext === '.png') box = extractPngJumbf(buf);
  if (!box) box = extractGenericJumbf(buf);

  if (!box || !box.buf || box.buf.length < 8) {
    return { file, manifest: false };
  }
  const tree = walkJumbf(box.buf);
  if (!tree.c2pa && !box.buf.includes(C2PA_TAG)) return { file, manifest: false };

  const labels = tree.labels;
  const strings = claimStrings(box.buf);
  const assertions = [...new Set(strings.filter(x => x.startsWith('c2pa.')))].sort();
  const generators = strings.filter(x => /\/\d+\.\d/.test(x)).slice(0, 4);
  // Count DISTINCT manifest-shaped labels. Deliberately NOT reported as "the asset
  // was edited N times" — that is an inference this heuristic cannot support, and
  // stating it would be the same overclaim this tool exists to avoid. A label count
  // is a label count.
  const manifestLabels = labels.filter(l => /^(urn:|self#jumbf|c2pa)/i.test(l) || /urn-uuid/i.test(l));

  return {
    file,
    manifest: true,
    bytes: box.buf.length,
    segments: box.segments,
    offset: box.offset,
    boxes: tree.boxes,
    manifestCount: Math.max(1, new Set(manifestLabels.map(l => l.replace(/^self#jumbf\//, ''))).size),
    generatorStrings: generators,   // heuristic extraction — NOT a parsed claim_generator
    assertions,
    aiDeclared: assertions.some(a => /trainedAlgorithmicMedia|generativeAI|c2pa\.created/i.test(a)) ||
                /trainedAlgorithmicMedia|generativeAI/i.test(box.buf.toString('utf8')),
    labels: labels.slice(0, 25),
  };
}

function walkDir(dir, out = []) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) walkDir(full, out);
    else if (IMAGE_EXT.has(path.extname(e.name).toLowerCase())) out.push(full);
  }
  return out;
}

const stat = fs.existsSync(TARGET) ? fs.statSync(TARGET) : null;
if (!stat) { console.error(`not found: ${TARGET}`); process.exit(1); }
const files = stat.isDirectory() ? walkDir(TARGET) : [TARGET];
const results = files.map(scanFile).filter(Boolean);

if (JSON_OUT) {
  console.log(JSON.stringify({ scanned: results.length, results }, null, 2));
} else {
  const withM = results.filter(r => r.manifest);
  console.log(`scanned ${results.length} image(s) — ${withM.length} carry a C2PA manifest\n`);
  for (const r of results) {
    if (!r.manifest) { console.log(`NONE     ${r.file}`); continue; }
    console.log(`MANIFEST ${r.file}`);
    console.log(`         ${r.bytes.toLocaleString()} bytes, ${r.segments} segment(s) at offset ${r.offset}, ${r.boxes} JUMBF boxes`);
    if (r.manifestCount > 1) console.log(`         ${r.manifestCount} distinct manifest-shaped labels (suggests a provenance chain — not a verified edit count)`);
    if (r.generatorStrings.length) console.log(`         version-tagged strings (heuristic, may include XMP namespaces): ${r.generatorStrings.join(', ')}`);
    if (r.aiDeclared) console.log(`         ⚑ declares AI-generated / algorithmic media`);
    if (r.assertions.length) console.log(`         assertions: ${r.assertions.slice(0, 8).join(', ')}${r.assertions.length > 8 ? ` (+${r.assertions.length - 8})` : ''}`);
  }
  if (withM.length) {
    console.log(`\nEvery line above is what the file CLAIMS. This tool does not check the`);
    console.log(`signature and cannot tell you the claim is true — use c2patool for that.`);
    console.log(`"A claim is present" and "the claim is true" are different facts.`);
  }
}
