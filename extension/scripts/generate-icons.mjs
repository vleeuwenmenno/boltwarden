#!/usr/bin/env node
// Generate the committed browser PNGs without the Rust app or npm dependencies.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const check = process.argv.includes('--check');
if (process.argv.slice(2).some(arg => arg !== '--check')) {
  throw new Error('Usage: node scripts/generate-icons.mjs [--check]');
}

const source = readFileSync(new URL('../public/bolt.svg', import.meta.url), 'utf8');
const directory = new URL('../public/icon/', import.meta.url);
const variants = [
  { prefix: '', color: '#808080', sizes: [16, 24, 32, 48, 64, 128] },
  // Firefox chooses these by toolbar text color, not by theme name.
  { prefix: 'light-', color: '#f0f0f0', sizes: [16, 32] },
  { prefix: 'dark-', color: '#242424', sizes: [16, 32] },
];

if (!check) mkdirSync(directory, { recursive: true });
for (const { prefix, color, sizes } of variants) {
  for (const size of sizes) {
    const target = new URL(`${prefix}${size}.png`, directory);
    const image = execFileSync('rsvg-convert', ['--width', String(size), '--height', String(size)], {
      input: source.replaceAll('currentColor', color),
    });
    if (check) {
      if (!readFileSync(target).equals(image)) {
        throw new Error(`Icon differs from canonical SVG: ${fileURLToPath(target)}`);
      }
    } else {
      writeFileSync(target, image);
    }
  }
}
console.log(check ? 'All 10 icons match the canonical SVG.' : 'Generated 10 icons from public/bolt.svg.');
