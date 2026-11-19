// The page's modules link: every name a module of src/ imports from another one is exported there.
// A browser refuses the whole page on one missing export (a SyntaxError at link time, before any of
// its code runs), and the unit tests, which import modules one by one, would not see it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const SRC = new URL('../src/', import.meta.url);
const exportsOf = (src) => {
  const names = new Set();
  for (const m of src.matchAll(/^export (?:async )?(?:function\*? |const |let |class )([\w$]+)/gm)) names.add(m[1]);
  for (const m of src.matchAll(/^export \{([^}]*)\}/gm)) for (const part of m[1].split(',')) names.add(part.trim().split(/\s+as\s+/).pop());
  return names;
};

test('every import of the page names an export of its module (app.js, src/ui/ and the rest of src/)', () => {
  const files = readdirSync(SRC, { recursive: true }).filter((f) => f.endsWith('.js'));
  let checked = 0;
  for (const f of files) {
    const src = readFileSync(new URL(f, SRC), 'utf8');
    for (const m of src.matchAll(/^import \{([^}]*)\} from '(\.[^']+)';/gm)) {
      const target = new URL(m[2], new URL(f, SRC));
      if (!target.pathname.includes('/vault/src/')) continue; // the indexer's and circuit/js modules have their own tests
      const exported = exportsOf(readFileSync(target, 'utf8'));
      for (const name of m[1].split(',').map((x) => x.trim().split(/\s+as\s+/)[0]).filter(Boolean)) {
        assert.ok(exported.has(name), `${f} imports ${name} from ${m[2]}, which does not export it`);
        checked++;
      }
    }
  }
  assert.ok(checked > 150, `${checked} imports checked`);
});

// `$` (the DOM helper of ui/context.js) is the one name a word pattern does not see: check its uses apart.
test('every module that calls $( imports it, or defines it', () => {
  for (const f of readdirSync(SRC, { recursive: true }).filter((x) => x.endsWith('.js'))) {
    const src = readFileSync(new URL(f, SRC), 'utf8').replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, '');
    if (!/(^|[^\w$.])\$\(/m.test(src)) continue;
    const imported = [...src.matchAll(/^import \{([^}]*)\} from/gm)].some((m) => m[1].split(',').map((x) => x.trim()).includes('$'));
    const defined = /^(export )?const \$ = /m.test(src);
    assert.ok(imported || defined, `${f} calls $( without importing it`);
  }
});

/**
 * The code without the text of its strings, template literals and comments, keeping the expressions
 * inside `${…}` (nested braces and templates too): what a call check must look at, and nothing else.
 */
function codeOnly(src) {
  let out = '';
  const stack = []; // 'tpl' while inside a template's text, a number (brace depth) inside a ${…}
  let i = 0;
  const inTemplateText = () => stack.length && stack[stack.length - 1] === 'tpl';
  while (i < src.length) {
    const c = src[i];
    if (inTemplateText()) {
      if (c === '\\') { i += 2; continue; }
      if (c === '`') { stack.pop(); out += ' '; i++; continue; }
      if (c === '$' && src[i + 1] === '{') { stack.push(0); out += ' '; i += 2; continue; }
      i++;
      continue;
    }
    if (c === '/' && src[i + 1] === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); i = e < 0 ? src.length : e + 2; continue; }
    if (c === "'" || c === '"') {
      i++;
      while (i < src.length && src[i] !== c && src[i] !== '\n') i += src[i] === '\\' ? 2 : 1;
      out += ' ';
      i++;
      continue;
    }
    if (c === '`') { stack.push('tpl'); out += ' '; i++; continue; }
    if (stack.length && c === '{') stack[stack.length - 1]++;
    if (stack.length && c === '}') {
      if (stack[stack.length - 1] === 0) { stack.pop(); out += ' '; i++; continue; } // back to the template's text
      stack[stack.length - 1]--;
    }
    out += c;
    i++;
  }
  return out;
}

// A name a module calls (also after a spread, `...f(x)`) must be defined or imported there: a missing
// import is a ReferenceError only when that code runs, which a test of another path does not reach.
test('every function a page module calls is defined or imported in that module', () => {
  const files = readdirSync(SRC, { recursive: true }).filter((x) => x.endsWith('.js'));
  const exported = new Set();
  for (const f of files) for (const n of exportsOf(readFileSync(new URL(f, SRC), 'utf8'))) exported.add(n);
  for (const f of files) {
    const raw = readFileSync(new URL(f, SRC), 'utf8');
    const code = codeOnly(raw).replace(/\.\.\./g, ' ');
    const imported = new Set([...raw.matchAll(/^import \{([^}]*)\} from/gm)].flatMap((m) => m[1].split(',').map((x) => x.trim().split(/\s+as\s+/).pop())));
    const local = new Set([...code.matchAll(/(?:function\*?|const|let|var|class)\s+([\w$]+)/g)].map((m) => m[1]));
    for (const m of code.matchAll(/(?<![\w$.])([A-Za-z_][\w$]*)\s*\(/g)) {
      const n = m[1];
      if (!exported.has(n) || local.has(n)) continue;
      const line = code.slice(code.lastIndexOf('\n', m.index) + 1, m.index);
      if (/^\s*((async|static|get|set)\s+)*$/.test(line)) continue; // a method's declaration, not a call
      assert.ok(imported.has(n), `${f} calls ${n}() without importing it`);
    }
  }
});

