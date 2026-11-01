/** Reject duplicate object keys, unsafe property names and ambiguous JSON before JSON.parse. */
export function parseStrictJSON(source, { maxDepth = 32, maxTokens = 150000 } = {}) {
  if (typeof source !== 'string' || source.charCodeAt(0) === 0xfeff || source.includes('\u0000'))
    throw new Error('Invalid JSON input');
  let p = 0, tokens = 0;
  const ws = () => { while (p < source.length && /[\x20\t\r\n]/.test(source[p])) p++; };
  function fail() { throw new Error('Invalid or ambiguous JSON input'); }
  function str() {
    if (source[p] !== '"') fail();
    const from = p++;
    let ended = false;
    while (p < source.length) {
      const c = source[p++];
      if (c === '"') { ended = true; break; }
      if (c === '\\') {
        const escaped = source[p++];
        if (escaped === 'u') {
          if (!/^[0-9a-fA-F]{4}$/.test(source.slice(p, p + 4))) fail();
          p += 4;
        } else if (!'"\\/bfnrt'.includes(escaped || '')) fail();
      } else if (c.charCodeAt(0) < 32) fail();
    }
    if (!ended) fail();
    try { return JSON.parse(source.slice(from, p)); } catch { return fail(); }
  }
  function value(depth) {
    if (++tokens > maxTokens || depth > maxDepth) fail();
    ws(); const c = source[p];
    if (c === '"') { str(); return; }
    if (c === '{') {
      p++; ws(); const keys = new Set();
      if (source[p] === '}') { p++; return; }
      while (true) {
        ws(); const k = str();
        if (keys.has(k) || ['__proto__', 'constructor', 'prototype'].includes(k)) fail();
        keys.add(k); ws(); if (source[p++] !== ':') fail(); value(depth + 1); ws();
        const sep = source[p++]; if (sep === '}') return; if (sep !== ',') fail();
      }
    }
    if (c === '[') {
      p++; ws(); if (source[p] === ']') { p++; return; }
      while (true) { value(depth + 1); ws(); const sep = source[p++]; if (sep === ']') return; if (sep !== ',') fail(); }
    }
    for (const token of ['true', 'false', 'null']) {
      if (source.startsWith(token, p)) { p += token.length; return; }
    }
    if (c === '-' || /[0-9]/.test(c || '')) {
      const match = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(source.slice(p));
      if (!match || match.index !== 0) fail(); p += match[0].length; return;
    }
    fail();
  }
  value(0); ws(); if (p !== source.length) fail();
  try { return JSON.parse(source); } catch { return fail(); }
}
