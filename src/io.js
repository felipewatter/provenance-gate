import { constants, promises as fs } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { parseStrictJSON } from './strict-json.js';

export const LIMITS = Object.freeze({ json: 1024 * 1024, policy: 64 * 1024, artifact: 512 * 1024 * 1024, totalArtifacts: 1024 * 1024 * 1024, artifacts: 100 });
const isFile = s => s.isFile() && !s.isSymbolicLink();
export function assertPath(value) { if (typeof value !== 'string' || !value || value.includes('\u0000')) throw Error('Invalid file path'); return value; }
export async function openRegular(filename) {
  assertPath(filename);
  const stat = await fs.lstat(filename);
  if (!isFile(stat)) throw Error('Only regular non-symlink files are supported');
  const fd = await fs.open(filename, constants.O_RDONLY | (process.platform === 'win32' ? 0 : (constants.O_NOFOLLOW ?? 0)));
  try {
    const st = await fd.stat();
    if (!st.isFile() || st.dev !== stat.dev || st.ino !== stat.ino) throw Error('File changed during opening');
    return { fd, stat: st };
  } catch (error) { await fd.close(); throw error; }
}
export async function readBounded(filename, limit = LIMITS.json) {
  const { fd, stat } = await openRegular(filename);
  try {
    if (stat.size > limit) throw Error('File exceeds size limit');
    const buf = await fd.readFile();
    const after = await fd.stat();
    if (buf.length > limit || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs) throw Error('File changed during read');
    return new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } finally { await fd.close(); }
}
export async function readJSON(filename, limit = LIMITS.json) { return parseStrictJSON(await readBounded(filename, limit)); }
export async function writeNew(filename, data, secret = false) {
  assertPath(filename);
  await fs.writeFile(filename, data, { flag: 'wx', mode: secret ? 0o600 : 0o644 });
}
export function artifactName(filename) {
  const name = path.basename(assertPath(filename));
  if (!name || name === '.' || name === '..' || name.length > 200 || /[\x00-\x1f\x7f]/.test(name)) throw Error('Unsafe artifact filename');
  return name;
}
export async function digestArtifact(filename) {
  const { fd, stat } = await openRegular(filename);
  try {
    if (stat.size > LIMITS.artifact) throw Error('Artifact exceeds size limit');
    const hash = createHash('sha256'); const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (true) {
      const { bytesRead } = await fd.read(buffer, 0, buffer.length, position);
      if (!bytesRead) break;
      position += bytesRead;
      if (position > LIMITS.artifact) throw Error('Artifact exceeds size limit');
      hash.update(buffer.subarray(0, bytesRead));
    }
    const after = await fd.stat();
    if (position !== stat.size || after.size !== stat.size || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs)
      throw Error('Artifact changed during hashing');
    return { name: artifactName(filename), digest: { sha256: hash.digest('hex') }, bytes: position };
  } finally { await fd.close(); }
}
export async function digestArtifacts(filenames) {
  if (!Array.isArray(filenames) || filenames.length < 1 || filenames.length > LIMITS.artifacts) throw Error('Expected 1-100 artifacts');
  const result = []; const names = new Set(); let total = 0;
  for (const filename of filenames) {
    const entry = await digestArtifact(filename);
    total += entry.bytes;
    if (total > LIMITS.totalArtifacts) throw Error('Aggregate artifact size limit exceeded');
    if (names.has(entry.name)) throw Error('Ambiguous duplicate artifact basename');
    names.add(entry.name); result.push(entry);
  }
  return result.sort((a, b) => a.name.localeCompare(b.name));
}
