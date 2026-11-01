import { createHash, generateKeyPairSync, createPublicKey, createPrivateKey, sign, verify, randomUUID } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import { readBounded, readJSON, writeNew, digestArtifacts, LIMITS } from './io.js';
import { parseStrictJSON } from './strict-json.js';

const TYPE = 'application/vnd.in-toto+json';
const STATEMENT = 'https://in-toto.io/Statement/v1';
const PROVENANCE = 'https://slsa.dev/provenance/v1';
const HEX = /^[0-9a-f]{64}$/;
export class VerificationFailure extends Error { constructor(message) { super(message); this.name = 'VerificationFailure'; } }
function object(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function assert(v, msg) { if (!v) throw Error(msg); }
function exact(value, keys, msg) { assert(object(value) && Object.keys(value).every(k => keys.includes(k)), msg); }
function text(v, max = 300) { assert(typeof v === 'string' && v.length > 0 && v.length <= max && !/[\x00-\x1f\x7f]/.test(v), 'Invalid string value'); return v; }
function base64(s, max = LIMITS.json) {
  assert(typeof s === 'string' && s.length <= 4 * Math.ceil(max / 3) && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s), 'Invalid base64');
  const bytes = Buffer.from(s, 'base64');
  assert(bytes.length <= max && bytes.toString('base64') === s, 'Noncanonical base64');
  return bytes;
}
function jsonBytes(bytes) { return parseStrictJSON(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
export function pae(payloadType, payload) {
  const type = Buffer.from(text(payloadType, 200), 'utf8');
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type, Buffer.from(` ${bytes.length} `), bytes]);
}
export function keyId(publicKey) {
  const k = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
  assert(k.asymmetricKeyType === 'ed25519', 'Only Ed25519 public keys supported');
  return createHash('sha256').update(k.export({ type: 'spki', format: 'der' })).digest('hex');
}
export async function generateKeys(privatePath, publicPath) {
  assert(privatePath !== publicPath, 'Private and public paths must differ');
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' });
  await writeNew(privatePath, privatePem, true);
  await writeNew(publicPath, publicPem);
  return { keyid: keyId(publicPem) };
}
function safeIdentity(repository, builder, buildType) {
  text(repository); text(builder); text(buildType);
  assert(/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository), 'Repository must be canonical GitHub HTTPS URL');
  assert(/^https:\/\/[^\s]+$/.test(builder) && /^https:\/\/[^\s]+$/.test(buildType), 'Builder and build type must use HTTPS');
}
function assertCommit(commit) { assert(typeof commit === 'string' && /^[0-9a-f]{40}$/.test(commit), 'Git commit must be full lowercase 40-character SHA-1'); }
async function loadSigningKey(privateKeyPath) {
  const info = await lstat(privateKeyPath);
  if (!info.isFile() || info.isSymbolicLink() || (process.platform !== 'win32' && (info.mode & 0o077) !== 0))
    throw Error('Private key must be a protected regular file (mode 0600)');
  const key = createPrivateKey(await readBounded(privateKeyPath, 16 * 1024));
  assert(key.asymmetricKeyType === 'ed25519', 'Only Ed25519 private keys supported');
  return key;
}
export async function createAttestation({ artifacts, privateKeyPath, repository, commit, builder, buildType, output }) {
  assertCommit(commit); safeIdentity(repository, builder, buildType);
  const subjects = (await digestArtifacts(artifacts)).map(({ name, digest }) => ({ name, digest }));
  const statement = {
    _type: STATEMENT,
    subject: subjects,
    predicateType: PROVENANCE,
    predicate: {
      buildDefinition: {
        buildType,
        externalParameters: { source: { repository, commit } },
        internalParameters: {},
        resolvedDependencies: [{ uri: repository, digest: { gitCommit: commit } }]
      },
      runDetails: { builder: { id: builder }, metadata: { invocationId: `urn:uuid:${randomUUID()}` } }
    }
  };
  const payload = Buffer.from(JSON.stringify(statement));
  const privateKey = await loadSigningKey(privateKeyPath);
  const publicKey = createPublicKey(privateKey);
  const envelope = { payloadType: TYPE, payload: payload.toString('base64'), signatures: [
    { keyid: keyId(publicKey), sig: sign(null, pae(TYPE, payload), privateKey).toString('base64') }
  ]};
  await writeNew(output, JSON.stringify(envelope, null, 2) + '\n');
  return { keyid: envelope.signatures[0].keyid, subjects: subjects.length };
}
function validateEnvelope(env) {
  exact(env, ['payloadType','payload','signatures'], 'Invalid DSSE envelope fields');
  assert(env.payloadType === TYPE, 'Unexpected DSSE payload type');
  const payload = base64(env.payload, 256 * 1024);
  assert(Array.isArray(env.signatures) && env.signatures.length >= 1 && env.signatures.length <= 20, 'Invalid signature list');
  const seen = new Set();
  for (const item of env.signatures) {
    exact(item, ['keyid','sig'], 'Invalid DSSE signature');
    assert(typeof item.keyid === 'string' && HEX.test(item.keyid) && !seen.has(item.keyid), 'Duplicate or invalid key ID');
    seen.add(item.keyid);
    assert(base64(item.sig, 128).length === 64, 'Invalid Ed25519 signature length');
  }
  return payload;
}
export async function addSignature(attestationPath, privateKeyPath, output) {
  const env = await readJSON(attestationPath);
  const payload = validateEnvelope(env);
  const key = await loadSigningKey(privateKeyPath);
  const id = keyId(createPublicKey(key));
  assert(!env.signatures.some(x => x.keyid === id), 'Signer already in envelope');
  assert(env.signatures.length < 20, 'Signature limit exceeded');
  env.signatures.push({ keyid: id, sig: sign(null, pae(env.payloadType, payload), key).toString('base64') });
  await writeNew(output, JSON.stringify(env, null, 2) + '\n');
  return { keyid: id, signatures: env.signatures.length };
}
function validatePolicy(policy) {
  exact(policy, ['schemaVersion','trustedKeys','threshold','repository','commit','builder','buildType'], 'Invalid trust policy');
  assert(policy.schemaVersion === 1 && Array.isArray(policy.trustedKeys) && policy.trustedKeys.length >= 1 && policy.trustedKeys.length <= 20, 'Invalid trust policy');
  assertCommit(policy.commit); safeIdentity(policy.repository, policy.builder, policy.buildType);
  assert(Number.isInteger(policy.threshold) && policy.threshold >= 1 && policy.threshold <= policy.trustedKeys.length, 'Invalid signer threshold');
  const keys = new Map();
  for (const item of policy.trustedKeys) {
    exact(item, ['keyid','publicKeyPem'], 'Invalid trusted key');
    assert(typeof item.publicKeyPem === 'string' && item.publicKeyPem.length < 8192, 'Invalid public key');
    const key = createPublicKey(item.publicKeyPem);
    const id = keyId(key);
    assert(item.keyid === id && !keys.has(id), 'Invalid or repeated trust root');
    keys.set(id, key);
  }
  return keys;
}
export async function createPolicy({ publicKeys, threshold, repository, commit, builder, buildType, output }) {
  assertCommit(commit); safeIdentity(repository, builder, buildType);
  assert(Array.isArray(publicKeys) && publicKeys.length >= 1 && publicKeys.length <= 20, 'Expected 1-20 trust keys');
  const trustedKeys = [];
  for (const filename of publicKeys) {
    const pem = await readBounded(filename, 8192);
    trustedKeys.push({ keyid: keyId(pem), publicKeyPem: pem });
  }
  const policy = {schemaVersion:1,trustedKeys,threshold,repository,commit,builder,buildType};
  validatePolicy(policy);
  await writeNew(output, JSON.stringify(policy, null, 2) + '\n');
  return { threshold, trustedKeys: trustedKeys.length };
}
function validateStatement(stmt) {
  exact(stmt, ['_type','subject','predicateType','predicate'], 'Unexpected statement fields');
  assert(stmt._type === STATEMENT && stmt.predicateType === PROVENANCE, 'Unsupported statement predicate');
  assert(Array.isArray(stmt.subject) && stmt.subject.length > 0 && stmt.subject.length <= LIMITS.artifacts, 'Invalid subject list');
  const names = new Set();
  for (const subject of stmt.subject) {
    exact(subject, ['name','digest'], 'Unexpected subject fields');
    assert(typeof subject.name === 'string' && subject.name.length > 0 && subject.name.length <= 200 && !subject.name.includes('/') && !subject.name.includes('\\') && !/[\x00-\x1f\x7f]/.test(subject.name) && subject.name !== '.' && subject.name !== '..' && !names.has(subject.name), 'Invalid or duplicate subject');
    names.add(subject.name);
    exact(subject.digest, ['sha256'], 'Invalid subject hash');
    assert(typeof subject.digest.sha256 === 'string' && HEX.test(subject.digest.sha256), 'Invalid sha256 digest');
  }
  const pred = stmt.predicate;
  exact(pred, ['buildDefinition','runDetails'], 'Malformed provenance');
  exact(pred.buildDefinition, ['buildType','externalParameters','internalParameters','resolvedDependencies'], 'Malformed build definition');
  exact(pred.buildDefinition.externalParameters, ['source'], 'Malformed external parameters');
  exact(pred.buildDefinition.externalParameters.source, ['repository','commit'], 'Malformed source');
  exact(pred.buildDefinition.internalParameters, [], 'Unsupported internal parameters');
  assert(Array.isArray(pred.buildDefinition.resolvedDependencies) && pred.buildDefinition.resolvedDependencies.length === 1, 'Unsupported resolved dependencies');
  const dependency = pred.buildDefinition.resolvedDependencies[0];
  exact(dependency, ['uri','digest'], 'Malformed dependency');
  exact(dependency.digest, ['gitCommit'], 'Malformed dependency digest');
  exact(pred.runDetails, ['builder','metadata'], 'Malformed run details');
  exact(pred.runDetails.builder, ['id'], 'Malformed builder');
  exact(pred.runDetails.metadata, ['invocationId'], 'Malformed invocation');
  text(pred.runDetails.metadata.invocationId, 120);
  return stmt;
}
export async function verifyAttestation({ attestationPath, policyPath, artifacts }) {
  const policy = await readJSON(policyPath, LIMITS.policy);
  const trustedKeys = validatePolicy(policy);
  const env = await readJSON(attestationPath);
  const payload = validateEnvelope(env);
  const stmt = validateStatement(jsonBytes(payload));
  const verified = new Set();
  const message = pae(env.payloadType, payload);
  for (const signature of env.signatures) {
    const key = trustedKeys.get(signature.keyid);
    if (key && verify(null, message, key, base64(signature.sig, 128))) verified.add(signature.keyid);
  }
  if (verified.size < policy.threshold) throw new VerificationFailure('Trusted signer threshold not met');
  const def = stmt.predicate.buildDefinition;
  if (def.buildType !== policy.buildType || stmt.predicate.runDetails.builder.id !== policy.builder ||
      def.externalParameters.source.repository !== policy.repository || def.externalParameters.source.commit !== policy.commit ||
      def.resolvedDependencies[0].uri !== policy.repository || def.resolvedDependencies[0].digest.gitCommit !== policy.commit)
    throw new VerificationFailure('Provenance identity policy mismatch');
  const actual = await digestArtifacts(artifacts);
  if (actual.length !== stmt.subject.length) throw new VerificationFailure('Unexpected artifact set');
  const expected = new Map(stmt.subject.map(s => [s.name,s.digest.sha256]));
  for (const item of actual) if (expected.get(item.name) !== item.digest.sha256) throw new VerificationFailure('Artifact digest or name mismatch');
  return { verified: true, trustedSigners: verified.size, requiredSigners: policy.threshold, artifacts: actual.length,
    repository: policy.repository, commit: policy.commit, builder: policy.builder, buildType: policy.buildType };
}
export const formats = Object.freeze({ payloadType: TYPE, statement: STATEMENT, predicateType: PROVENANCE });
