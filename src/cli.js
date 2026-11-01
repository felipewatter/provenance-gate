#!/usr/bin/env node
import { generateKeys, createAttestation, addSignature, createPolicy, verifyAttestation, VerificationFailure } from './index.js';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HELP = `Provenance Gate v0.1.0 — offline signed-release admission control

Commands:
  keygen        --private KEY.pem --public KEY.pub.pem
  attest        --artifact FILE [--artifact FILE...] --key KEY.pem --repository URL
                --commit SHA --builder URL --build-type URL --output ATTEST.json
  cosign        --attestation ATTEST.json --key KEY.pem --output COSIGNED.json
  policy-create --public KEY.pub.pem [--public KEY2.pub.pem...] --threshold N
                --repository URL --commit SHA --builder URL --build-type URL --output POLICY.json
  verify        --attestation ATTEST.json --policy POLICY.json
                --artifact FILE [--artifact FILE...] [--json]
  --help, --version

Exit codes: 0=verified/success, 1=cryptographic or identity policy mismatch,
            2=invalid input, operational error, or incomplete verification.
Signatures authenticate signer assertions, NOT independent CI/build trust or SLSA levels.
`;
export function parseArguments(argv) {
  if (argv.includes('--help') || argv.includes('-h')) return { command: 'help' };
  if (argv.includes('--version') || argv.includes('-v')) return { command: 'version' };
  const [command, ...args] = argv;
  if (!['keygen','attest','cosign','policy-create','verify'].includes(command)) throw Error('Unsupported command');
  const allowed = {
    keygen: ['private','public'],
    attest: ['artifact','key','repository','commit','builder','build-type','output'],
    cosign: ['attestation','key','output'],
    'policy-create': ['public','threshold','repository','commit','builder','build-type','output'],
    verify: ['attestation','policy','artifact','json']
  }[command];
  const out = { command, artifact: [], public: [] };
  for (let i = 0; i < args.length; ++i) {
    const arg = args[i], eq = arg.indexOf('=');
    const flag = eq >= 0 ? arg.slice(0,eq) : arg;
    if (!flag.startsWith('--')) throw Error('No positional arguments supported');
    const key = flag.slice(2);
    if (!allowed.includes(key)) throw Error('Unrecognized option');
    if (key === 'json') { if (eq >= 0 || out.json) throw Error('Invalid --json'); out.json = true; continue; }
    const value = eq >= 0 ? arg.slice(eq+1) : args[++i];
    if (!value || (eq < 0 && value.startsWith('--'))) throw Error('Missing option value');
    if (key === 'artifact' || key === 'public') out[key].push(value);
    else { if (out[key] !== undefined) throw Error('Repeated option'); out[key] = value; }
  }
  for (const key of allowed) {
    if (key === 'json') continue;
    const value = out[key];
    if (!value || (Array.isArray(value) && !value.length)) throw Error('Missing required parameter');
  }
  if (command === 'policy-create') {
    if (!/^[1-9][0-9]*$/.test(out.threshold)) throw Error('Invalid threshold');
    out.threshold = Number(out.threshold);
    if (!Number.isSafeInteger(out.threshold)) throw Error('Invalid threshold');
  }
  return out;
}
export async function main(argv = process.argv.slice(2), printer = console) {
  let options;
  try { options = parseArguments(argv); } catch {
    printer.error('Provenance Gate: invalid options. Use --help.'); return 2;
  }
  if (options.command === 'help') { printer.log(HELP); return 0; }
  if (options.command === 'version') { printer.log('0.1.0'); return 0; }
  try {
    let result;
    if (options.command === 'keygen') result = await generateKeys(options.private, options.public);
    if (options.command === 'attest') result = await createAttestation({
      artifacts:options.artifact, privateKeyPath:options.key, repository:options.repository,
      commit:options.commit,builder:options.builder,buildType:options['build-type'],output:options.output
    });
    if (options.command === 'cosign') result = await addSignature(options.attestation, options.key, options.output);
    if (options.command === 'policy-create') result = await createPolicy({
      publicKeys:options.public, threshold:options.threshold,repository:options.repository,
      commit:options.commit,builder:options.builder,buildType:options['build-type'],output:options.output
    });
    if (options.command === 'verify') result = await verifyAttestation({
      attestationPath:options.attestation,policyPath:options.policy,artifacts:options.artifact
    });
    printer.log(options.json ? JSON.stringify(result) : options.command === 'verify'
      ? `PASS: ${result.artifacts} artifact(s), ${result.trustedSigners}/${result.requiredSigners} trusted signers, pinned commit verified.`
      : `OK: ${options.command} completed; no private key material printed.`);
    return 0;
  } catch (error) {
    // Avoid accidentally printing paths, PEM contents or credentials in error strings.
    if (error instanceof VerificationFailure) {
      printer.error('FAIL: artifact integrity, signature threshold or provenance identity policy did not match.');
      return 1;
    }
    printer.error('ERROR: invalid input or incomplete verification. No approval issued.');
    return 2;
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  void main().then(code => { process.exitCode = code; });
}
