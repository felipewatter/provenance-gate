import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { generateKeys, createAttestation, addSignature, createPolicy } from '../../src/index.js';
const SOURCE = 'https://github.com/felipewatter/example-release';
const SHA = 'a'.repeat(40);
const BUILDER = 'https://github.com/actions/runner/github-hosted';
const BUILD_TYPE = 'https://example.org/buildtypes/provenance-gate-demo/v1';
export async function fixture(fn) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'provenance-gate-'));
  try {
    const p = n => path.join(dir, n);
    await writeFile(p('release.tar.gz'), 'legitimate-release-payload');
    const alice = { priv:p('alice.pem'),pub:p('alice.pub') };
    const bob = { priv:p('bob.pem'),pub:p('bob.pub') };
    await generateKeys(alice.priv,alice.pub);await generateKeys(bob.priv,bob.pub);
    const options = { repository: SOURCE, commit: SHA, builder: BUILDER, buildType: BUILD_TYPE };
    const attestation = p('attestation.json'), signed = p('both.json'), policy=p('policy.json');
    await createAttestation({ artifacts:[p('release.tar.gz')],privateKeyPath:alice.priv,output:attestation,...options });
    await addSignature(attestation,bob.priv,signed);
    await createPolicy({ publicKeys:[alice.pub,bob.pub],threshold:2,output:policy,...options });
    await fn({p,dir,alice,bob,options,attestation,signed,policy});
  } finally { await rm(dir,{recursive:true,force:true}); }
}
