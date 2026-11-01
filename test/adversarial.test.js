import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile,chmod} from 'node:fs/promises';
import {fixture} from './helpers/fixture.js';
import {verifyAttestation,createAttestation,addSignature,createPolicy,VerificationFailure} from '../src/index.js';
const artifacts=f=>[f.p('release.tar.gz')];
test('invalid/truncated base64 signature cannot be accepted',async()=>fixture(async f=>{
  const env=JSON.parse(await readFile(f.signed,'utf8'));
  env.signatures[0].sig=env.signatures[0].sig.slice(0,-4)+'@@@@';
  const file=f.p('invalid-base64.json');await writeFile(file,JSON.stringify(env));
  await assert.rejects(()=>verifyAttestation({attestationPath:file,policyPath:f.policy,artifacts:artifacts(f)}));
}));
test('untrusted envelope key hints cannot inject a trust root',async()=>fixture(async f=>{
  const env=JSON.parse(await readFile(f.signed,'utf8'));
  env.trustedKeys=JSON.parse(await readFile(f.policy,'utf8')).trustedKeys;
  const file=f.p('trust-from-envelope.json');await writeFile(file,JSON.stringify(env));
  await assert.rejects(()=>verifyAttestation({attestationPath:file,policyPath:f.policy,artifacts:artifacts(f)}));
}));
test('ambiguous duplicate key JSON is rejected before cryptographic evaluation',async()=>fixture(async f=>{
  const content=await readFile(f.signed,'utf8');
  const hacked=content.replace('"payloadType":', '"payloadType":"ignored","payloadType":');
  const file=f.p('duplicate.json');await writeFile(file,hacked);
  await assert.rejects(()=>verifyAttestation({attestationPath:file,policyPath:f.policy,artifacts:artifacts(f)}));
}));
test('changing source repository in external policy blocks verification',async()=>fixture(async f=>{
  const policy=JSON.parse(await readFile(f.policy,'utf8'));
  policy.repository='https://github.com/another-user/another-repo';
  const file=f.p('another-repo.json');await writeFile(file,JSON.stringify(policy));
  await assert.rejects(()=>verifyAttestation({attestationPath:f.signed,policyPath:file,artifacts:artifacts(f)}),VerificationFailure);
}));
test('changing build type in policy blocks verification',async()=>fixture(async f=>{
  const policy=JSON.parse(await readFile(f.policy,'utf8'));
  policy.buildType='https://example.org/buildtypes/altered/v1';
  const file=f.p('another-type.json');await writeFile(file,JSON.stringify(policy));
  await assert.rejects(()=>verifyAttestation({attestationPath:f.signed,policyPath:file,artifacts:artifacts(f)}),VerificationFailure);
}));
test('policy rejects dishonest threshold larger than approved key count',async()=>fixture(async f=>{
  const bad=f.p('bad-policy.json');const policy=JSON.parse(await readFile(f.policy,'utf8'));
  policy.threshold=3;await writeFile(bad,JSON.stringify(policy));
  await assert.rejects(()=>verifyAttestation({attestationPath:f.signed,policyPath:bad,artifacts:artifacts(f)}));
}));
test('expired policy is not assumed; release commit must still be explicitly pinned',async()=>fixture(async f=>{
  const p=JSON.parse(await readFile(f.policy,'utf8'));delete p.commit;
  const file=f.p('not-pinned.json');await writeFile(file,JSON.stringify(p));
  await assert.rejects(()=>verifyAttestation({attestationPath:f.signed,policyPath:file,artifacts:artifacts(f)}));
}));
test('Unix signing keys with group-read permission are rejected', {skip:process.platform==='win32'},async()=>fixture(async f=>{
  await chmod(f.alice.priv,0o644);
  await assert.rejects(()=>createAttestation({artifacts:artifacts(f),privateKeyPath:f.alice.priv,output:f.p('bad-attestation.json'),...f.options}));
  await assert.rejects(()=>addSignature(f.attestation,f.alice.priv,f.p('bad-cosign.json')));
}));
test('generated policy cannot reuse the same trusted public key twice',async()=>fixture(async f=>{
  await assert.rejects(()=>createPolicy({publicKeys:[f.alice.pub,f.alice.pub],threshold:2,output:f.p('duplicate-trust.json'),...f.options}));
}));
