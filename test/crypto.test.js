import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createPublicKey, createPrivateKey, sign, verify } from 'node:crypto';
import { generateKeys, keyId, pae, createAttestation, addSignature, createPolicy, verifyAttestation, VerificationFailure } from '../src/index.js';

import { fixture } from './helpers/fixture.js';
test('Ed25519 DSSE PAE uses byte lengths and binds payload type', async()=>{
  const payload=Buffer.from('héllo','utf8'),type='application/vnd.in-toto+json';
  const expected=Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.length} `),payload]);
  assert.deepEqual(pae(type,payload),expected);
  const dir=await mkdtemp(path.join(os.tmpdir(),'pg-key-'));
  try{
    const priv=path.join(dir,'private.pem'),pub=path.join(dir,'public.pem');
    const identity=await generateKeys(priv,pub);
    const signature=sign(null,pae(type,payload),createPrivateKey(await readFile(priv)));
    assert.equal(verify(null,pae(type,payload),createPublicKey(await readFile(pub)),signature),true);
    assert.equal(verify(null,pae('application/vnd.in-toto+yaml',payload),createPublicKey(await readFile(pub)),signature),false);
    assert.equal(keyId(await readFile(pub)),identity.keyid);
    await assert.rejects(()=>generateKeys(priv,pub));
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('two independent signatures satisfy a 2-of-2 external policy',async()=>fixture(async f=>{
  const r=await verifyAttestation({attestationPath:f.signed,policyPath:f.policy,artifacts:[f.p('release.tar.gz')]});
  assert.equal(r.verified,true);assert.equal(r.trustedSigners,2);assert.equal(r.requiredSigners,2);
  assert.equal(r.commit,f.options.commit);assert.equal(r.artifacts,1);
}));
test('1 signature cannot satisfy 2-of-2 threshold',async()=>fixture(async f=>{
  await assert.rejects(()=>verifyAttestation({attestationPath:f.attestation,policyPath:f.policy,artifacts:[f.p('release.tar.gz')]}),VerificationFailure);
}));
test('artifact byte tampering invalidates digest even with two valid signers',async()=>fixture(async f=>{
  await writeFile(f.p('release.tar.gz'),'modified-release-content');
  await assert.rejects(()=>verifyAttestation({attestationPath:f.signed,policyPath:f.policy,artifacts:[f.p('release.tar.gz')]}),/Artifact digest/);
}));
test('attestation subject tampering invalidates signature',async()=>fixture(async f=>{
  const env=JSON.parse(await readFile(f.signed,'utf8'));
  const payload=JSON.parse(Buffer.from(env.payload,'base64').toString('utf8'));
  payload.subject[0].digest.sha256='0'.repeat(64);
  env.payload=Buffer.from(JSON.stringify(payload)).toString('base64');
  const fake=f.p('tampered.json');await writeFile(fake,JSON.stringify(env));
  await assert.rejects(()=>verifyAttestation({attestationPath:fake,policyPath:f.policy,artifacts:[f.p('release.tar.gz')]}),VerificationFailure);
}));
test('policy source commit is pinned and mismatches are rejected',async()=>fixture(async f=>{
  const p=JSON.parse(await readFile(f.policy,'utf8'));p.commit='b'.repeat(40);
  const wrong=f.p('wrong.json');await writeFile(wrong,JSON.stringify(p));
  await assert.rejects(()=>verifyAttestation({attestationPath:f.signed,policyPath:wrong,artifacts:[f.p('release.tar.gz')]}),VerificationFailure);
}));
test('builder identity is pinned; signing cannot evade builder policy',async()=>fixture(async f=>{
  const p=JSON.parse(await readFile(f.policy,'utf8'));p.builder='https://attacker.example/builder';
  const wrong=f.p('builder.json');await writeFile(wrong,JSON.stringify(p));
  await assert.rejects(()=>verifyAttestation({attestationPath:f.signed,policyPath:wrong,artifacts:[f.p('release.tar.gz')]}),VerificationFailure);
}));
test('rogue signer not in external trust root cannot satisfy threshold',async()=>fixture(async f=>{
  const badPriv=f.p('rogue.pem'),badPub=f.p('rogue.pub');await generateKeys(badPriv,badPub);
  const a=await addSignature(f.attestation,badPriv,f.p('rogue-attest.json'));
  assert.match(a.keyid,/^[0-9a-f]{64}$/);
  await assert.rejects(()=>verifyAttestation({attestationPath:f.p('rogue-attest.json'),policyPath:f.policy,artifacts:[f.p('release.tar.gz')]}),VerificationFailure);
}));
test('cosigning same key twice or overwriting previous file fails',async()=>fixture(async f=>{
  await assert.rejects(()=>addSignature(f.attestation,f.alice.priv,f.p('duplicate.json')));
  await assert.rejects(()=>addSignature(f.attestation,f.bob.priv,f.signed));
}));
test('key replacement requires updating trust roots, never silently accepted',async()=>fixture(async f=>{
  const roguePriv=f.p('rogue.pem'),roguePub=f.p('rogue.pub');await generateKeys(roguePriv,roguePub);
  const p=JSON.parse(await readFile(f.policy,'utf8'));p.trustedKeys[1].publicKeyPem=await readFile(roguePub,'utf8');
  const mismatch=f.p('inconsistent-trust.json');await writeFile(mismatch,JSON.stringify(p));
  await assert.rejects(()=>verifyAttestation({attestationPath:f.signed,policyPath:mismatch,artifacts:[f.p('release.tar.gz')]}));
}));
test('signature key ID and signature are bound to public key, not signer hint',async()=>fixture(async f=>{
  const env=JSON.parse(await readFile(f.signed,'utf8'));
  env.signatures[0].keyid=env.signatures[1].keyid;
  const file=f.p('bad-keyid.json');await writeFile(file,JSON.stringify(env));
  await assert.rejects(()=>verifyAttestation({attestationPath:file,policyPath:f.policy,artifacts:[f.p('release.tar.gz')]}));
}));
test('exact subject set blocks unlisted files',async()=>fixture(async f=>{
  await writeFile(f.p('other.txt'),'extra');
  await assert.rejects(()=>verifyAttestation({attestationPath:f.signed,policyPath:f.policy,artifacts:[f.p('release.tar.gz'),f.p('other.txt')]}),VerificationFailure);
}));
