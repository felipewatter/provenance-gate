/** Self-contained demo with throwaway keys and artifacts. Nothing is committed. */
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {generateKeys,createAttestation,addSignature,createPolicy,verifyAttestation,VerificationFailure} from '../src/index.js';
const root=await mkdtemp(path.join(os.tmpdir(),'provenance-gate-demo-'));
const p=name=>path.join(root,name);
const provenance={repository:'https://github.com/felipewatter/demo-repo',commit:'b'.repeat(40),
  builder:'https://github.com/actions/runner/github-hosted',buildType:'https://example.org/buildtypes/demo/v1'};
try{
  await writeFile(p('app-v0.1.0.tar.gz'),Buffer.from('sample-release-content-for-learning'));
  await generateKeys(p('signer-one.key'),p('signer-one.pub'));
  await generateKeys(p('signer-two.key'),p('signer-two.pub'));
  await createAttestation({artifacts:[p('app-v0.1.0.tar.gz')],privateKeyPath:p('signer-one.key'),output:p('first.intoto.json'),...provenance});
  await addSignature(p('first.intoto.json'),p('signer-two.key'),p('two-signers.intoto.json'));
  await createPolicy({publicKeys:[p('signer-one.pub'),p('signer-two.pub')],threshold:2,output:p('policy.json'),...provenance});
  const result=await verifyAttestation({attestationPath:p('two-signers.intoto.json'),policyPath:p('policy.json'),artifacts:[p('app-v0.1.0.tar.gz')]});
  if(!result.verified)throw Error('Expected verified result');
  console.log('PASS — 2/2 trusted Ed25519 signers, pinned source identity and artifact SHA-256 verified.');
  await writeFile(p('app-v0.1.0.tar.gz'),Buffer.from('tampered-release'));
  let rejected=false;
  try{await verifyAttestation({attestationPath:p('two-signers.intoto.json'),policyPath:p('policy.json'),artifacts:[p('app-v0.1.0.tar.gz')]});}
  catch(e){if(e instanceof VerificationFailure)rejected=true;else throw e;}
  if(!rejected)throw Error('Tampered release was accepted');
  console.log('PASS — altered release bytes rejected, no approval issued.');
  console.log('Demo credentials were temporary and have been discarded.');
}finally{await rm(root,{recursive:true,force:true});}
