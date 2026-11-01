import {test} from 'node:test';
import assert from 'node:assert/strict';
import {main,parseArguments} from '../src/cli.js';
import {fixture} from './helpers/fixture.js';
import {writeFile,readFile} from 'node:fs/promises';
function printer(){const log=[],error=[];return {log:(x)=>log.push(x),error:(x)=>error.push(x),messages:log,errors:error};}
test('CLI rejects unsupported flags and missing required arguments',()=>{
  for(const args of [[],['verify'],['keygen','--private','key.pem'],['verify','--bad','1'],['policy-create','--threshold','x'],['cosign','--key','x','--key','y']])assert.throws(()=>parseArguments(args));
});
test('CLI recognizes --help and --version independent of files',async()=>{
  let p=printer();assert.equal(await main(['--help'],p),0);assert.match(p.messages[0],/DSSE|signed|admission control/i);
  p=printer();assert.equal(await main(['--version'],p),0);assert.equal(p.messages[0],'0.1.0');
});
test('CLI verify JSON prints only structured status, not sensitive material',async()=>fixture(async f=>{
  const p=printer();const status=await main(['verify','--attestation',f.signed,'--policy',f.policy,'--artifact',f.p('release.tar.gz'),'--json'],p);
  assert.equal(status,0);const x=JSON.parse(p.messages[0]);assert.equal(x.verified,true);assert.equal(x.trustedSigners,2);
  assert.equal(p.messages[0].includes('PRIVATE KEY'),false);
}));
test('CLI returns 1 for signer threshold failures',async()=>fixture(async f=>{
  const p=printer();const status=await main(['verify','--attestation',f.attestation,'--policy',f.policy,'--artifact',f.p('release.tar.gz')],p);
  assert.equal(status,1);assert.match(p.errors[0],/FAIL/);
}));
test('CLI returns 2 for incomplete input without leaking filesystem paths',async()=>fixture(async f=>{
  const p=printer();const status=await main(['verify','--attestation',f.p('missing.json'),'--policy',f.policy,'--artifact',f.p('release.tar.gz')],p);
  assert.equal(status,2);assert.equal(p.errors[0].includes(f.dir),false);
}));
test('CLI policy and attest cannot overwrite existing files',async()=>fixture(async f=>{
  const p=printer();const opts=['attest','--artifact',f.p('release.tar.gz'),'--key',f.alice.priv,'--repository',f.options.repository,
    '--commit',f.options.commit,'--builder',f.options.builder,'--build-type',f.options.buildType,'--output',f.attestation];
  assert.equal(await main(opts,p),2);
}));
