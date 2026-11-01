import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseStrictJSON } from '../src/strict-json.js';
import { digestArtifacts } from '../src/io.js';
import {mkdtemp,writeFile,rm,symlink} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
test('parse JSON values without prototype pollution',()=>{
  assert.deepEqual(parseStrictJSON('{"a":1,"b":[true,false,null,{"name":"ok"}]}'),{a:1,b:[true,false,null,{name:'ok'}]});
});
test('reject repeated object keys even if unicode escaped',()=>{
  for(const s of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"nested":{"x":1,"x":2}}'])assert.throws(()=>parseStrictJSON(s));
});
test('reject dangerous keys, trailing data, malformed escapes and leading zeros',()=>{
  for(const s of ['{"__proto__":{}}','{"constructor":1}','{"prototype":1}','{} {}','{"a":"\\x"}','{"a":01}','{"a":1,}','[1,,2]','{"x":1e9999}0'])assert.throws(()=>parseStrictJSON(s));
});
test('enforce JSON depth and token limits',()=>{
  assert.throws(()=>parseStrictJSON('['.repeat(40)+'0'+']'.repeat(40)));
  assert.throws(()=>parseStrictJSON('[1,2,3,4]',{maxTokens:3}));
});
test('reject BOM and NUL in input',()=>{
  assert.throws(()=>parseStrictJSON('\ufeff{}'));assert.throws(()=>parseStrictJSON('{"x":"a\u0000b"}'));
});
test('digestArtifacts verifies size-bounded file while rejecting symlinks',async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),'pg-files-'));
  try{
    await writeFile(path.join(dir,'a.bin'),'data');
    const x=await digestArtifacts([path.join(dir,'a.bin')]);
    assert.equal(x[0].name,'a.bin');assert.match(x[0].digest.sha256,/^[0-9a-f]{64}$/);
    await assert.rejects(()=>digestArtifacts([path.join(dir,'a.bin'),path.join(dir,'a.bin')]),/duplicate/);
    if(process.platform!=='win32'){
      await symlink(path.join(dir,'a.bin'),path.join(dir,'linked.bin'));
      await assert.rejects(()=>digestArtifacts([path.join(dir,'linked.bin')]));
    }
  }finally{await rm(dir,{recursive:true,force:true});}
});
