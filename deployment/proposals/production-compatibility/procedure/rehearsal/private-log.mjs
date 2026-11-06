import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {target} from '../build.mjs';
// Private, durable and append-only. A failed/ambiguous claim is never removed.
export function privateLog(directory,approvalId,scenario){
 const root=fs.realpathSync(target.private_destination),actual=fs.realpathSync(directory);
 const relative=path.relative(root,actual);assert.ok(relative&&!relative.startsWith('..')&&!path.isAbsolute(relative),'Private destination required');
 assert.match(approvalId,/^[a-f0-9-]{36}$/);assert.match(scenario,/^[a-z]+$/);
 const prefix=path.join(actual,approvalId+'-'+scenario);
 const append=event=>{const fd=fs.openSync(prefix+'.jsonl','a',0o600);try{fs.writeSync(fd,JSON.stringify(event)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}};
 const claim=phase=>{assert.match(phase,/^[a-z]+$/);const fd=fs.openSync(prefix+'-'+phase+'.claim','wx',0o600);try{fs.writeSync(fd,JSON.stringify({phase,at:new Date().toISOString()}));fs.fsyncSync(fd);}finally{fs.closeSync(fd);}};
 return {append,claim};
}
