import fs from 'node:fs';
import {createHash} from 'node:crypto';
const msi='windows-agent/package/base/CVEHarbor-Agent.msi';
const receipt={channel:'unsigned-evaluation',commit:process.env.GITHUB_SHA,sha256:createHash('sha256').update(fs.readFileSync(msi)).digest('hex'),version:'1.0.0'};
if(!/^[a-f0-9]{40}$/.test(receipt.commit||''))throw Error('Build provenance required');
fs.writeFileSync('windows-agent/package/base/agent-release.json',JSON.stringify(receipt,null,2)+'\n');
