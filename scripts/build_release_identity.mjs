import fs from 'node:fs';import path from 'node:path';import {createHash} from 'node:crypto';import {fileURLToPath} from 'node:url';
export const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
export function backendIdentity(base=root){
 const files=[];function walk(dir){for(const e of fs.readdirSync(path.join(base,dir),{withFileTypes:true})){const name=dir+'/'+e.name;if(e.isDirectory())walk(name);else if(name!=='account-backend/src/release-build.js'&&(/\.sql$/.test(name)||name.startsWith('account-backend/src/')||name==='account-backend/wrangler.toml'))files.push(name);}}
 walk('account-backend/src');walk('account-backend/migrations');for(const f of fs.readdirSync(path.join(base,'account-backend')))if(f.endsWith('.sql'))files.push('account-backend/'+f);
 files.push('account-backend/wrangler.toml'); // Public feed data does not change the API/schema compatibility contract.
 const hash=createHash('sha256');for(const name of files.sort()){hash.update(name+'\0');hash.update(fs.readFileSync(path.join(base,name)));hash.update('\0');}return hash.digest('hex');
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){const hash=backendIdentity();fs.writeFileSync(path.join(root,'account-backend/src/release-build.js'),`// Generated at build time; identifies the exact backend source/schema/configuration.\nexport const releaseIdentity=${JSON.stringify(hash)};\n`);console.log('Backend identity generated: '+hash);}
