import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomBytes} from 'node:crypto';
import {capacityFixture,capacitySessions} from '../account-backend/tests/helpers/capacity-db.mjs';
import {capacitySessionBinding} from '../account-backend/tests/helpers/capacity-sessions.mjs';
import {seedOutage,outageAdapter} from './nvd_capacity_fixture.mjs';
import {CapacityAuthorityCoordinator,coordinatedAuthority} from './capacity_authority_coordinator.mjs';
import {outageRehearsal} from './nvd_capacity_rehearsal.mjs';
const backend=path.resolve(process.env.CAPACITY_BACKEND_DIR||'.');
const worker=(await import(pathToFileURL(path.join(backend,'account-backend/src/index.js')))).default,cvie=await import(pathToFileURL(path.join(backend,'account-backend/src/cvie.js')));
const fixture=capacityFixture({owners:50,customers:50,environments:100,assets:50000}),tokens=capacitySessions(fixture.sql),seed=await seedOutage(fixture,cvie),controlKey=randomBytes(32).toString('hex');
seed.env.DB=capacitySessionBinding(fixture);
if(process.env.CAPACITY_AUTHORITY_COORDINATOR==='true')seed.env.DB=coordinatedAuthority(seed.env.DB,new CapacityAuthorityCoordinator({}, {DB:seed.env.DB}));
const adapter=outageAdapter(worker,cvie.runCvieStep,seed.epoch,controlKey);
const server=http.createServer(async(req,res)=>{try{const r=await adapter.fetch(new Request('https://api.cveharbor.com'+req.url,{method:req.method,headers:req.headers}),{...seed.env,RECOVERY_CONTROL_REQUIRED:'true'},{waitUntil:p=>p.catch(()=>{})});res.writeHead(r.status,Object.fromEntries(r.headers));res.end(await r.text());}catch(e){res.writeHead(500);res.end(JSON.stringify({error:e.message}));}});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
try{
 const result=await outageRehearsal({base:'http://127.0.0.1:'+server.address().port,tokens,controlKey,site:process.env.INVENTORY_TEST_SITE||'.',seconds:Number(process.env.CAPACITY_SECONDS||30)});
 result.environment='Local full Worker/SQLite and Chrome; not Cloudflare capacity';result.backend=backend;result.saved_advisories_after=fixture.sql.prepare('SELECT count(*) n FROM cvie_shared_advisories').get().n;
 fs.writeFileSync('verification/nvd-capacity-local.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({status:'passed',saved_advisories:result.saved_advisories_after}));
}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));fixture.close();}
