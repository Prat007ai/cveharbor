// Disposable fictional tenants and SQLite only; no staging/production requests.
import fs from 'node:fs';
import worker from '../account-backend/src/index.js';
import {unifiedFixture,assetOne,assetTwo,assetOther} from '../account-backend/tests/helpers/unified-db.mjs';
export {assetOne,assetTwo,assetOther};
export const customerA='c-'+assetOne,customerB='c-'+assetTwo,customerOther='c-'+assetOther;
export async function customerRemediationFixture({migration=true}={}){
 const f=await unifiedFixture();
 for(const file of ['0029_finding_assignment_links.sql','0030_status_update_notifications.sql'])f.DB.sql.exec(fs.readFileSync(new URL('../account-backend/migrations/'+file,import.meta.url),'utf8'));
 if(migration)f.DB.sql.exec(fs.readFileSync(new URL('../deployment/proposals/customer-remediation/schema.sql',import.meta.url),'utf8'));
 Object.assign(f.env,{ASSIGNMENT_ACK_ENABLED:'true'});
 const call=async(path,method='GET',data,account='a')=>worker.fetch(f.request(path,method,data,account),f.env,{waitUntil:()=>{}});
 return {...f,call};
}
