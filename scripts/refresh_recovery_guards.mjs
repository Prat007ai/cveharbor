import {d1Client} from './cloudflare_d1.mjs';import {installGuards} from './recovery_control.mjs';
const DB=d1Client({readOnly:false});const installed=await DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='operations_control'").first();
if(installed)console.log(JSON.stringify(await installGuards(DB)));else console.log('Recovery controls not installed; no guard changes made.');
