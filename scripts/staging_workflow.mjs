import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
const action=process.env.STAGING_OPERATION;assert.ok(['bootstrap','validate'].includes(action));const r=spawnSync(process.execPath,['scripts/phase1_staging.mjs',action],{stdio:'inherit'});process.exit(r.status??1);
