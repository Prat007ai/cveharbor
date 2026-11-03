export const recoveryTablesSQL="SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT GLOB '_cf_*' AND name NOT GLOB 'd1_*' AND name NOT IN ('operations_control','operations_leases','operations_events') ORDER BY name";
export function recoveryGuardSQL(table,op){
 if(!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(table)||!['insert','update','delete'].includes(op))throw Error('Invalid recovery guard identifier');
 return `CREATE TRIGGER IF NOT EXISTS recovery_hold_${table}_${op} BEFORE ${op.toUpperCase()} ON "${table}" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END`;
}
export const leaseGuardSQL="CREATE TRIGGER IF NOT EXISTS recovery_hold_new_lease BEFORE INSERT ON operations_leases WHEN COALESCE((SELECT write_hold FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END";
export const normalizedDDL=sql=>String(sql).replace(/IF NOT EXISTS\s*/gi,'').replace(/\s+/g,' ').trim().replace(/;$/,'');
