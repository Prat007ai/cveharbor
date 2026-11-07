// Explicit operational reserve, not a claim about missing provider metering.
import assert from 'node:assert/strict';
export const failedImportReserve=500000;
export function checkRehearsalWrites(reportedSubsequentWrites,nextOperationReserve=0){
 for(const n of [reportedSubsequentWrites,nextOperationReserve])assert.ok(Number.isSafeInteger(n)&&n>=0);
 const accounted=failedImportReserve+reportedSubsequentWrites;
 assert.ok(accounted+nextOperationReserve<=1000000,'Combined write cap including failed-import reserve');
 return {failed_import_billable_writes:'unknown',failed_import_reserved_writes:failedImportReserve,accounted_writes:accounted,remaining_writes:1000000-accounted};
}
