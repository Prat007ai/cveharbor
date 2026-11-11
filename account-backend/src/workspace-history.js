// Account aggregates only: never infer confirmed exposure or backfill earlier days.
export const historyTable = 'workspace_finding_daily_snapshots';
export const historyFields = ['needs_review', 'in_progress', 'fixed', 'accepted_risk', 'not_applicable'];

// One atomic INSERT SELECT gives every included account a consistent observation.
// The primary key makes duplicate hourly deliveries safe without changing history.
export const captureSQL = `WITH
 owned_assets AS (
  SELECT a.id,a.user_id FROM inventory_assets a
  JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id
  JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id
 ), findings AS (
  SELECT s.user_id,
   SUM(s.status='Needs Review') needs_review,
   SUM(s.status='Fix in Progress') in_progress,
   SUM(s.status='Fixed/Patched') fixed,
   SUM(s.status='Accepted Risk') accepted_risk,
   SUM(s.status='Not Applicable') not_applicable
  FROM customer_finding_statuses s JOIN owned_assets a ON a.id=s.asset_id AND a.user_id=s.user_id
  GROUP BY s.user_id
 ), inventory AS (SELECT user_id,COUNT(*) n FROM owned_assets GROUP BY user_id)
 INSERT INTO workspace_finding_daily_snapshots
 (user_id,day,captured_at,metric_version,needs_review,in_progress,fixed,accepted_risk,not_applicable,inventory_records)
 SELECT u.id,date('now'),strftime('%Y-%m-%dT%H:%M:%fZ','now'),1,
  COALESCE(f.needs_review,0),COALESCE(f.in_progress,0),COALESCE(f.fixed,0),
  COALESCE(f.accepted_risk,0),COALESCE(f.not_applicable,0),COALESCE(i.n,0)
 FROM users u LEFT JOIN findings f ON f.user_id=u.id LEFT JOIN inventory i ON i.user_id=u.id
 WHERE NOT EXISTS (SELECT 1 FROM workspace_finding_daily_snapshots h WHERE h.user_id=u.id AND h.day=date('now'))
 ON CONFLICT(user_id,day) DO NOTHING`;

export async function captureWorkspaceHistory(env) {
 if (env.WORKSPACE_HISTORY_ENABLED !== 'true') return {enabled:false};
 // Called only inside recoveryProtected's scheduled lease. Database time chooses
 // the actual observation day, even when the scheduled event arrives late.
 const result = await env.DB.prepare(captureSQL).run();
 if (result.success === false) throw Error('Workspace daily snapshot failed');
 return {enabled:true,created:result.meta?.changes ?? null};
}

export async function readWorkspaceHistory(env, userId) {
 if (env.WORKSPACE_HISTORY_ENABLED !== 'true') return {available:false,reason:'not_enabled',rows:[]};
 try {
  const result = await env.DB.prepare(`SELECT day,captured_at,metric_version,
   needs_review,in_progress,fixed,accepted_risk,not_applicable,inventory_records
   FROM workspace_finding_daily_snapshots
   WHERE user_id=? AND day>=date('now','-29 days') AND day<=date('now')
   ORDER BY day`).bind(userId).all();
  if (result.success === false) throw Error('History unavailable');
  return {available:true,scope:'account',metric:'saved_finding_statuses',metric_version:1,
   days:30,time_zone:'UTC',generated_at:new Date().toISOString(),rows:result.results || []};
 } catch {
  return {available:false,reason:'read_failed',rows:[]};
 }
}
