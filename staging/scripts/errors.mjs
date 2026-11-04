// Only errors created here can contribute structured evidence. Never serialize
// arbitrary error messages, causes, subprocess output or Cloudflare response text.
const evidence = new WeakMap();
export function failure(operation, category, details = {}, cause) {
  if (cause && evidence.has(cause)) return cause;
  const error = new Error('Staging operation stopped; see sanitized evidence.');
  evidence.set(error, { operation, category, ...details });
  return error;
}
export function safeFailure(error) {
  return evidence.get(error) || { operation: 'provisioning', category: 'unknown' };
}
export function wranglerCategory(result) {
  if (result.error) return result.error.code === 'ETIMEDOUT' ? 'subprocess_timeout' : 'subprocess_start';
  // Match locally, then discard all text. Only fixed categories leave this module.
  const text = String(result.stderr || '') + String(result.stdout || '');
  if (/authentication error|not authorized|unauthorized|permission denied|code:\s*(?:10000|9109)\b/i.test(text)) return 'authorization';
  if (/invalid.*config|configuration.*invalid|unexpected.*(?:field|binding)|invalid.*binding/i.test(text)) return 'configuration';
  if (/build failed|could not resolve|syntaxerror/i.test(text)) return 'build';
  if (/fetch failed|network|ENOTFOUND|ECONNRESET|ETIMEDOUT/i.test(text)) return 'network';
  return 'wrangler_exit';
}

// Inspect provider text only in memory; emit fixed categories and numeric codes.
export function providerCategory(status, payload) {
  if(status===401||status===403)return 'authorization';
  if(status===429)return 'rate_limit';
  const text=JSON.stringify(payload?.errors||[]);
  if(/(?:missing|required|must provide).{0,40}sql|sql.{0,40}(?:missing|required|must be)/i.test(text))return 'missing_sql';
  if(/too many terms in compound select/i.test(text))return 'compound_select_limit';
  if(/no such table/i.test(text))return 'missing_table';
  if(/no such column/i.test(text))return 'missing_column';
  if(/foreign key constraint/i.test(text))return 'foreign_key_constraint';
  if(/unique constraint/i.test(text))return 'unique_constraint';
  return 'cloudflare_api';
}
export function diagnosticTransport(operation, transport=fetch) {
  return async (...args)=>{
    let response;try{response=await transport(...args);}catch{throw failure(operation,'network');}
    let payload;try{payload=await response.clone().json();}catch{throw failure(operation,'invalid_json',{http_status:response.status});}
    if(!response.ok||payload?.success!==true)throw failure(operation,providerCategory(response.status,payload),{http_status:response.status,api_codes:(Array.isArray(payload?.errors)?payload.errors:[]).map(e=>e?.code).filter(Number.isInteger).slice(0,8)});
    return response;
  };
}
