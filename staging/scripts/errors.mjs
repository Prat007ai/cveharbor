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
