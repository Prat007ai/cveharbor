// esbuild injects this symbol into every backend source module for staging only.
// No real network call occurs, even if a mail credential is mistakenly supplied.
export async function fetch() {
  throw new Error('Outbound providers are disabled in the initial staging build');
}
