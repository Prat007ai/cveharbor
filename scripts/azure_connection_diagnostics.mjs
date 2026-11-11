// Record only a fixed operation label and HTTP status, never URLs, bodies or headers.
export function diagnosticFetch(report, setStage, fetcher = fetch) {
  return async (input, options) => {
    const url = new URL(input);
    let operation = 'release_network_check';
    if (url.hostname === 'api.cveharbor.com') {
      operation = ({'/v1/release-readiness':'production_readiness', '/v1/health':'production_health',
        '/v1/me':'anonymous_account_boundary'})[url.pathname] || operation;
    } else if (url.hostname === 'api.cloudflare.com') {
      if (/\/d1\/database\/[a-f0-9-]+$/.test(url.pathname)) operation = 'cloudflare_database_identity';
      else if (url.pathname.endsWith('/query')) operation = 'cloudflare_database_read';
      else if (url.pathname.endsWith('/settings')) operation = 'cloudflare_worker_settings';
      else if (url.pathname.endsWith('/deployments')) operation = 'cloudflare_deployment_history';
      else if (url.pathname.includes('/versions/')) operation = 'cloudflare_previous_version';
    }
    setStage(operation);
    delete report.last_http_status;
    const response = await fetcher(input, options);
    report.last_http_status = response.status;
    return response;
  };
}
