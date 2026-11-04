// Approved Task 2C targets. Never derive these from the production configuration.
export const TARGET = Object.freeze({
  account: '9706b4d98ad72884e67fd1eb875c8a61',
  api: 'cveharbor-accounts-staging',
  site: 'cveharbor-site-staging',
  database: 'cveharbor-accounts-staging',
  origin: 'https://cveharborstage.com',
  productionDatabase: '46710e51-7ca4-4571-b89c-921b9969de0b',
  compatibility: '2026-10-28',
});
export function databaseId(value) {
  if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value || '') || value.toLowerCase() === TARGET.productionDatabase)
    throw Error('A newly created staging D1 UUID is required; production is forbidden.');
  return value;
}
export function accessSettings(issuer, audience) {
  if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(issuer || '') || !/^[a-f0-9]{64}$/i.test(audience || ''))
    throw Error('Set the staging Access team issuer and application AUD before configuration.');
  return { ACCESS_ISSUER: issuer, ACCESS_AUD: audience };
}

// Retained only for authenticated backend readiness during the existing-Worker transition.
export const LEGACY_ORIGIN='https://cveharbor-site-staging.cveharbor-staging.workers.dev';
