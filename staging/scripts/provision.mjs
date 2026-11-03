// Old marked commits cannot authorize a new permanent release operation.
export function authorize(){throw Error('Initial provisioning retired; explicit permanent release approval required.');}
export async function provision(){authorize();}
if(process.argv[1]?.endsWith('/provision.mjs')){console.error('Initial provisioning retired. No cloud operation was attempted.');process.exitCode=1;}
