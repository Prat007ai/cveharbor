export const CONFIRM_ORIGIN='https://confirm.cveharbor.com';
export const API_ORIGIN='https://api.cveharbor.com';
export const LEGACY_PREFIX='/v1/acknowledge/';
export const CONFIRM_PREFIX='/acknowledge/';
export function acknowledgementLink(env,token){
 const origin=env.ASSIGNMENT_CONFIRM_ORIGIN;
 if(origin&&origin!==CONFIRM_ORIGIN&&origin!==API_ORIGIN)throw Error('Confirmation hostname is not configured correctly');
 return (origin===CONFIRM_ORIGIN?CONFIRM_ORIGIN+CONFIRM_PREFIX:API_ORIGIN+LEGACY_PREFIX)+token;
}
export function confirmationRequest(url){
 if(url.protocol!=='https:')return null;
 if(url.origin===CONFIRM_ORIGIN&&url.pathname.startsWith(CONFIRM_PREFIX))return {origin:CONFIRM_ORIGIN,token:url.pathname.slice(CONFIRM_PREFIX.length)};
 if(url.origin===API_ORIGIN&&url.pathname.startsWith(LEGACY_PREFIX))return {origin:API_ORIGIN,token:url.pathname.slice(LEGACY_PREFIX.length)};
 return null;
}
