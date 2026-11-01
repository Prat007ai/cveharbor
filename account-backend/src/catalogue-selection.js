// Catalogue selection is independent from inventory and watchlist subscriptions.
import {normalizeName} from './product-identity.js';
export function catalogueProducts(preferences={}){
 const selected=new Map((preferences.defaults||[]).map(name=>[normalizeName(name),{name}]));
 for(const product of preferences.products||[])if(product.enabled!==false)selected.set(normalizeName(product.name),product);
 return [...selected.values()];
}
export async function catalogueRevision(payload){
 if(payload===null)return 'none';
 return [...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(payload)))].map(n=>n.toString(16).padStart(2,'0')).join('');
}
export function catalogueAllows(p='p'){
 // New saves contain normalized keys; legacy saves remain readable without migration.
 return `(NOT EXISTS(SELECT 1 FROM user_technology_catalogue c WHERE c.user_id=${p}.user_id) OR EXISTS(
 SELECT 1 FROM user_technology_catalogue c WHERE c.user_id=${p}.user_id AND (
 EXISTS(SELECT 1 FROM json_each(c.preferences_json,'$.selection_keys') k WHERE k.value=${p}.name_key)
 OR (json_type(c.preferences_json,'$.selection_keys') IS NULL AND (
 EXISTS(SELECT 1 FROM json_each(c.preferences_json,'$.defaults') k WHERE lower(trim(k.value))=${p}.name_key)
 OR EXISTS(SELECT 1 FROM json_each(c.preferences_json,'$.products') k WHERE lower(trim(json_extract(k.value,'$.name')))=${p}.name_key AND COALESCE(json_extract(k.value,'$.enabled'),1)<>0))))))`;
}
export function activeSubscription(p='p',scope='all'){
 if(!['all','catalogue','inventory','stack'].includes(scope))throw Error('Invalid CVIE scope');
 return `EXISTS(SELECT 1 FROM cvie_subscriptions s WHERE s.product_id=${p}.id AND s.user_id=${p}.user_id ${scope==='all'?'':`AND s.origin='${scope}'`} AND (s.origin<>'catalogue' OR ${catalogueAllows(p)}))`;
}
