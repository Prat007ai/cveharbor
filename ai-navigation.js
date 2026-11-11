// Fetch privileges afresh; never infer platform access from an organization role.
import {api,element} from './ai-common.js';
try{const caps=await api('/ai/capabilities'),nav=document.querySelector('.account-hero-header');if(caps.admin&&nav){const a=element('a','AI usage administration','account-back-link');a.href='/admin/ai-usage/';nav.append(a);}}catch{/* Existing account settings remain available when AI is disabled. */}
