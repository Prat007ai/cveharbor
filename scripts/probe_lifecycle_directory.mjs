// Public source reads only. No account writes, subscriptions or email.
import {directoryCycles} from '../account-backend/src/monitor-directory.js';
import {fetchVendor} from '../account-backend/src/monitor-sources.js';
for(const slug of ['drupal','dotnetfx','ubuntu','spring-boot','msexchange']){
 const cycles=directoryCycles(await fetchVendor({url:'https://endoflife.date/api/'+slug+'.json'}));
 console.log(JSON.stringify({slug,release_branches:cycles.length,source:'endoflife.date',writes:0}));
}
