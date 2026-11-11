// Azure Retail Prices API, USD, Foundry Models / East US / GPT 5.4 mini / Data Zone.
// Integer picodollars avoid rounding away small charges. 1 USD = 10^12 units.
export const USD = 1_000_000_000_000;
export const ALLOWANCE = 20 * USD;
export const INPUT_CEILING = 32768;
export const OUTPUT_CEILING = 1024;
export const PRICE = Object.freeze({id:'azure-eastus-dz-gpt54mini-20261111',
 model:'gpt-5.4-mini-2026-03-17', input:825000, cached:82500, output:4950000,
 validFrom:'2026-11-11T00:00:00Z', validUntil:'2026-12-12T00:00:00Z'});
export const RESERVATION = INPUT_CEILING * PRICE.input + OUTPUT_CEILING * PRICE.output;
export function charge(usage, price=PRICE) {
 const {input_tokens:i,output_tokens:o,cached_input_tokens:c=0,reasoning_tokens:r=0}=usage||{};
 if(![i,o,c,r].every(n=>Number.isSafeInteger(n)&&n>=0)||c>i||r>o||i>INPUT_CEILING||o>OUTPUT_CEILING)throw Error('Unverifiable AI usage');
 const cost=(i-c)*price.input+c*price.cached+o*price.output;
 if(!Number.isSafeInteger(cost)||cost<0||cost>RESERVATION)throw Error('Unverifiable AI charge');
 return cost;
}
export function priceCurrent(now=Date.now()) {return now>=Date.parse(PRICE.validFrom)&&now<Date.parse(PRICE.validUntil);}
export function period(now=Date.now()){return new Date(now).toISOString().slice(0,7);}
export function summary(row,month){return {month,currency:'USD',allowance_usd:20,
 spent_usd:(row?.spent||0)/USD,reserved_usd:(row?.reserved||0)/USD,
 available_usd:(ALLOWANCE-(row?.spent||0)-(row?.reserved||0))/USD};}
