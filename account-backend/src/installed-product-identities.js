// Reviewed Windows display-name aliases. Only whole product names match;
// architecture/language/version suffixes are allowed for specific installers.
// Provenance and exclusions: docs/installed-product-assessment.md.
export const installedProductRules=[
 [/^google chrome$/,'a','google','chrome','googlechrome'],
 [/^microsoft edge$/,'a','microsoft','edge_chromium',''],
 [/^mozilla firefox(?: \((?:x64|x86|arm64)(?: [a-z]{2}(?:-[a-z]{2})?)?\))?$/,'a','mozilla','firefox','firefox'],
 [/^filezilla(?: client)?(?: \d+(?:\.\d+){1,3})?$/,'a','filezilla-project','filezilla_client',''],
 [/^forti(?:net )?client$/,'a','fortinet','forticlient','fortinet'],
 [/^eset endpoint security$/,'a','eset','endpoint_security',''],
 [/^keepass(?: password safe)?(?: \d+(?:\.\d+){1,3})?$/,'a','keepass','keepass',''],
 [/^notepad\+\+(?: \((?:64-bit x64|32-bit x86|64-bit|32-bit|arm64)\))?$/,'a','notepad-plus-plus','notepad\\+\\+',''],
 [/^adguard$/,'a','adguard','adguard',''],
 [/^microsoft onedrive$/,'a','microsoft','onedrive',''],
 [/^python \d+\.\d+\.\d+ core interpreter \((?:64|32)-bit\)$/,'a','python','python','python'],
];
