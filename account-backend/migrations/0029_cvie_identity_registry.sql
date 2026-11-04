-- Additive registry and minimal source-pointer index. No customer rows are rewritten.
CREATE TABLE cvie_identities (
 identity_id TEXT PRIMARY KEY, vendor TEXT NOT NULL, name TEXT NOT NULL, kind TEXT NOT NULL,
 ecosystem TEXT NOT NULL, version_scheme TEXT NOT NULL, revision INTEGER NOT NULL,
 provenance TEXT NOT NULL, verification_state TEXT NOT NULL DEFAULT 'reviewed', replacement_id TEXT
);
CREATE TABLE cvie_identity_aliases (
 alias TEXT NOT NULL, identity_id TEXT NOT NULL REFERENCES cvie_identities(identity_id),
 provenance TEXT NOT NULL, revision INTEGER NOT NULL, PRIMARY KEY(alias,identity_id)
);
CREATE TABLE cvie_identity_identifiers (
 scheme TEXT NOT NULL,value TEXT NOT NULL,identity_id TEXT NOT NULL REFERENCES cvie_identities(identity_id),
 provenance TEXT NOT NULL,revision INTEGER NOT NULL, PRIMARY KEY(scheme,value,identity_id)
);
CREATE INDEX cvie_identifier_identity ON cvie_identity_identifiers(identity_id,scheme,value);
CREATE TABLE cvie_identity_members (
 parent_id TEXT NOT NULL REFERENCES cvie_identities(identity_id),child_id TEXT NOT NULL REFERENCES cvie_identities(identity_id),
 relationship TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(parent_id,child_id),CHECK(parent_id<>child_id)
);
CREATE TABLE cvie_identity_families (
 family_key TEXT NOT NULL,identity_id TEXT NOT NULL REFERENCES cvie_identities(identity_id),PRIMARY KEY(family_key,identity_id)
);
CREATE INDEX cvie_identity_family_reverse ON cvie_identity_families(identity_id,family_key);
CREATE TABLE cvie_product_identities (
 product_id TEXT PRIMARY KEY REFERENCES cvie_products(id) ON DELETE CASCADE,
 identity_id TEXT REFERENCES cvie_identities(identity_id),source_name TEXT NOT NULL,source_vendor TEXT NOT NULL,source_cpe TEXT NOT NULL,
 revision INTEGER NOT NULL
);
CREATE TABLE cvie_identity_evidence (
 identity_id TEXT NOT NULL REFERENCES cvie_identities(identity_id),cve_id TEXT NOT NULL,
 nvd_scope_id TEXT,cna_affected_json TEXT,sort_date TEXT NOT NULL DEFAULT '',PRIMARY KEY(identity_id,cve_id)
);
CREATE INDEX cvie_identity_evidence_page ON cvie_identity_evidence(identity_id,sort_date DESC,cve_id DESC);
CREATE INDEX cvie_identity_evidence_cve ON cvie_identity_evidence(cve_id,identity_id);
CREATE TABLE cvie_index_state (source TEXT PRIMARY KEY,cursor TEXT NOT NULL DEFAULT '',complete INTEGER NOT NULL DEFAULT 0);
INSERT INTO cvie_index_state(source) VALUES('nvd'),('cna');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('microsoft-dotnet-framework','microsoft','Microsoft .NET Framework','product','','vendor','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('.net','microsoft-dotnet-framework','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('.net framework','microsoft-dotnet-framework','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('dotnet framework','microsoft-dotnet-framework','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('microsoft .net framework','microsoft-dotnet-framework','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*','microsoft-dotnet-framework','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*','microsoft-dotnet-framework');
INSERT INTO cvie_identity_families VALUES('name:microsoft:dotnetframework','microsoft-dotnet-framework');
INSERT INTO cvie_identity_families VALUES('name:microsoft:microsoftnetframework','microsoft-dotnet-framework');
INSERT INTO cvie_identity_families VALUES('name:microsoft:netframework','microsoft-dotnet-framework');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('microsoft-dotnet-runtime','microsoft','Microsoft .NET Runtime','component','','vendor','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('.net','microsoft-dotnet-runtime','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('.net runtime','microsoft-dotnet-runtime','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('dotnet runtime','microsoft-dotnet-runtime','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('microsoft .net runtime','microsoft-dotnet-runtime','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*','microsoft-dotnet-runtime','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*','microsoft-dotnet-runtime');
INSERT INTO cvie_identity_families VALUES('name:microsoft:dotnetruntime','microsoft-dotnet-runtime');
INSERT INTO cvie_identity_families VALUES('name:microsoft:microsoftnetruntime','microsoft-dotnet-runtime');
INSERT INTO cvie_identity_families VALUES('name:microsoft:net','microsoft-dotnet-runtime');
INSERT INTO cvie_identity_families VALUES('name:microsoft:netruntime','microsoft-dotnet-runtime');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('microsoft-aspnet-core','microsoft','Microsoft ASP.NET Core','component','','vendor','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('asp.net core','microsoft-aspnet-core','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('asp.net core runtime','microsoft-aspnet-core','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('microsoft asp.net core','microsoft-aspnet-core','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:microsoft:asp.net_core:*:*:*:*:*:*:*:*','microsoft-aspnet-core','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:microsoft:asp.net_core:*:*:*:*:*:*:*:*','microsoft-aspnet-core');
INSERT INTO cvie_identity_families VALUES('name:microsoft:aspnetcore','microsoft-aspnet-core');
INSERT INTO cvie_identity_families VALUES('name:microsoft:aspnetcoreruntime','microsoft-aspnet-core');
INSERT INTO cvie_identity_families VALUES('name:microsoft:microsoftaspnetcore','microsoft-aspnet-core');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('microsoft-dotnet-sdk','microsoft','Microsoft .NET Core SDK','package','','vendor','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('.net','microsoft-dotnet-sdk','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('.net core sdk','microsoft-dotnet-sdk','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('.net sdk','microsoft-dotnet-sdk','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('microsoft .net core sdk','microsoft-dotnet-sdk','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:microsoft:.net_core_sdk:*:*:*:*:*:*:*:*','microsoft-dotnet-sdk','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:microsoft:.net_core_sdk:*:*:*:*:*:*:*:*','microsoft-dotnet-sdk');
INSERT INTO cvie_identity_families VALUES('name:microsoft:microsoftnetcoresdk','microsoft-dotnet-sdk');
INSERT INTO cvie_identity_families VALUES('name:microsoft:netcoresdk','microsoft-dotnet-sdk');
INSERT INTO cvie_identity_families VALUES('name:microsoft:netsdk','microsoft-dotnet-sdk');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('wordpress-core','wordpress','WordPress Core','product','wordpress','numeric','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('wordpress','wordpress-core','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('wordpress core','wordpress-core','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('lifecycle','wordpress','wordpress-core','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*','wordpress-core','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*','wordpress-core');
INSERT INTO cvie_identity_families VALUES('name:wordpress:wordpress','wordpress-core');
INSERT INTO cvie_identity_families VALUES('name:wordpress:wordpresscore','wordpress-core');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('wordpress-woocommerce','automattic','WooCommerce','package','wordpress','numeric','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('woocommerce','wordpress-woocommerce','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('woocommerce plugin','wordpress-woocommerce','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('wordpress woocommerce','wordpress-woocommerce','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('wordpress-slug','woocommerce','wordpress-woocommerce','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('php','php','PHP','product','','numeric','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('php','php','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('php runtime','php','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('lifecycle','php','php','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:php:php:*:*:*:*:*:*:*:*','php','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:php:php:*:*:*:*:*:*:*:*','php');
INSERT INTO cvie_identity_families VALUES('name:php:php','php');
INSERT INTO cvie_identity_families VALUES('name:php:phpruntime','php');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('python','python','Python','product','','pep440','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('cpython','python','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('python','python','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('python runtime','python','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('lifecycle','python','python','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:python:python:*:*:*:*:*:*:*:*','python','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:python:python:*:*:*:*:*:*:*:*','python');
INSERT INTO cvie_identity_families VALUES('name:python:cpython','python');
INSERT INTO cvie_identity_families VALUES('name:python:python','python');
INSERT INTO cvie_identity_families VALUES('name:python:pythonruntime','python');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('microsoft-windows-server','microsoft','Windows Server','group','','vendor','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('microsoft windows server','microsoft-windows-server','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('windows server','microsoft-windows-server','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('windows server os','microsoft-windows-server','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('microsoft-windows-server-2016','microsoft','Windows Server 2016','release_variant','','vendor','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('microsoft windows server 2016','microsoft-windows-server-2016','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('windows server 2016','microsoft-windows-server-2016','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*','microsoft-windows-server-2016','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*','microsoft-windows-server-2016');
INSERT INTO cvie_identity_families VALUES('name:microsoft:microsoftwindowsserver2016','microsoft-windows-server-2016');
INSERT INTO cvie_identity_families VALUES('name:microsoft:windowsserver2016','microsoft-windows-server-2016');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('microsoft-windows-server-2019','microsoft','Windows Server 2019','release_variant','','vendor','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('microsoft windows server 2019','microsoft-windows-server-2019','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('windows server 2019','microsoft-windows-server-2019','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*','microsoft-windows-server-2019','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*','microsoft-windows-server-2019');
INSERT INTO cvie_identity_families VALUES('name:microsoft:microsoftwindowsserver2019','microsoft-windows-server-2019');
INSERT INTO cvie_identity_families VALUES('name:microsoft:windowsserver2019','microsoft-windows-server-2019');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('microsoft-windows-server-2022','microsoft','Windows Server 2022','release_variant','','vendor','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('microsoft windows server 2022','microsoft-windows-server-2022','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('windows server 2022','microsoft-windows-server-2022','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*','microsoft-windows-server-2022','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*','microsoft-windows-server-2022');
INSERT INTO cvie_identity_families VALUES('name:microsoft:microsoftwindowsserver2022','microsoft-windows-server-2022');
INSERT INTO cvie_identity_families VALUES('name:microsoft:windowsserver2022','microsoft-windows-server-2022');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('microsoft-sql-server','microsoft','SQL Server','product','','vendor','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('microsoft sql server','microsoft-sql-server','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('mssql','microsoft-sql-server','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('sql','microsoft-sql-server','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('sql server','microsoft-sql-server','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*','microsoft-sql-server','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*','microsoft-sql-server');
INSERT INTO cvie_identity_families VALUES('name:microsoft:microsoftsqlserver','microsoft-sql-server');
INSERT INTO cvie_identity_families VALUES('name:microsoft:mssql','microsoft-sql-server');
INSERT INTO cvie_identity_families VALUES('name:microsoft:sqlserver','microsoft-sql-server');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('oracle-mysql','oracle','MySQL','product','','numeric','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('mysql','oracle-mysql','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('oracle mysql','oracle-mysql','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('sql','oracle-mysql','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('lifecycle','mysql','oracle-mysql','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*','oracle-mysql','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*','oracle-mysql');
INSERT INTO cvie_identity_families VALUES('name:oracle:mysql','oracle-mysql');
INSERT INTO cvie_identity_families VALUES('name:oracle:oraclemysql','oracle-mysql');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('mariadb','mariadb','MariaDB','product','','numeric','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('mariadb','mariadb','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('mariadb server','mariadb','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('sql','mariadb','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('lifecycle','mariadb','mariadb','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*','mariadb','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*','mariadb');
INSERT INTO cvie_identity_families VALUES('name:mariadb:mariadb','mariadb');
INSERT INTO cvie_identity_families VALUES('name:mariadb:mariadbserver','mariadb');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('ubuntu','canonical','Ubuntu','product','','debian','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('canonical ubuntu','ubuntu','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('linux','ubuntu','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('ubuntu','ubuntu','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('ubuntu linux','ubuntu','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('lifecycle','ubuntu','ubuntu','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*','ubuntu','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*','ubuntu');
INSERT INTO cvie_identity_families VALUES('name:canonical:canonicalubuntu','ubuntu');
INSERT INTO cvie_identity_families VALUES('name:canonical:ubuntu','ubuntu');
INSERT INTO cvie_identity_families VALUES('name:canonical:ubuntulinux','ubuntu');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('debian','debian','Debian','product','','debian','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('debian','debian','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('debian linux','debian','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('gnu/linux debian','debian','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('linux','debian','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('lifecycle','debian','debian','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*','debian','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:o:debian:debian_linux:*:*:*:*:*:*:*:*','debian');
INSERT INTO cvie_identity_families VALUES('name:debian:debian','debian');
INSERT INTO cvie_identity_families VALUES('name:debian:debianlinux','debian');
INSERT INTO cvie_identity_families VALUES('name:debian:gnulinuxdebian','debian');
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance) VALUES('drupal','drupal','Drupal','product','','numeric','1','https://nvd.nist.gov/products/cpe/search');
INSERT INTO cvie_identity_aliases VALUES('drupal','drupal','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_aliases VALUES('drupal cms','drupal','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('lifecycle','drupal','drupal','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_identifiers VALUES('cpe','cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*','drupal','https://nvd.nist.gov/products/cpe/search','1');
INSERT INTO cvie_identity_families VALUES('cpe:cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*','drupal');
INSERT INTO cvie_identity_families VALUES('name:drupal:drupal','drupal');
INSERT INTO cvie_identity_families VALUES('name:drupal:drupalcms','drupal');
INSERT INTO cvie_identity_members VALUES('microsoft-windows-server','microsoft-windows-server-2016','release_variant',1);
INSERT INTO cvie_identity_members VALUES('microsoft-windows-server','microsoft-windows-server-2019','release_variant',1);
INSERT INTO cvie_identity_members VALUES('microsoft-windows-server','microsoft-windows-server-2022','release_variant',1);

-- Projection changes commit atomically with their source rows. No request-time JSON joins.
-- Populate the initial page key in the insert, avoiding a second row/index write.
CREATE TRIGGER cvie_fast_nvd_insert AFTER INSERT ON cvie_shared_advisories BEGIN
 INSERT INTO cvie_identity_evidence(identity_id,cve_id,nvd_scope_id,sort_date)
 SELECT i.identity_id,NEW.cve_id,NEW.scope_id,
 CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=NEW.cve_id AND d.state='REJECTED') THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=NEW.cve_id) THEN '9999-12-31T23:59:59.999Z' ELSE NEW.published END
 FROM cvie_shared_scopes s JOIN cvie_identity_identifiers i ON i.scheme='cpe' AND i.value=s.cpe
 WHERE s.id=NEW.scope_id AND json_array_length(json_extract(s.signature,'$[1]'))=1
 ON CONFLICT(identity_id,cve_id) DO UPDATE SET nvd_scope_id=excluded.nvd_scope_id WHERE nvd_scope_id IS NOT excluded.nvd_scope_id;
END;
CREATE TRIGGER cvie_fast_nvd_delete AFTER DELETE ON cvie_shared_advisories BEGIN
 UPDATE cvie_identity_evidence SET nvd_scope_id=NULL WHERE cve_id=OLD.cve_id AND nvd_scope_id=OLD.scope_id;
 DELETE FROM cvie_identity_evidence WHERE cve_id=OLD.cve_id AND nvd_scope_id IS NULL AND cna_affected_json IS NULL;
END;
CREATE TRIGGER cvie_fast_cna_insert AFTER INSERT ON cvie_disclosure_products
 WHEN EXISTS(SELECT 1 FROM cvie_identity_families WHERE family_key=NEW.family_key) BEGIN
 INSERT INTO cvie_identity_evidence(identity_id,cve_id,cna_affected_json,sort_date)
 SELECT i.identity_id,NEW.cve_id,i.affected,
 CASE WHEN d.state='REJECTED' OR NOT EXISTS(SELECT 1 FROM json_each(i.affected) a
  WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
  OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected')) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=NEW.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(d.published,(SELECT n.published FROM cvie_identity_evidence e JOIN cvie_shared_advisories n ON n.scope_id=e.nvd_scope_id AND n.cve_id=e.cve_id WHERE e.identity_id=i.identity_id AND e.cve_id=NEW.cve_id),'') END
 FROM (SELECT f.identity_id,(SELECT json_group_array(json(a.value)) FROM cvie_disclosure_products p
  JOIN cvie_identity_families m ON m.family_key=p.family_key AND m.identity_id=f.identity_id,json_each(p.affected_json) a
  WHERE p.cve_id=NEW.cve_id) AS affected FROM cvie_identity_families f WHERE f.family_key=NEW.family_key) i
 JOIN cvie_disclosures d ON d.cve_id=NEW.cve_id WHERE 1
 ON CONFLICT(identity_id,cve_id) DO UPDATE SET cna_affected_json=excluded.cna_affected_json,sort_date=excluded.sort_date
 WHERE cna_affected_json IS NOT excluded.cna_affected_json OR sort_date IS NOT excluded.sort_date;
END;
CREATE TRIGGER cvie_fast_cna_delete AFTER DELETE ON cvie_disclosure_products BEGIN
 UPDATE cvie_identity_evidence SET cna_affected_json=(
  SELECT CASE WHEN COUNT(*)>0 THEN json_group_array(json(a.value)) END FROM cvie_disclosure_products d
  JOIN cvie_identity_families f ON f.family_key=d.family_key AND f.identity_id=cvie_identity_evidence.identity_id,json_each(d.affected_json) a WHERE d.cve_id=OLD.cve_id)
 WHERE cve_id=OLD.cve_id AND identity_id IN(SELECT identity_id FROM cvie_identity_families WHERE family_key=OLD.family_key);
 DELETE FROM cvie_identity_evidence WHERE cve_id=OLD.cve_id AND nvd_scope_id IS NULL AND cna_affected_json IS NULL;
END;

CREATE TRIGGER cvie_fast_sort_link_insert AFTER INSERT ON cvie_identity_evidence BEGIN
 UPDATE cvie_identity_evidence SET sort_date=CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END WHERE identity_id=NEW.identity_id AND cve_id=NEW.cve_id AND sort_date IS NOT (CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END);
END;

CREATE TRIGGER cvie_fast_sort_link_update AFTER UPDATE OF cna_affected_json,nvd_scope_id ON cvie_identity_evidence BEGIN
 UPDATE cvie_identity_evidence SET sort_date=CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END WHERE identity_id=NEW.identity_id AND cve_id=NEW.cve_id AND sort_date IS NOT (CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END);
END;

CREATE TRIGGER cvie_fast_sort_disclosure_revision AFTER UPDATE OF state,published ON cvie_disclosures
 WHEN NEW.state IS NOT OLD.state OR NEW.published IS NOT OLD.published BEGIN
 UPDATE cvie_identity_evidence SET sort_date=CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END WHERE cve_id=NEW.cve_id AND sort_date IS NOT (CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END);
END;

CREATE TRIGGER cvie_fast_sort_kev_add AFTER INSERT ON cvie_kev BEGIN
 UPDATE cvie_identity_evidence SET sort_date=CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END WHERE cve_id=NEW.cve_id AND sort_date IS NOT (CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END);
END;

CREATE TRIGGER cvie_fast_sort_kev_remove AFTER DELETE ON cvie_kev BEGIN
 UPDATE cvie_identity_evidence SET sort_date=CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END WHERE cve_id=OLD.cve_id AND sort_date IS NOT (CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END);
END;

CREATE TRIGGER cvie_fast_sort_nvd_date AFTER UPDATE OF published ON cvie_shared_advisories
 WHEN NEW.published IS NOT OLD.published BEGIN
 UPDATE cvie_identity_evidence SET sort_date=CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END WHERE cve_id=NEW.cve_id AND nvd_scope_id=NEW.scope_id AND sort_date IS NOT (CASE WHEN EXISTS(SELECT 1 FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id AND d.state='REJECTED')
 OR (cna_affected_json IS NOT NULL AND NOT EXISTS(SELECT 1 FROM json_each(cna_affected_json) a WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
 OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected'))) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=cvie_identity_evidence.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(CASE WHEN cna_affected_json IS NOT NULL THEN (SELECT published FROM cvie_disclosures d WHERE d.cve_id=cvie_identity_evidence.cve_id) END,
 (SELECT published FROM cvie_shared_advisories n WHERE n.scope_id=cvie_identity_evidence.nvd_scope_id AND n.cve_id=cvie_identity_evidence.cve_id),'') END);
END;

CREATE TRIGGER cvie_fast_cna_update AFTER UPDATE OF applicability,affected_json ON cvie_disclosure_products
 WHEN (NEW.applicability IS NOT OLD.applicability OR NEW.affected_json IS NOT OLD.affected_json)
 AND EXISTS(SELECT 1 FROM cvie_identity_families WHERE family_key=NEW.family_key) BEGIN
 INSERT INTO cvie_identity_evidence(identity_id,cve_id,cna_affected_json,sort_date)
 SELECT i.identity_id,NEW.cve_id,i.affected,
 CASE WHEN d.state='REJECTED' OR NOT EXISTS(SELECT 1 FROM json_each(i.affected) a
  WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
  OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected')) THEN ''
 WHEN EXISTS(SELECT 1 FROM cvie_kev k WHERE k.cve_id=NEW.cve_id) THEN '9999-12-31T23:59:59.999Z'
 ELSE COALESCE(d.published,(SELECT n.published FROM cvie_identity_evidence e JOIN cvie_shared_advisories n ON n.scope_id=e.nvd_scope_id AND n.cve_id=e.cve_id WHERE e.identity_id=i.identity_id AND e.cve_id=NEW.cve_id),'') END
 FROM (SELECT f.identity_id,(SELECT json_group_array(json(a.value)) FROM cvie_disclosure_products p
  JOIN cvie_identity_families m ON m.family_key=p.family_key AND m.identity_id=f.identity_id,json_each(p.affected_json) a
  WHERE p.cve_id=NEW.cve_id) AS affected FROM cvie_identity_families f WHERE f.family_key=NEW.family_key) i
 JOIN cvie_disclosures d ON d.cve_id=NEW.cve_id WHERE 1
 ON CONFLICT(identity_id,cve_id) DO UPDATE SET cna_affected_json=excluded.cna_affected_json,sort_date=excluded.sort_date
 WHERE cna_affected_json IS NOT excluded.cna_affected_json OR sort_date IS NOT excluded.sort_date;
END;

-- Shared local-index work for newly verified long-tail identities; no provider calls.
CREATE INDEX cvie_scope_cpe ON cvie_shared_scopes(cpe,id);
CREATE TABLE cvie_identity_index_jobs (
 identity_id TEXT PRIMARY KEY REFERENCES cvie_identities(identity_id),
 cursor_json TEXT NOT NULL DEFAULT '{}',lease_until INTEGER NOT NULL DEFAULT 0,
 lease_token TEXT NOT NULL DEFAULT '',next_attempt_at INTEGER NOT NULL DEFAULT 0,
 complete INTEGER NOT NULL DEFAULT 0,failed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX cvie_identity_index_due ON cvie_identity_index_jobs(complete,next_attempt_at,lease_until);

-- A package identity is distinct from its runtime family and platform siblings.
INSERT INTO cvie_identities(identity_id,vendor,name,kind,ecosystem,version_scheme,revision,provenance)
 VALUES('microsoft-net-runtime-win-x64-package','microsoft','Microsoft.NETCore.App.Runtime.win-x64','package','nuget','semver',1,'https://www.nuget.org/packages/Microsoft.NETCore.App.Runtime.win-x64/');
INSERT INTO cvie_identity_aliases VALUES('microsoft.netcore.app.runtime.win-x64','microsoft-net-runtime-win-x64-package','https://www.nuget.org/packages/Microsoft.NETCore.App.Runtime.win-x64/',1);
INSERT INTO cvie_identity_identifiers VALUES('purl','pkg:nuget/Microsoft.NETCore.App.Runtime.win-x64','microsoft-net-runtime-win-x64-package','https://www.nuget.org/packages/Microsoft.NETCore.App.Runtime.win-x64/',1);
