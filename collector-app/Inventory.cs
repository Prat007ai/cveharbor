using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace CVEHarbor.Collector
{
    public sealed class Product
    {
        public string Technology { get; set; }
        public string Version { get; set; }
        public string Details { get; set; }
    }
    public sealed class Address
    {
        public string ip { get; set; }
        public int prefix { get; set; }
        public string state { get; set; }
        public bool skip_source { get; set; }
    }
    public sealed class Adapter
    {
        public string id { get; set; }
        public string name { get; set; }
        public string status { get; set; }
        public List<Address> addresses { get; set; }
    }
    public sealed class Primary
    {
        public string adapter_id { get; set; }
        public string ip { get; set; }
    }
    public sealed class Snapshot
    {
        public string Hostname { get; set; }
        public string CollectedUtc { get; set; }
        public bool Demo { get; set; }
        public bool Incomplete { get; set; }
        public List<Product> Products = new List<Product>();
        public List<Adapter> Adapters = new List<Adapter>();
        public List<string> Warnings = new List<string>();
        public void Add(string name, string version, string details)
        {
            name = Exporter.Safe(name); version = Exporter.Safe(version);
            if (name.Length == 0) return;
            if (name.Length > 120 || version.Length > 80)
            { Incomplete=true; Warnings.Add("An overlong product name or version was excluded. Review the source inventory."); return; }
            if (Products.Any(p => String.Equals(p.Technology, name, StringComparison.OrdinalIgnoreCase) && String.Equals(p.Version, version, StringComparison.OrdinalIgnoreCase))) return;
            Products.Add(new Product { Technology = name, Version = version, Details = Exporter.Safe(details) });
            if (version.Length == 0) Warnings.Add("Version unavailable: " + name);
        }
    }
    public static class Inventory
    {
        public static readonly string[] Roles = { "Web", "Database", "Application", "Active Directory", "File", "Print", "Remote Desktop", "Other" };
        public static readonly string[] Coverage = {
            "Read-only local inventory. No upload, AI request, port scan or vulnerability scan.",
            "Programs and Features: machine 32/64-bit records and the executing user. Other user profiles, Store apps, containers, portable software and bundled runtimes may be missing.",
            "Directory discovery does not prove that a runtime is actively used. Windows and .NET Framework patch applicability needs vendor/build evidence.",
            "Network data is a snapshot of adapters exposed by Windows. Primary selection is an import suggestion; an existing dashboard primary choice is preserved.",
            "Imports are additive. Review obsolete versions manually. Choose the correct customer and environment before uploading."
        };
        public static string FrameworkVersion(int release)
        {
            int[] numbers = {533320,528040,461808,461308,460798,394802,394254,393295,379893,378675,378389};
            string[] versions = {"4.8.1","4.8","4.7.2","4.7.1","4.7","4.6.2","4.6.1","4.6","4.5.2","4.5.1","4.5"};
            for (int i=0;i<numbers.Length;i++) if (release>=numbers[i]) return versions[i];
            return "";
        }
        public static void Installed(Snapshot s, string name, string version, string publisher, string date, string source)
        {
            string[] patterns = {
                @"^Microsoft (?:\.NET|\.NET Core) Runtime - ([0-9.]+)(?: \((?:x64|x86|arm64)\))?$",
                @"^Microsoft (?:ASP\.NET Core|\.NET) (?:Windows )?Desktop Runtime - ([0-9.]+)(?: \((?:x64|x86|arm64)\))?$",
                @"^Microsoft ASP\.NET Core ([0-9.]+) - Shared Framework(?: \((?:x64|x86|arm64)\))?$",
                @"^Microsoft \.NET SDK ([0-9.]+)(?: \((?:x64|x86|arm64)\))?$"
            };
            string[] names = {".NET Runtime", ".NET Desktop Runtime", "ASP.NET Core Runtime", ".NET SDK"};
            for (int i=0;i<patterns.Length;i++) { Match m=Regex.Match(name ?? "",patterns[i]); if(m.Success){name=names[i];version=m.Groups[1].Value;break;} }
            s.Add(name, version, "Publisher: "+publisher+"; source: "+source+"; installed: "+date+"; collected UTC: "+s.CollectedUtc);
        }
        static string Read(RegistryKey k,string name) { return Convert.ToString(k.GetValue(name, "")); }
        static void Software(Snapshot s, bool machineOnly)
        {
            foreach (RegistryHive hive in machineOnly?new[]{RegistryHive.LocalMachine}:new[]{RegistryHive.LocalMachine,RegistryHive.CurrentUser})
            foreach (RegistryView view in new[]{RegistryView.Registry64,RegistryView.Registry32})
            {
                try { using(var root=RegistryKey.OpenBaseKey(hive,view)) using(var key=root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                { if(key==null)continue; foreach(string child in key.GetSubKeyNames()) try { using(var item=key.OpenSubKey(child)) if(item!=null) Installed(s,Read(item,"DisplayName"),Read(item,"DisplayVersion"),Read(item,"Publisher"),Read(item,"InstallDate"),hive+"/"+view+" Programs and Features"); } catch(Exception ex) { s.Incomplete=true; s.Warnings.Add("An installed-software record could not be read: "+ex.GetType().Name); } }
                } catch(Exception ex){s.Incomplete=true;s.Warnings.Add("Software registry view unavailable: "+hive+"/"+view+" ("+ex.GetType().Name+")");}
            }
        }
        static void WalkFramework(Snapshot s, RegistryKey key, bool modern, string path)
        {
            int release; Int32.TryParse(Read(key,"Release"), out release);
            if(release>0 && path.EndsWith(@"\Full",StringComparison.OrdinalIgnoreCase))
                s.Add(".NET Framework",FrameworkVersion(release),"Registry release: "+release+"; framework family, not Windows patch level.");
            else if(Read(key,"Install")=="1" && Read(key,"Version")!="" && release==0 && !(modern && path.StartsWith(@"v4\",StringComparison.OrdinalIgnoreCase)) && !Regex.IsMatch(path.Split('\\').Last(),@"^\d+$"))
                s.Add(".NET Framework",Read(key,"Version"),"Framework registry version; verify patch applicability.");
            foreach(string sub in key.GetSubKeyNames()) using(var child=key.OpenSubKey(sub)) if(child!=null) WalkFramework(s,child,modern,path==""?sub:path+"\\"+sub);
        }
        static void Frameworks(Snapshot s)
        {
            try { using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)) using(var ndp=root.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP"))
                if(ndp!=null) { bool modern; using(var full=ndp.OpenSubKey(@"v4\Full")) modern=full!=null && full.GetValue("Release")!=null; WalkFramework(s,ndp,modern,""); }
            } catch(Exception ex){s.Incomplete=true;s.Warnings.Add(".NET Framework inventory incomplete: "+ex.GetType().Name);}
            var roots=new List<string>();
            foreach(string variable in new[]{"ProgramW6432","ProgramFiles","ProgramFiles(x86)"}) {string v=Environment.GetEnvironmentVariable(variable);if(!String.IsNullOrEmpty(v))roots.Add(Path.Combine(v,"dotnet"));}
            roots.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),".dotnet"));
            string custom=Environment.GetEnvironmentVariable("DOTNET_ROOT");if(!String.IsNullOrEmpty(custom))roots.Add(custom);
            string[] folders={@"shared\Microsoft.NETCore.App",@"shared\Microsoft.AspNetCore.App",@"shared\Microsoft.WindowsDesktop.App","sdk"};
            string[] names={".NET Runtime","ASP.NET Core Runtime",".NET Desktop Runtime",".NET SDK"};
            foreach(string root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if(root.StartsWith(@"\\") || !Path.IsPathRooted(root)){s.Incomplete=true;s.Warnings.Add("Non-local .NET path skipped.");continue;}
                for(int i=0;i<folders.Length;i++) try {
                    string path=Path.Combine(root,folders[i]);if(!Directory.Exists(path))continue;
                    foreach(string dir in Directory.GetDirectories(path)) {string v=Path.GetFileName(dir);if(Regex.IsMatch(v,@"^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$"))s.Add(names[i],v,"Discovered .NET installation directory; verify active usage.");}
                }catch(Exception ex){s.Incomplete=true;s.Warnings.Add("A .NET installation directory could not be read: "+ex.GetType().Name);}
            }
        }
        static void Network(Snapshot s)
        {
            try { foreach(var nic in NetworkInterface.GetAllNetworkInterfaces()) try {
                var adapter=new Adapter{id=nic.Id,name=nic.Name,status=nic.OperationalStatus.ToString(),addresses=new List<Address>()};
                foreach(var a in nic.GetIPProperties().UnicastAddresses)
                {
                    if(a.Address.AddressFamily!=AddressFamily.InterNetwork && a.Address.AddressFamily!=AddressFamily.InterNetworkV6)continue;
                    string ip=a.Address.ToString().Split('%')[0];
                    if(adapter.addresses.Any(p=>p.ip==ip))continue;
                    adapter.addresses.Add(new Address{ip=ip,prefix=a.PrefixLength,state=a.DuplicateAddressDetectionState.ToString(),skip_source=false});
                }
                s.Adapters.Add(adapter);
            }catch(Exception ex){s.Incomplete=true;s.Warnings.Add("An adapter could not be fully collected: "+ex.GetType().Name);}
            }catch(Exception ex){s.Incomplete=true;s.Warnings.Add("Network inventory unavailable: "+ex.GetType().Name);}
        }
        public static Snapshot Collect(Action<string> progress, bool machineOnly=false)
        {
            var s=new Snapshot{Hostname=Environment.MachineName,CollectedUtc=DateTime.UtcNow.ToString("o")};
            progress("Reading Windows edition and build...");
            try { using(var search=new ManagementObjectSearcher("SELECT Caption,Version,OSArchitecture FROM Win32_OperatingSystem")) using(var results=search.Get())
                foreach(ManagementObject os in results) using(os) {
                    string caption=Convert.ToString(os["Caption"]),version=Convert.ToString(os["Version"]),display="";
                    using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)) using(var cv=root.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                    if(cv!=null){string ubr=Read(cv,"UBR");if(ubr!="")version+="."+ubr;display=Read(cv,"DisplayVersion");}
                    s.Add(caption.IndexOf("Windows Server",StringComparison.OrdinalIgnoreCase)>=0?"Windows Server":"Windows",version,"Edition: "+caption+"; display version: "+display+"; architecture: "+os["OSArchitecture"]+"; collected UTC: "+s.CollectedUtc);
                }
            }catch(Exception ex){s.Incomplete=true;s.Warnings.Add("Operating system inventory incomplete: "+ex.GetType().Name);}
            progress("Reading installed software (Programs and Features)..."); Software(s,machineOnly);
            progress("Reading .NET runtimes, SDKs and IIS..."); Frameworks(s);
            try {using(var root=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,RegistryView.Registry64)) using(var iis=root.OpenSubKey(@"SOFTWARE\Microsoft\InetStp"))
                if(iis!=null && Read(iis,"MajorVersion")!="")s.Add("IIS",Read(iis,"MajorVersion")+"."+Read(iis,"MinorVersion"),"IIS version; Windows build and patch evidence are also required.");
            }catch(Exception ex){s.Incomplete=true;s.Warnings.Add("IIS inventory unavailable: "+ex.GetType().Name);}
            progress("Reading network adapters and addresses..."); Network(s);
            s.Products=s.Products.OrderBy(p=>p.Technology,StringComparer.OrdinalIgnoreCase).ThenBy(p=>p.Version,StringComparer.OrdinalIgnoreCase).ToList();return s;
        }
        public static Snapshot Fictional()
        {
            var s=new Snapshot{Hostname="NORTHSTAR-WEB01",CollectedUtc="2026-11-12T12:00:00Z",Demo=true};
            s.Add("Windows Server","10.0.20348.1","Fictional example; not a recommended patch level.");
            Installed(s,"Microsoft .NET Runtime - 8.0.1 (x64)","8.0.1","Microsoft","","Fictional fixture");
            Installed(s,"Microsoft .NET Runtime - 8.0.2 (x64)","8.0.2","Microsoft","","Fictional fixture");
            s.Add("ASP.NET Core Runtime","8.0.2","Fictional example");s.Add("IIS","10.0","Fictional example");s.Add("Northstar Example Software","","Fictional example with missing version");
            s.Adapters.Add(new Adapter{id="demo-lan",name="Production LAN",status="Up",addresses=new List<Address>{new Address{ip="192.0.2.47",prefix=24,state="Preferred"},new Address{ip="192.0.2.48",prefix=24,state="Preferred"},new Address{ip="2001:db8::47",prefix=64,state="Preferred"}}});
            s.Adapters.Add(new Adapter{id="demo-backup",name="Backup network",status="Up",addresses=new List<Address>{new Address{ip="198.51.100.47",prefix=24,state="Preferred"}}});
            s.Adapters.Add(new Adapter{id="demo-offline",name="Disconnected adapter",status="Down",addresses=new List<Address>()});return s;
        }
    }
    public static class Exporter
    {
        public const int MaxRows=10000,MaxBytes=10485760;
        public static string Safe(string value)
        {
            string s=Regex.Replace(value??"",@"[\x00-\x1f\x7f]"," ").Trim();
            return Regex.IsMatch(s,@"^[=+@-]")?"'"+s:s;
        }
        static string Csv(string value){return "\""+(value??"").Replace("\"","\"\"")+"\"";}
        public static object Network(Snapshot s, Primary primary)
        {
            if(primary!=null && !s.Adapters.Any(a=>a.id==primary.adapter_id && a.addresses.Any(p=>p.ip==primary.ip)))throw new InvalidOperationException("Select a primary IP present in this collection.");
            return new {version=1,collected_at=s.CollectedUtc,adapters=s.Adapters,suggested=primary};
        }
        public static string BuildCsv(Snapshot s,string[] roles,Primary primary)
        {
            roles=roles.Distinct().ToArray();
            if(roles.Length==0 || roles.Any(r=>!Inventory.Roles.Contains(r)))throw new InvalidOperationException("Select at least one server role.");
            if(s.Products.Count==0 || s.Products.Count>MaxRows)throw new InvalidOperationException("Export requires 1 to 10,000 inventory entries. No file was written.");
            string host=Safe(s.Hostname);if(host.Length==0||host.Length>120)throw new InvalidOperationException("Hostname exceeds the import limit.");
            var serializer=new JavaScriptSerializer{MaxJsonLength=MaxBytes};string network="";
            if(s.Adapters.Count>0){network=serializer.Serialize(Network(s,primary));
                if(network.Length>14000 || s.Adapters.Count>32 || s.Adapters.Sum(a=>a.addresses.Count)>128 || s.Adapters.Any(a=>a.addresses.Count>64||String.IsNullOrEmpty(a.id)||a.id.Length>80||String.IsNullOrEmpty(a.name)||a.name.Length>120||a.status.Length>32))throw new InvalidOperationException("Network inventory exceeds the CSV import limits. No CSV was written; review the adapter count or contact support.");}
            var text=new StringBuilder("\"Asset Name\",\"Asset Type\",\"Technology\",\"Version\",\"Notes\",\"Server Network\"\r\n");
            int n=0;foreach(var p in s.Products){string notes=Safe("Server role: "+String.Join(" / ",roles)+"; "+p.Details);if(notes.Length>500)notes=notes.Substring(0,500);
                text.AppendLine(String.Join(",",new[]{Csv(host),Csv("Server"),Csv(p.Technology),Csv(p.Version),Csv(notes),Csv(n++==0?network:"")}));}
            string result=text.ToString();if(Encoding.UTF8.GetByteCount(result)+3>MaxBytes)throw new InvalidOperationException("Inventory exceeds the 10 MB upload limit. No CSV was written.");return result;
        }
        public static string Save(Snapshot s,string[] roles,Primary primary,string parent)
        {
            string csv=BuildCsv(s,roles,primary);
            if(!Path.IsPathRooted(parent)||!Directory.Exists(parent))throw new InvalidOperationException("Choose an existing output folder.");
            string output=Path.Combine(parent,"CVEHarbor-Inventory-"+DateTime.UtcNow.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,8));
            Directory.CreateDirectory(output);
            try{
                var serializer=new JavaScriptSerializer{MaxJsonLength=MaxBytes};
                string report=serializer.Serialize(new {collector_version="windows-app-1.0.0",asset_name=Safe(s.Hostname),collected_utc=s.CollectedUtc,server_roles=roles,entries=s.Products.Count,files=new[]{"cveharbor-assets.csv"},network=Network(s,primary),warnings=s.Warnings,coverage=Inventory.Coverage,fixture_mode=s.Demo});
                using(var f=new FileStream(Path.Combine(output,"collection-report.json"),FileMode.CreateNew))using(var w=new StreamWriter(f,new UTF8Encoding(true)))w.Write(report);
                // CSV is published only after the report is safely written.
                string temporary=Path.Combine(output,"inventory.tmp");
                using(var f=new FileStream(temporary,FileMode.CreateNew))using(var w=new StreamWriter(f,new UTF8Encoding(true)))w.Write(csv);
                File.Move(temporary,Path.Combine(output,"cveharbor-assets.csv"));return output;
            }catch(Exception ex){throw new IOException("Export did not finish. Any incomplete files are in "+output+". Choose a writable folder and export again.",ex);}
        }
    }
}
