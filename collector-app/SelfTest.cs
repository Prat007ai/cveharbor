using System;
using System.IO;
using System.Linq;
using System.Text;
namespace CVEHarbor.Collector
{
    internal static class SelfTest
    {
        static void Require(bool ok,string message){if(!ok)throw new Exception(message);}
        static void Reject(Action action,string message){bool rejected=false;try{action();}catch(InvalidOperationException){rejected=true;}Require(rejected,message);}
        public static void Run(string destination)
        {
            destination=Path.GetFullPath(destination);Directory.CreateDirectory(destination);var s=Inventory.Fictional();int original=s.Products.Count;
            Inventory.Installed(s,"Microsoft .NET Runtime - 8.0.2 (x64)","8.0.2","Microsoft","","Duplicate fixture");Require(s.Products.Count==original,"Identical software must deduplicate");
            Require(s.Products.Count(p=>p.Technology==".NET Runtime")==2,"Side-by-side versions retained");
            Require(Inventory.FrameworkVersion(528040)=="4.8" && Inventory.FrameworkVersion(533320)=="4.8.1","Framework release mapping");
            s.Add("=Fictional, \"Spreadsheet\" App","+1.0","Fixture\nline");
            var selected=new Primary{adapter_id="demo-backup",ip="198.51.100.47"};
            string csv=Exporter.BuildCsv(s,new[]{"Web","Application"},selected);
            Require(csv.Contains("'="),"Formula prefix escaped");Require(csv.Contains("Web / Application"),"Roles retained");
            Reject(()=>Exporter.BuildCsv(s,new[]{"WC-WEB-2022"},selected),"Role validation");
            Reject(()=>Exporter.BuildCsv(s,new string[0],selected),"Role required");
            Reject(()=>Exporter.BuildCsv(s,new[]{"Web"},new Primary{adapter_id="demo-backup",ip="203.0.113.99"}),"Invalid primary rejected");
            string path=Exporter.Save(s,new[]{"Web","Application"},selected,destination);
            Require(Directory.GetFiles(path,"*.csv").Length==1,"One CSV only");Require(File.ReadAllBytes(Path.Combine(path,"cveharbor-assets.csv")).Take(3).SequenceEqual(new byte[]{239,187,191}),"UTF8 BOM");
            File.WriteAllText(Path.Combine(destination,"fixture-path.txt"),path);
            for(int i=0;i<400;i++)s.Add("Fictional Product "+i,"1.0",new string('x',400));
            string large=Exporter.Save(s,new[]{"Database"},null,destination);Require(new FileInfo(Path.Combine(large,"cveharbor-assets.csv")).Length>131072,"Large CSV not split");
            File.WriteAllText(Path.Combine(destination,"large-fixture-path.txt"),large);
            var empty=Inventory.Fictional();empty.Products.Clear();Reject(()=>Exporter.BuildCsv(empty,new[]{"Web"},null),"Empty exports blocked");
            var limit=Inventory.Fictional();for(int i=0;i<10001;i++)limit.Add("Fixture "+i,"1","Test");Reject(()=>Exporter.BuildCsv(limit,new[]{"Web"},null),"Row limit enforced");
            File.WriteAllText(Path.Combine(destination,"test-results.txt"),"PASS: one CSV, >128KB export, roles, primary selection, formula escaping, duplicate consolidation, side-by-side versions, UTF8 BOM, empty/oversized rejection. Fictional data only.");
        }
    }
}
