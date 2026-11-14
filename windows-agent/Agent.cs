using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using CVEHarbor.Collector;

namespace CVEHarbor.Agent
{
 public sealed class Configuration { public string device_id; public string credential; public string customer; public string environment; }
 public sealed class AgentHttpException : Exception { public readonly int Status; public AgentHttpException(int status):base("CVEHarbor request returned HTTP "+status){Status=status;} }
 public static class Runtime
 {
  public const string Version="1.0.0";
  public const string Endpoint="https://api.cveharbor.com/v1/agent/";
  public const int MaxBytes=2097152;
  public static readonly string StatePath=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"CVEHarborAgent");
  static readonly JavaScriptSerializer Json=new JavaScriptSerializer{MaxJsonLength=MaxBytes,RecursionLimit=32};
  static readonly byte[] Entropy=Encoding.UTF8.GetBytes("CVEHarbor Windows Agent state v1");
  static readonly HttpClient Client=CreateClient();
  static HttpClient CreateClient(){
   ServicePointManager.SecurityProtocol=SecurityProtocolType.Tls12;
   var c=new HttpClient(new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false,AutomaticDecompression=DecompressionMethods.None});
   c.Timeout=TimeSpan.FromSeconds(45);c.MaxResponseContentBufferSize=131072;c.DefaultRequestHeaders.UserAgent.ParseAdd("CVEHarbor-Agent/"+Version);return c;
  }
  public static string Serialize(object value){return Json.Serialize(value);}
  public static Dictionary<string,object> Parse(string value){return Json.Deserialize<Dictionary<string,object>>(value);}
  public static bool IsAdministrator(){return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);}
  static void NoReparse(string path){if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new IOException("Agent state cannot use symbolic links or redirected directories.");}
  public static void PrepareState(){
   if(!IsAdministrator())throw new UnauthorizedAccessException("Open Agent Setup as an administrator.");
   NoReparse(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
   var admins=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null);
   var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
   var service=(SecurityIdentifier)new NTAccount("NT SERVICE","CVEHarborAgent").Translate(typeof(SecurityIdentifier));
   var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);acl.SetOwner(admins);
   foreach(var sid in new[]{admins,system,service})acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
   if(Directory.Exists(StatePath)){
    NoReparse(StatePath);var owner=(SecurityIdentifier)Directory.GetAccessControl(StatePath).GetOwner(typeof(SecurityIdentifier));
    if(!owner.Equals(admins)&&!owner.Equals(system))throw new UnauthorizedAccessException("Existing agent state directory has an unexpected owner. Ask your administrator to investigate.");
    // Do not follow pre-existing child links when applying access controls.
    foreach(string file in Directory.GetFileSystemEntries(StatePath))NoReparse(file);
    Directory.SetAccessControl(StatePath,acl);
   }else Directory.CreateDirectory(StatePath,acl);
  }
  static string FilePath(string name){if(name!="credential.bin"&&name!="pending.bin"&&name!="status.txt")throw new ArgumentException("Invalid state file");NoReparse(StatePath);string p=Path.Combine(StatePath,name);if(File.Exists(p))NoReparse(p);return p;}
  public static void Save(string name,string value){
   byte[] plain=Encoding.UTF8.GetBytes(value);if(plain.Length>MaxBytes)throw new InvalidOperationException("Inventory exceeds the supported upload limit.");
   string path=FilePath(name),temporary=path+"."+Guid.NewGuid().ToString("N")+".tmp";
   byte[] protectedBytes=ProtectedData.Protect(plain,Entropy,DataProtectionScope.LocalMachine);Array.Clear(plain,0,plain.Length);
   try{using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){stream.Write(protectedBytes,0,protectedBytes.Length);stream.Flush(true);}if(File.Exists(path))File.Replace(temporary,path,null);else File.Move(temporary,path);}
   finally{if(File.Exists(temporary))File.Delete(temporary);Array.Clear(protectedBytes,0,protectedBytes.Length);}
  }
  public static string Load(string name){
   if(!Directory.Exists(StatePath))return null;string path=FilePath(name);if(!File.Exists(path))return null;
   if(new FileInfo(path).Length>MaxBytes+65536)throw new IOException("Protected state exceeds limit.");
   byte[] bytes=ProtectedData.Unprotect(File.ReadAllBytes(path),Entropy,DataProtectionScope.LocalMachine);try{return Encoding.UTF8.GetString(bytes);}finally{Array.Clear(bytes,0,bytes.Length);}
  }
  public static void ClearPending(){string path=FilePath("pending.bin");if(File.Exists(path))File.Delete(path);}
  public static void Status(string message){if(!Directory.Exists(StatePath))return;File.WriteAllText(FilePath("status.txt"),DateTime.UtcNow.ToString("o")+" "+message+Environment.NewLine,Encoding.UTF8);}
  public static async Task<Dictionary<string,object>> Post(string action,string body,string credential,CancellationToken cancel){
   if(action!="enroll"&&action!="poll"&&action!="upload")throw new ArgumentException("Invalid action");
   if(Encoding.UTF8.GetByteCount(body)>MaxBytes)throw new InvalidOperationException("Upload exceeds limit");
   using(var request=new HttpRequestMessage(HttpMethod.Post,Endpoint+action)){
    request.Content=new StringContent(body,Encoding.UTF8,"application/json");
    if(credential!=null){if(!Regex.IsMatch(credential,"^[a-f0-9]{64}$"))throw new InvalidOperationException("Invalid device credential");request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",credential);}
    using(var response=await Client.SendAsync(request,HttpCompletionOption.ResponseContentRead,cancel)){
     if(!response.IsSuccessStatusCode)throw new AgentHttpException((int)response.StatusCode);
     string raw=await response.Content.ReadAsStringAsync();if(raw.Length>131072)throw new IOException("Service response too large");return Parse(raw);
    }
   }
  }
  public static async Task<Configuration> Enroll(string code,CancellationToken cancel){
   PrepareState();code=(code??"").Trim();if(!Regex.IsMatch(code,"^[a-f0-9]{64}$"))throw new ArgumentException("Enter the one-time code from the CVEHarbor customer setup page.");
   var result=await Post("enroll",Serialize(new{code=code,hostname=Environment.MachineName,agent_version=Version}),null,cancel);
   Guid device;if(!Guid.TryParse(Convert.ToString(result["device_id"]),out device)||!Regex.IsMatch(Convert.ToString(result["credential"]),"^[a-f0-9]{64}$"))throw new IOException("Invalid enrollment response");
   var config=new Configuration{device_id=device.ToString(),credential=Convert.ToString(result["credential"]),customer=Convert.ToString(result["customer"]),environment=Convert.ToString(result["environment"])};
   Save("credential.bin",Serialize(config));ClearPending();Status("Enrolled. Waiting for the first collection and web review.");return config;
  }
  public static string Collection(long sequence,long request){
   var s=Inventory.Collect(delegate(string ignored){},true);
   return Collection(s,sequence,request);
  }
  public static string Collection(Snapshot s,long sequence,long request){
   if(s.Products.Count<1||s.Products.Count>10000||s.Warnings.Count>100)throw new InvalidOperationException("Collection limits exceeded; inventory was not uploaded.");
   string result=Serialize(new{schema=1,sequence=sequence,request=request,collected_at=s.CollectedUtc,hostname=s.Hostname,agent_version=Version,complete=!s.Incomplete,
    products=s.Products.Select(p=>new{name=p.Technology,version=p.Version,details=p.Details.Length>500?p.Details.Substring(0,500):p.Details}).ToArray(),
    network=s.Adapters.Count>0?Exporter.Network(s,null):null,warnings=s.Warnings.Select(w=>w.Length>250?w.Substring(0,250):w).ToArray()});
   if(Encoding.UTF8.GetByteCount(result)>MaxBytes)throw new InvalidOperationException("Inventory exceeds the supported upload limit.");return result;
  }
  public static async Task Run(CancellationToken cancel){
   int failures=0;
   while(!cancel.IsCancellationRequested){
    int wait=300;
    try{
     string stored=Load("credential.bin");
     if(stored!=null){var c=Json.Deserialize<Configuration>(stored);string pending=Load("pending.bin");
      if(pending==null){var poll=await Post("poll","{}",c.credential,cancel);if(Convert.ToBoolean(poll["collect"])){
       pending=Collection(Convert.ToInt64(poll["sequence"]),Convert.ToInt64(poll["request"]));Save("pending.bin",pending);
      }}
      if(pending!=null){var accepted=await Post("upload",pending,c.credential,cancel);if(!accepted.ContainsKey("accepted")||!Convert.ToBoolean(accepted["accepted"]))throw new IOException("Upload was not acknowledged");ClearPending();Status(Convert.ToBoolean(accepted["review_required"])?"First inventory uploaded. Confirm it in the CVEHarbor setup wizard.":"Inventory upload accepted.");}
     }
     failures=0;
    }catch(AgentHttpException error){
     failures++;if(error.Status==409){ClearPending();Status("Collection sequence changed; requesting a fresh collection.");}
     else if(error.Status==423){ClearPending();Status("Uploads suspended. Review the incident in CVEHarbor.");wait=900;}
     else if(error.Status==401){Status("Device credential revoked or unavailable. Re-enroll through Agent Setup.");wait=3600;}
     else{Status("Upload unavailable (HTTP "+error.Status+"). The bounded encrypted queue will retry.");wait=Math.Min(3600,300*(1<<Math.Min(failures,3)));}
    }catch(OperationCanceledException){if(cancel.IsCancellationRequested)break;failures++;Status("Request timed out; collection retained for retry.");wait=Math.Min(3600,300*(1<<Math.Min(failures,3)));}
    catch(Exception){failures++;try{Status("Collection or local state unavailable. Check service permissions and connectivity; no private values were logged.");}catch{}wait=Math.Min(3600,300*(1<<Math.Min(failures,3)));}
    byte[] jitter=new byte[1];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(jitter);
    try{await Task.Delay(TimeSpan.FromSeconds(wait+jitter[0]%61),cancel);}catch(OperationCanceledException){break;}
   }
  }
 }
}
