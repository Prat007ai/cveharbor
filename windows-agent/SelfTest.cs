using System;
using System.IO;
using System.Text;
using CVEHarbor.Collector;
using CVEHarbor.Agent;
public static class AgentSelfTest {
 public static int Main(string[] args){try{
  var s=Inventory.Fictional();s.CollectedUtc=DateTime.UtcNow.ToString("o");
  string json=Runtime.Collection(s,1,1);var parsed=Runtime.Parse(json);
  if(Convert.ToInt32(parsed["schema"])!=1||!Convert.ToBoolean(parsed["complete"])||json.Contains("credential")||json.Contains("customer_id"))throw new Exception("Payload boundary failed");
  File.WriteAllText(args[0],json,new UTF8Encoding(false));
  s.Incomplete=true;s.Warnings.Add("A fixture source was unreadable.");if(Convert.ToBoolean(Runtime.Parse(Runtime.Collection(s,2,1))["complete"]))throw new Exception("Incomplete inventory must be flagged");
  s.Products.Clear();bool rejected=false;try{Runtime.Collection(s,3,1);}catch(InvalidOperationException){rejected=true;}if(!rejected)throw new Exception("Empty inventory must fail");
  if(Runtime.Endpoint!="https://api.cveharbor.com/v1/agent/")throw new Exception("Fixed upload endpoint changed");
  Console.WriteLine("Agent fictional payload checks passed; no local inventory or network requests.");return 0;
 }catch(Exception e){Console.Error.WriteLine(e.Message);return 1;}}
}
