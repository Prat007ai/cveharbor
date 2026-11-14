using System;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
namespace CVEHarbor.Agent {
 public sealed class InventoryService:ServiceBase {
  CancellationTokenSource cancel;Task runner;
  public InventoryService(){ServiceName="CVEHarborAgent";CanStop=true;AutoLog=false;}
  protected override void OnStart(string[] args){cancel=new CancellationTokenSource();runner=Task.Run(()=>Runtime.Run(cancel.Token));}
  protected override void OnStop(){cancel.Cancel();try{runner.Wait(TimeSpan.FromSeconds(10));}catch(AggregateException){}cancel.Dispose();}
  public static void Main(string[] args){ServiceBase.Run(new InventoryService());}
 }
}
