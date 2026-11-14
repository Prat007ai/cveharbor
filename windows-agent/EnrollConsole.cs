using System;
using System.ServiceProcess;
using System.Threading;
namespace CVEHarbor.Agent {
 public static class ConsoleEnrollment {
  public static int Main(){try{
   Console.WriteLine("UNSIGNED EVALUATION BUILD: testing and demos only. Follow your organization's software approval policy.");
   Console.Write("One-time CVEHarbor enrollment code (input hidden): ");string code="";
   if(Console.IsInputRedirected)code=Console.ReadLine();else for(;;){var k=Console.ReadKey(true);if(k.Key==ConsoleKey.Enter)break;if(k.Key==ConsoleKey.Backspace&&code.Length>0)code=code.Substring(0,code.Length-1);else if(!char.IsControl(k.KeyChar)&&code.Length<64)code+=k.KeyChar;}
   using(var service=new ServiceController("CVEHarborAgent")){bool restart=service.Status==ServiceControllerStatus.Running;try{if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(30));}var result=Runtime.Enroll(code,CancellationToken.None).GetAwaiter().GetResult();service.Start();Console.WriteLine("\nConnected to "+result.customer+" / "+result.environment+". Review inventory in the web wizard.");}finally{service.Refresh();if(restart&&service.Status==ServiceControllerStatus.Stopped)service.Start();}}return 0;
  }catch{Console.Error.WriteLine("\nEnrollment failed. Check administrator access, the installed service, connectivity and the one-time code.");return 1;}}
 }
}
