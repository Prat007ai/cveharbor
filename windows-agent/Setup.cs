using System;
using System.Drawing;
using System.ServiceProcess;
using System.Threading;
using System.Windows.Forms;
namespace CVEHarbor.Agent {
 public sealed class SetupForm:Form {
  readonly TextBox code=new TextBox{Dock=DockStyle.Top,UseSystemPasswordChar=true,MaxLength=64};
  readonly Label status=new Label{Dock=DockStyle.Fill,AutoSize=false};
  readonly Button connect=new Button{Text="Connect this server",Dock=DockStyle.Bottom,Height=44};
  public SetupForm(){Text="CVEHarbor Windows Agent Setup";ClientSize=new Size(580,300);MinimumSize=Size;Font=new Font("Segoe UI",10);Padding=new Padding(24);
   var intro=new Label{Text="UNSIGNED EVALUATION BUILD — testing and demos only. Windows may show an unrecognized-app warning. Follow your organization's software approval policy.\n\nOpen your customer environment in CVEHarbor and enter its one-time enrollment code. Review the first collection in the web wizard before daily synchronization starts.",Dock=DockStyle.Top,Height=150};
   Controls.Add(status);Controls.Add(connect);Controls.Add(code);Controls.Add(intro);connect.Click+=Connect;
  }
  async void Connect(object sender,EventArgs e){connect.Enabled=false;code.Enabled=false;status.Text="Connecting securely to CVEHarbor…";try{
   // Stop the installed service before replacing its identity or pending queue.
   using(var service=new ServiceController("CVEHarborAgent")){bool restart=service.Status==ServiceControllerStatus.Running;try{if(service.Status!=ServiceControllerStatus.Stopped){service.Stop();service.WaitForStatus(ServiceControllerStatus.Stopped,TimeSpan.FromSeconds(30));}
    var result=await Runtime.Enroll(code.Text,CancellationToken.None);code.Clear();service.Start();status.Text="Connected to "+result.customer+" / "+result.environment+". Return to the web wizard to review the first inventory.";
   }finally{service.Refresh();if(restart&&service.Status==ServiceControllerStatus.Stopped)service.Start();}}
  }catch(Exception error){status.Text=error is AgentHttpException?error.Message+". Check the enrollment code and try again.":"Setup could not complete. Confirm administrator access, the installed service and internet connectivity. "+(error is ArgumentException?error.Message:"");}
   finally{connect.Enabled=true;code.Enabled=true;}
  }
  [STAThread] public static void Main(string[] args){Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);Application.Run(new SetupForm());}
 }
}
