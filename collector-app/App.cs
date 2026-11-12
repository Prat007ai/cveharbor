using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.Versioning;

[assembly: AssemblyTitle("CVEHarbor Windows Collector")]
[assembly: AssemblyDescription("Local Windows inventory and CVEHarbor CSV export")]
[assembly: AssemblyCompany("CVEHarbor")]
[assembly: AssemblyProduct("CVEHarbor Windows Collector")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: TargetFramework(".NETFramework,Version=v4.8")]

namespace CVEHarbor.Collector
{
    internal static class Program
    {
        [STAThread] static int Main(string[] args)
        {
            if(args.Length==2 && args[0]=="--self-test") { try {SelfTest.Run(args[1]);return 0;}catch(Exception ex){File.WriteAllText(Path.Combine(args[1],"test-failure.txt"),ex.ToString());return 1;} }
            Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new CollectorForm(args.Contains("--demo")));return 0;
        }
    }
    internal sealed class HarborBanner : Panel
    {
        public HarborBanner(){DoubleBuffered=true;SetStyle(ControlStyles.ResizeRedraw,true);Height=116;Dock=DockStyle.Top;AccessibleName="CVEHarbor Windows Collector";}
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;
            using(var gradient=new LinearGradientBrush(ClientRectangle,Color.FromArgb(14,43,60),Color.FromArgb(9,64,73),0f))g.FillRectangle(gradient,ClientRectangle);
            using(var f=new Font("Segoe UI",21,FontStyle.Bold))using(var white=new SolidBrush(Color.White))g.DrawString("CVEHarbor",f,white,24,12);
            using(var f=new Font("Segoe UI",10))using(var b=new SolidBrush(Color.FromArgb(174,211,223)))g.DrawString("WINDOWS COLLECTOR   /   Your inventory, clearly mapped",f,b,26,72);
            float x=Width-145;
            using(var beam=new SolidBrush(Color.FromArgb(28,90,238,215)))g.FillPolygon(beam,new[]{new PointF(x+26,27),new PointF(x-200,7),new PointF(x-190,68)});
            using(var b=new SolidBrush(Color.FromArgb(193,226,228)))g.FillPolygon(b,new[]{new PointF(x+12,34),new PointF(x+40,34),new PointF(x+49,97),new PointF(x+3,97)});
            using(var b=new SolidBrush(Color.FromArgb(30,139,142))){g.FillRectangle(b,x+7,60,37,13);g.FillRectangle(b,x+9,25,34,10);}
            using(var p=new Pen(Color.FromArgb(88,223,204),2)){g.DrawLine(p,x+7,22,x+26,10);g.DrawLine(p,x+26,10,x+45,22);g.DrawLine(p,x-150,97,x-75,79);g.DrawLine(p,x-75,79,x+20,103);g.DrawLine(p,x+20,103,x+110,80);foreach(var pt in new[]{new PointF(x-150,97),new PointF(x-75,79),new PointF(x+20,103),new PointF(x+110,80)})g.DrawEllipse(p,pt.X-3,pt.Y-3,6,6);
                g.DrawPolygon(p,new[]{new PointF(x-85,26),new PointF(x-63,32),new PointF(x-67,52),new PointF(x-85,65),new PointF(x-103,52),new PointF(x-107,32)});g.DrawLines(p,new[]{new PointF(x-96,44),new PointF(x-87,52),new PointF(x-75,38)});}
        }
    }
    public sealed class CollectorForm : Form
    {
        static readonly Color Background=Color.FromArgb(7,23,35),Card=Color.FromArgb(15,43,59),Ink=Color.FromArgb(229,243,247),Muted=Color.FromArgb(170,199,212),Teal=Color.FromArgb(87,222,202);
        readonly bool demo;
        Snapshot snapshot;
        bool busy;
        string output;
        CheckedListBox roles;
        TabControl tabs;
        ComboBox primary;
        DataGridView products,networks;
        Label status,summary,networkSummary;
        CheckBox reviewed;
        Button collect,export,folder;
        TextBox search;
        public CollectorForm(bool demoMode)
        {
            demo=demoMode;Text="CVEHarbor Windows Collector"+(demo?" — FICTIONAL DEMO":"");
            Size=new Size(1280,940);MinimumSize=new Size(1000,800);StartPosition=FormStartPosition.CenterScreen;
            SuspendLayout();Font=new Font("Segoe UI",10);BackColor=Background;ForeColor=Ink;AutoScaleMode=AutoScaleMode.None;
            Icon=SystemIcons.Shield;
            var shell=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=3,Padding=new Padding(16)};
            shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));shell.RowStyles.Add(new RowStyle(SizeType.Absolute,116));shell.RowStyles.Add(new RowStyle(SizeType.Percent,100));shell.RowStyles.Add(new RowStyle(SizeType.Absolute,74));Controls.Add(shell);
            shell.Controls.Add(new HarborBanner{Dock=DockStyle.Fill},0,0);
            tabs=new TabControl{Dock=DockStyle.Fill,Padding=new Point(24,9),Margin=new Padding(0,14,0,8),AccessibleName="Collection steps"};
            var setup=Page("1  Server details");var network=Page("2  Network & primary IP");var review=Page("3  Review & export");shell.Controls.Add(tabs,0,1);
            var details=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=1};details.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,49));details.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,51));setup.Controls.Add(details);
            var left=Stack();var right=Stack();details.Controls.Add(left,0,0);details.Controls.Add(right,1,0);
            left.Controls.Add(Heading("Identify this server"));left.Controls.Add(Note("Hostname is collected automatically from Windows."));
            left.Controls.Add(new TextBox{Text=demo?"NORTHSTAR-WEB01":Environment.MachineName,ReadOnly=true,Width=380,BackColor=Background,ForeColor=Ink,BorderStyle=BorderStyle.FixedSingle,AccessibleName="Server hostname",Margin=new Padding(0,10,0,16)});
            left.Controls.Add(Heading("What does this server do?"));left.Controls.Add(Note("Choose one or more roles. This is separate from its name."));
            roles=new CheckedListBox{Width=390,Height=260,CheckOnClick=true,BackColor=Card,ForeColor=Ink,BorderStyle=BorderStyle.None,AccessibleName="Server roles",IntegralHeight=false};roles.Items.AddRange(Inventory.Roles);roles.ItemCheck+=(s,e)=>BeginInvoke((Action)UpdateExport);left.Controls.Add(roles);
            right.Controls.Add(Heading("A clearer route to your inventory"));
            right.Controls.Add(Note("01   COLLECT\r\nRead Windows, installed software, .NET and network adapters on this server.",16));
            right.Controls.Add(Note("02   REVIEW\r\nChoose a primary IP. Inspect versions and any collection warnings.",16));
            right.Controls.Add(Note("03   EXPORT\r\nSave one CSV, then upload it to your selected CVEHarbor customer environment.",16));
            right.Controls.Add(Note("Local collection only. No installation, background service, automatic upload or AI requests.",12));
            right.Controls.Add(Note(demo?"FICTIONAL DEMO — this mode never inventories this computer.":"Version 1.0.0 • Unsigned evaluation build\r\nWindows Desktop Experience with .NET Framework 4.8 or later.",12));
            var networkLayout=new TableLayoutPanel{Dock=DockStyle.Fill,RowCount=5,ColumnCount=1};networkLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));
            networkLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,40));networkLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,45));networkLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,52));networkLayout.RowStyles.Add(new RowStyle(SizeType.Percent,100));networkLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,43));network.Controls.Add(networkLayout);
            networkLayout.Controls.Add(Heading("Choose the address your team recognizes"),0,0);
            primary=new ComboBox{Dock=DockStyle.Fill,DropDownStyle=ComboBoxStyle.DropDownList,AccessibleName="Primary adapter and IP",BackColor=Background,ForeColor=Ink,Enabled=false};primary.SelectedIndexChanged+=(s,e)=>{reviewed.Checked=false;UpdateExport();};networkLayout.Controls.Add(primary,0,1);
            networkLayout.Controls.Add(Note("All listed adapters and addresses are included. Your selection suggests the primary IP on first import; an existing dashboard selection is preserved."),0,2);
            networks=Grid();networks.AccessibleName="Network adapters and IP addresses";AddColumn(networks,"Adapter",30);AddColumn(networks,"Status",12);AddColumn(networks,"IP address",35);AddColumn(networks,"Prefix",8);AddColumn(networks,"Address state",15);networkLayout.Controls.Add(networks,0,3);
            networkSummary=Note("Collect inventory to discover network adapters.");networkSummary.Dock=DockStyle.Fill;networkLayout.Controls.Add(networkSummary,0,4);
            var reviewLayout=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=1,RowCount=5};reviewLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));reviewLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,42));reviewLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,42));reviewLayout.RowStyles.Add(new RowStyle(SizeType.Percent,100));reviewLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,58));reviewLayout.RowStyles.Add(new RowStyle(SizeType.Absolute,65));review.Controls.Add(reviewLayout);
            summary=Note("Collect inventory to review the software and versions.");summary.Dock=DockStyle.Fill;reviewLayout.Controls.Add(summary,0,0);
            search=new TextBox{Dock=DockStyle.Fill,AccessibleName="Filter inventory",BackColor=Background,ForeColor=Ink,Enabled=false};search.TextChanged+=(s,e)=>ShowProducts();reviewLayout.Controls.Add(search,0,1);
            products=Grid();products.AccessibleName="Collected software preview";AddColumn(products,"Technology",27);AddColumn(products,"Version",16);AddColumn(products,"Collection evidence",57);reviewLayout.Controls.Add(products,0,2);
            reviewed=new CheckBox{Text="I reviewed this inventory and any warnings. I will select the correct customer and environment before uploading.",Dock=DockStyle.Fill,AutoSize=false,AccessibleName="Inventory reviewed",Enabled=false};reviewed.CheckedChanged+=(s,e)=>UpdateExport();reviewLayout.Controls.Add(reviewed,0,3);
            var actions=new FlowLayoutPanel{Dock=DockStyle.Fill,WrapContents=false};export=Button("Export single CSV",true);export.Enabled=false;export.Click+=(s,e)=>Save();actions.Controls.Add(export);
            folder=Button("Open output folder",false);folder.Enabled=false;folder.Click+=(s,e)=>{try{Process.Start(new ProcessStartInfo{FileName=output,UseShellExecute=true});}catch(Exception ex){MessageBox.Show(this,ex.Message,"Cannot open folder");}};actions.Controls.Add(folder);
            var warnings=Button("Coverage & warnings",false);warnings.Click+=(s,e)=>ShowWarnings();actions.Controls.Add(warnings);reviewLayout.Controls.Add(actions,0,4);
            var footer=new TableLayoutPanel{Dock=DockStyle.Fill,ColumnCount=2,RowCount=1};footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100));footer.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute,200));shell.Controls.Add(footer,0,2);
            status=Note("Ready. Choose server roles, then collect inventory.");status.Dock=DockStyle.Fill;footer.Controls.Add(status,0,0);
            collect=Button(demo?"Load fictional inventory":"Collect inventory",true);collect.Dock=DockStyle.Fill;collect.Click+=async(s,e)=>await Collect();footer.Controls.Add(collect,1,0);
            FormClosing+=(s,e)=>{if(busy){e.Cancel=true;status.Text="Collection is still running. Wait for it to finish before closing.";}};
            AutoScaleDimensions=new SizeF(96F,96F);AutoScaleMode=AutoScaleMode.Dpi;ResumeLayout(true);
        }
        TabPage Page(string title){var p=new TabPage(title){BackColor=Background,ForeColor=Ink,Padding=new Padding(16)};tabs.TabPages.Add(p);return p;}
        static FlowLayoutPanel Stack(){var panel=new FlowLayoutPanel{Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(8)};panel.SizeChanged+=(s,e)=>{int width=Math.Max(100,panel.ClientSize.Width-40);foreach(Control c in panel.Controls){if(c is Label)c.MaximumSize=new Size(width,0);else c.Width=width;}};return panel;}
        static Label Heading(string t){return new Label{Text=t,UseMnemonic=false,AutoSize=true,Font=new Font("Segoe UI",13,FontStyle.Bold),ForeColor=Ink,Margin=new Padding(0,0,0,9)};}
        static Label Note(string t,int bottom=6){return new Label{Text=t,UseMnemonic=false,AutoSize=true,MaximumSize=new Size(900,0),ForeColor=Muted,Margin=new Padding(0,4,12,bottom)};}
        static Button Button(string t,bool primary){return new Button{Text=t,UseMnemonic=false,AutoSize=true,MinimumSize=new Size(155,38),Padding=new Padding(10,5,10,5),FlatStyle=FlatStyle.Flat,BackColor=primary?Teal:Card,ForeColor=primary?Background:Ink,Cursor=Cursors.Hand,Margin=new Padding(0,0,10,0),UseVisualStyleBackColor=false};}
        static DataGridView Grid(){return new DataGridView{Dock=DockStyle.Fill,ReadOnly=true,AllowUserToAddRows=false,AllowUserToDeleteRows=false,AllowUserToResizeRows=false,RowHeadersVisible=false,AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,BackgroundColor=Card,BorderStyle=BorderStyle.None,GridColor=Color.FromArgb(42,74,87),SelectionMode=DataGridViewSelectionMode.FullRowSelect,MultiSelect=false,EnableHeadersVisualStyles=false,ColumnHeadersHeight=36,RowTemplate=new DataGridViewRow{Height=32},DefaultCellStyle=new DataGridViewCellStyle{BackColor=Card,ForeColor=Ink,SelectionBackColor=Color.FromArgb(28,91,100),SelectionForeColor=Color.White,Padding=new Padding(5)},ColumnHeadersDefaultCellStyle=new DataGridViewCellStyle{BackColor=Color.FromArgb(26,57,72),ForeColor=Ink,Font=new Font("Segoe UI",10,FontStyle.Bold)},AutoGenerateColumns=false};}
        static void AddColumn(DataGridView grid,string title,int weight){grid.Columns.Add(new DataGridViewTextBoxColumn{HeaderText=title,Name=title,FillWeight=weight,SortMode=DataGridViewColumnSortMode.Automatic});}
        string[] ChosenRoles(){return roles.CheckedItems.Cast<string>().ToArray();}
        Primary ChosenPrimary(){var choice=primary.SelectedItem as AddressChoice;return choice==null?null:choice.Value;}
        void UpdateExport(){if(export!=null)export.Enabled=!busy && snapshot!=null && snapshot.Products.Count>0 && reviewed.Checked && ChosenRoles().Length>0;}
        async Task Collect()
        {
            if(ChosenRoles().Length==0){tabs.SelectedIndex=0;status.Text="Choose at least one server role first (for example, Web).";roles.Focus();return;}
            busy=true;collect.Enabled=false;roles.Enabled=false;export.Enabled=false;reviewed.Checked=false;reviewed.Enabled=false;folder.Enabled=false;primary.Enabled=false;search.Enabled=false;snapshot=null;products.Rows.Clear();networks.Rows.Clear();primary.Items.Clear();
            try{
                var progress=new Progress<string>(message=>status.Text=message);
                snapshot=await Task.Run(()=>demo?Inventory.Fictional():Inventory.Collect(message=>((IProgress<string>)progress).Report(message)));
                primary.Items.Add(new AddressChoice("No primary selected — choose later in CVEHarbor",null));
                foreach(var adapter in snapshot.Adapters){if(adapter.addresses.Count==0)networks.Rows.Add(adapter.name,adapter.status,"No address assigned","—","—");foreach(var ip in adapter.addresses){networks.Rows.Add(adapter.name,adapter.status,ip.ip,"/"+ip.prefix,ip.state);primary.Items.Add(new AddressChoice(adapter.name+"  ·  "+ip.ip+"  ("+adapter.status+")",new Primary{adapter_id=adapter.id,ip=ip.ip}));}}
                primary.SelectedIndex=0;primary.Enabled=true;search.Enabled=true;reviewed.Enabled=snapshot.Products.Count>0;search.Text="";ShowProducts();
                summary.Text=snapshot.Products.Count+" software entries  •  "+snapshot.Warnings.Count+" warnings  •  Filter by product or version below";
                networkSummary.Text=snapshot.Adapters.Count+" adapters  •  "+snapshot.Adapters.Sum(a=>a.addresses.Count)+" addresses  •  Collected "+snapshot.CollectedUtc;
                status.Text=snapshot.Products.Count==0?"No software collected. Review Coverage & warnings before trying again.":"Collection complete. Choose a primary IP, then open Review & export.";
                collect.Text="Collect again";tabs.SelectedIndex=1;
            }catch(Exception ex){status.Text="Collection failed. No CSV was exported.";MessageBox.Show(this,ex.Message,"Collection could not finish",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
            finally{busy=false;roles.Enabled=true;collect.Enabled=true;UpdateExport();}
        }
        void ShowProducts(){products.Rows.Clear();if(snapshot==null)return;string term=search.Text.Trim();foreach(var p in snapshot.Products.Where(p=>(p.Technology+" "+p.Version).IndexOf(term,StringComparison.OrdinalIgnoreCase)>=0))products.Rows.Add(p.Technology,p.Version.Length==0?"Not recorded":p.Version,p.Details);}
        void ShowWarnings()
        {
            using(var dialog=new Form{Text="Collection coverage & warnings",Size=new Size(760,520),StartPosition=FormStartPosition.CenterParent,BackColor=Background,ForeColor=Ink,Font=Font})
            {var text=new TextBox{Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Vertical,Dock=DockStyle.Fill,BackColor=Card,ForeColor=Ink,Text=String.Join("\r\n\r\n",Inventory.Coverage)+"\r\n\r\nCOLLECTION WARNINGS\r\n"+(snapshot==null?"Collect inventory first.":snapshot.Warnings.Count==0?"No collection warnings. Coverage limits above still apply.":String.Join("\r\n",snapshot.Warnings)),AccessibleName="Coverage and collection warnings"};dialog.Controls.Add(text);dialog.ShowDialog(this);}
        }
        void Save()
        {
            if(!export.Enabled)return;
            using(var dialog=new FolderBrowserDialog{Description="Choose where to save the new CVEHarbor inventory folder",ShowNewFolderButton=true})
            if(dialog.ShowDialog(this)==DialogResult.OK)try{output=Exporter.Save(snapshot,ChosenRoles(),ChosenPrimary(),dialog.SelectedPath);folder.Enabled=true;status.Text="Export complete: one cveharbor-assets.csv plus the collection report. Open the output folder to upload your CSV.";MessageBox.Show(this,"Saved to:\r\n"+output+"\r\n\r\nIn CVEHarbor, choose your customer and environment, upload cveharbor-assets.csv, review it and import. No data has been uploaded by this app.","Single CSV exported",MessageBoxButtons.OK,MessageBoxIcon.Information);}catch(Exception ex){status.Text="Export did not complete. Your collected inventory is still available.";MessageBox.Show(this,ex.Message,"Export could not finish",MessageBoxButtons.OK,MessageBoxIcon.Warning);}
        }
        sealed class AddressChoice { public string Label;public Primary Value;public AddressChoice(string label,Primary value){Label=label;Value=value;}public override string ToString(){return Label;} }
    }
}
