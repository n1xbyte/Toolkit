### Not currently fuctional

enum TOKEN_INFORMATION_CLASS
    {
        TokenIntegrityLevel = 25
    }

    [DllImport("advapi32", SetLastError = true),
    SuppressUnmanagedCodeSecurityAttribute]
    static extern int OpenProcessToken(
    System.IntPtr ProcessHandle,
    int DesiredAccess,
    ref IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    
 public bool isHighIntegrity()
    {
        Process[] processes = Process.GetProcessesByName("CSharpAgent");

        foreach (Process process in processes)
        {
            IntPtr hToken = IntPtr.Zero;

            if (OpenProcessToken(process.Handle, 8, ref hToken) != 0)
            {
                int cbSize = 0;
                Console.WriteLine("Made it");
                bool result = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, IntPtr.Zero, cbSize, out cbSize);
                IntPtr TokenPtr = Marshal.AllocHGlobal(cbSize);
                Console.WriteLine(result);
                bool result2 = GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, TokenPtr, cbSize, out cbSize);
                Console.WriteLine(result2);
                IntPtr pSid = Marshal.ReadIntPtr(TokenPtr);
                int dwIntegrityLevel = Marshal.ReadInt32(GetSidSubAuthority(pSid, (Marshal.ReadByte(GetSidSubAuthorityCount(pSid)) - 1U)));
                if (dwIntegrityLevel == 0x00003000)
                {
                    return true;
                }
            }
        }
        return false;
    }
}