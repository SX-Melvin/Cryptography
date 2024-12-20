using System;
using System.IO;
using System.Security.Cryptography;

namespace Cryptography.Service
{
    public class AESService
    {
        private static readonly string KeyFileName = "AES.Key";
        private static readonly string KeyFilePath = "C:/_work/secureinfo";
        private static readonly string EncryptedFilePath = "C:/_work/secureinfo";

        public static void GenerateAESKeyFile(int keySize = 256)
        {
            Directory.CreateDirectory(KeyFilePath);
            using var aes = Aes.Create();
            aes.KeySize = keySize;
            aes.GenerateKey();
            string keyFilePath = Path.Combine(KeyFilePath, KeyFileName);
            File.WriteAllBytes(keyFilePath, aes.Key);
            Console.WriteLine($"AES key saved to {keyFilePath}");
        }

        public static void EncryptSensitiveData(string plainText, string fileName)
        {
            byte[] key = File.ReadAllBytes(Path.Combine(KeyFilePath, KeyFileName));

            using var aes = Aes.Create();
            aes.Key = key;
            aes.Padding = PaddingMode.PKCS7; // Default padding mode
            aes.GenerateIV(); // Generate a new Initialization Vector (IV)

            using var encryptor = aes.CreateEncryptor();
            using var ms = new MemoryStream();

            // Prepend the IV to the encrypted data for decryption purposes
            ms.Write(aes.IV, 0, aes.IV.Length);

            using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            using (var sw = new StreamWriter(cryptoStream))
            {
                sw.Write(plainText);
            }

            // Encode the encrypted data as Base64 for safer storage
            string base64EncryptedData = Convert.ToBase64String(ms.ToArray());
            File.WriteAllText(Path.Combine(EncryptedFilePath, fileName), base64EncryptedData);
        }

        public static string DecryptSensitiveData(string fileName)
        {
            byte[] key = File.ReadAllBytes(Path.Combine(KeyFilePath, KeyFileName));
            string base64EncryptedData = File.ReadAllText(Path.Combine(EncryptedFilePath, fileName));

            byte[] encryptedData = Convert.FromBase64String(base64EncryptedData);

            using var aes = Aes.Create();
            aes.Key = key;
            aes.Padding = PaddingMode.PKCS7;

            // Extract the IV from the encrypted data
            byte[] iv = encryptedData.Take(16).ToArray();
            byte[] cipherText = encryptedData.Skip(16).ToArray();
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            using var ms = new MemoryStream(cipherText);
            using var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var sr = new StreamReader(cryptoStream);

            return sr.ReadToEnd();
        }

    }
}
