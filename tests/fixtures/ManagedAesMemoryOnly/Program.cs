using System;
using System.Security.Cryptography;

// Harmless JSON stays in memory. The program only checks the decoded length.
byte[] key = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
byte[] iv = Convert.FromBase64String("EBESExQVFhcYGRobHB0eHw==");
byte[] cipher = Convert.FromBase64String(
    "OZk7lxB0x9F9ZkorCqj5Zu8CckKT3e3ajxZ7BzU/aRVu8grkG977SiDlZ0Iq9c7zvgvh/DynYfWX6D5CZz/BJA==");
using var aes = Aes.Create();
aes.Key = key;
aes.IV = iv;
byte[] plain = aes.CreateDecryptor().TransformFinalBlock(cipher, 0, cipher.Length);
return plain.Length == 63 ? 0 : 1;
