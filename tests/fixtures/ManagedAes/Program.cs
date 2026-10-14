using System;
using System.IO;
using System.Security.Cryptography;

byte[] key = Convert.FromBase64String("K34VFiiu0qar9xWICc9PPA==");
byte[] iv = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
byte[] plain = Convert.FromBase64String("a8G+4i5An5bpPX4Rc5MXKg==");
byte[] cipher = Convert.FromBase64String("dkmrrIEZskbO6Y6bEukZfQ==");
string folder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string tag = "emumee-aes-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
using var aes = Aes.Create();
aes.Key = key;
aes.IV = iv;
aes.Mode = CipherMode.CBC;
aes.Padding = PaddingMode.None;
using var decryptor = aes.CreateDecryptor();
byte[] recovered = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
File.WriteAllBytes(Path.Combine(folder, tag + "-plain.bin"), recovered);
using var encryptor = aes.CreateEncryptor(key, iv);
byte[] encoded = encryptor.TransformFinalBlock(plain, 0, plain.Length);
File.WriteAllBytes(Path.Combine(folder, tag + "-cipher.bin"), encoded);

using var paddedAes = Aes.Create();
paddedAes.Key = key;
paddedAes.IV = iv;
byte[] paddedWindow = Convert.FromBase64String(
    "WFh3kNoKPS9mXhW4f12t3iMSz7fAVA6IGv+oGnnR+BJIGg==");
using var paddedDecryptor = paddedAes.CreateDecryptor(key, iv);
byte[] unpadded = paddedDecryptor.TransformFinalBlock(
    paddedWindow, 2, paddedWindow.Length - 2);
File.WriteAllBytes(Path.Combine(folder, tag + "-unpadded.bin"), unpadded);

bool badInput = false;
try
{
    decryptor.TransformFinalBlock(cipher, 0, cipher.Length - 1);
}
catch (CryptographicException)
{
    badInput = true;
}
bool badKey = false;
try
{
    aes.Key = new byte[3];
}
catch (CryptographicException)
{
    badKey = true;
}
File.WriteAllText(Path.Combine(folder, tag + "-state.txt"),
    badInput && badKey ? "aes-ok;bad-input;bad-key" : "aes-bad");
