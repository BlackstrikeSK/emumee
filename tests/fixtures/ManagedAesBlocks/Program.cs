using System;
using System.IO;
using System.Security.Cryptography;

byte[] key = Convert.FromBase64String("K34VFiiu0qar9xWICc9PPA==");
byte[] iv = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
byte[] plain = Convert.FromBase64String(
    "bWFuYWdlZCBhZXMgc3RyZWFtaW5nIHBheWxvYWQgdmVyaWZpZWQh");
string folder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string tag = "emumee-aes-blocks-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
using var aes = Aes.Create();
aes.Key = key;
aes.IV = iv;
aes.Mode = CipherMode.CBC;
aes.Padding = PaddingMode.PKCS7;
using var encryptor = aes.CreateEncryptor();
byte[] encryptedBuffer = new byte[64];
int first = encryptor.TransformBlock(plain, 0, 16, encryptedBuffer, 1);
int second = encryptor.TransformBlock(plain, 16, 16, encryptedBuffer, 1 + first);
byte[] encryptedTail = encryptor.TransformFinalBlock(plain, 32, plain.Length - 32);
byte[] cipher = new byte[first + second + encryptedTail.Length];
for (int i = 0; i < first + second; i++) cipher[i] = encryptedBuffer[i + 1];
for (int i = 0; i < encryptedTail.Length; i++) cipher[first + second + i] = encryptedTail[i];
File.WriteAllBytes(Path.Combine(folder, tag + "-cipher.bin"), cipher);

using var decryptor = aes.CreateDecryptor(key, iv);
byte[] decryptedBuffer = new byte[64];
int decryptedBlocks = decryptor.TransformBlock(cipher, 0, cipher.Length, decryptedBuffer, 2);
byte[] decryptedTail = decryptor.TransformFinalBlock(new byte[0], 0, 0);
byte[] recovered = new byte[decryptedBlocks + decryptedTail.Length];
for (int i = 0; i < decryptedBlocks; i++) recovered[i] = decryptedBuffer[i + 2];
for (int i = 0; i < decryptedTail.Length; i++) recovered[decryptedBlocks + i] = decryptedTail[i];
File.WriteAllBytes(Path.Combine(folder, tag + "-plain.bin"), recovered);

bool smallOutput = false;
try
{
    decryptor.TransformBlock(cipher, 0, 16, new byte[15], 0);
}
catch (ArgumentOutOfRangeException)
{
    smallOutput = true;
}
bool partialInput = false;
try
{
    decryptor.TransformBlock(cipher, 0, 15, new byte[16], 0);
}
catch (ArgumentOutOfRangeException)
{
    partialInput = true;
}
byte[] reused = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
bool matches = reused.Length == plain.Length;
for (int i = 0; i < reused.Length && matches; i++) matches = reused[i] == plain[i];
File.WriteAllText(Path.Combine(folder, tag + "-state.txt"),
    first == 16 && second == 16 && encryptedTail.Length == 16 &&
    decryptedBlocks == 32 && decryptedTail.Length == 7 &&
    encryptor.InputBlockSize == 16 && encryptor.OutputBlockSize == 16 &&
    encryptor.CanReuseTransform && encryptor.CanTransformMultipleBlocks &&
    smallOutput && partialInput && matches
        ? "aes-blocks-ok;hold-final;reuse;bounds"
        : "aes-blocks-bad");
