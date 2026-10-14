using System;
using System.IO;
using System.Security.Cryptography;

byte[] key = Convert.FromBase64String("K34VFiiu0qar9xWICc9PPA==");
byte[] iv = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
byte[] plain = Convert.FromBase64String(
    "bWFuYWdlZCBhZXMgc3RyZWFtaW5nIHBheWxvYWQgdmVyaWZpZWQh");
byte[] cipher = Convert.FromBase64String(
    "1tAgYJrRvuZpSKWorSt6Ei/rqKmY0F5myUUr19RJySOwtxOrvLsUbPOnq5F+HQY3");
string folder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string tag = "emumee-cryptostream-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
using var aes = Aes.Create();
aes.Key = key;
aes.IV = iv;

using var encryptedSource = new MemoryStream(cipher);
using var readDecryptor = aes.CreateDecryptor();
using var readCrypto = new CryptoStream(
    encryptedSource, readDecryptor, CryptoStreamMode.Read, true);
using var readTarget = new MemoryStream();
byte[] firstByte = new byte[1];
int firstRead = readCrypto.Read(firstByte, 0, firstByte.Length);
long sourcePositionAfterFirst = encryptedSource.Position;
readTarget.Write(firstByte, 0, firstRead);
readCrypto.CopyTo(readTarget);
byte[] readPlain = readTarget.ToArray();
File.WriteAllBytes(Path.Combine(folder, tag + "-read.bin"), readPlain);
byte[] eofBuffer = new byte[3];
bool reachedEof = readCrypto.Read(eofBuffer, 0, eofBuffer.Length) == 0;

using var writeTarget = new MemoryStream();
using var encryptor = aes.CreateEncryptor();
using var writeCrypto = new CryptoStream(
    writeTarget, encryptor, CryptoStreamMode.Write, true);
writeCrypto.Write(plain, 0, 5);
writeCrypto.Write(plain, 5, plain.Length - 5);
bool beforeFlush = !writeCrypto.HasFlushedFinalBlock;
writeCrypto.FlushFinalBlock();
bool afterFlush = writeCrypto.HasFlushedFinalBlock;
byte[] writeCipher = writeTarget.ToArray();
File.WriteAllBytes(Path.Combine(folder, tag + "-write.bin"), writeCipher);
bool doubleFlush = false;
try
{
    writeCrypto.FlushFinalBlock();
}
catch (NotSupportedException)
{
    doubleFlush = true;
}

using var decryptTarget = new MemoryStream();
using var writeDecryptor = aes.CreateDecryptor();
using var decryptCrypto = new CryptoStream(
    decryptTarget, writeDecryptor, CryptoStreamMode.Write, true);
decryptCrypto.Write(cipher, 0, 17);
decryptCrypto.Write(cipher, 17, cipher.Length - 17);
decryptCrypto.FlushFinalBlock();
byte[] writePlain = decryptTarget.ToArray();
File.WriteAllBytes(Path.Combine(folder, tag + "-write-decrypt.bin"), writePlain);

using (var file = File.Create(Path.Combine(folder, tag + "-file.bin")))
using (var fileDecryptor = aes.CreateDecryptor())
using (var fileCrypto = new CryptoStream(file, fileDecryptor, CryptoStreamMode.Write))
{
    fileCrypto.Write(cipher, 0, cipher.Length);
}

bool sameRead = readPlain.Length == plain.Length;
for (int i = 0; i < readPlain.Length && sameRead; i++) sameRead = readPlain[i] == plain[i];
bool sameWrite = writeCipher.Length == cipher.Length;
for (int i = 0; i < writeCipher.Length && sameWrite; i++) sameWrite = writeCipher[i] == cipher[i];
bool sameDecrypt = writePlain.Length == plain.Length;
for (int i = 0; i < writePlain.Length && sameDecrypt; i++)
    sameDecrypt = writePlain[i] == plain[i];
File.WriteAllText(Path.Combine(folder, tag + "-state.txt"),
    sameRead && sameWrite && sameDecrypt && reachedEof && beforeFlush && afterFlush && doubleFlush
    && firstRead == 1 && sourcePositionAfterFirst < encryptedSource.Length
        ? "cryptostream-ok;read;write;file;flush;leave-open"
        : "cryptostream-bad");
