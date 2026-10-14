using System;
using System.IO;
using System.Security.Cryptography;

string password = "blue-team-fixture";
byte[] salt = Convert.FromBase64String("AQIDBAUGBwgJCgsMDQ4PEA==");
byte[] cipher = Convert.FromBase64String(
    "rYRazBnV5e1nxggoK0RAujUmiwWAe/RBUOarnrGRuLRPB0N8aW3vgHAMSkEaxDO/");
string folder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string tag = "emumee-pbkdf2-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
using var derive = new Rfc2898DeriveBytes(password, salt, 1000, HashAlgorithmName.SHA256);
byte[] key = derive.GetBytes(32);
byte[] iv = derive.GetBytes(16);
using var aes = Aes.Create();
aes.Key = key;
aes.IV = iv;
using var decryptor = aes.CreateDecryptor();
byte[] plain = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);
File.WriteAllBytes(Path.Combine(folder, tag + "-payload.bin"), plain);

using var legacy = new Rfc2898DeriveBytes(password, salt, 1000);
byte[] first = legacy.GetBytes(17);
byte[] second = legacy.GetBytes(23);
legacy.Reset();
byte[] reset = legacy.GetBytes(40);
bool continuous = true;
for (int i = 0; i < 40; i++)
    if (reset[i] != (i < 17 ? first[i] : second[i - 17])) continuous = false;
byte[] oneShot = Rfc2898DeriveBytes.Pbkdf2(password, salt, 1000, HashAlgorithmName.SHA256, 48);
bool oneShotMatches = true;
for (int i = 0; i < 48; i++)
    if (oneShot[i] != (i < 32 ? key[i] : iv[i - 32])) oneShotMatches = false;
bool caught = false;
try { legacy.GetBytes(-1); }
catch (ArgumentOutOfRangeException) { caught = true; }
File.WriteAllText(Path.Combine(folder, tag + "-state.txt"),
    continuous && oneShotMatches && caught
        ? "pbkdf2-ok;sha1;sha256;reset;oneshot;catch"
        : "pbkdf2-bad");
