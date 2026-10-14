#pragma warning disable SYSLIB0014
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;

// A deliberately inert malware-behavior fixture. Never run its actions unless
// the Emumee test harness explicitly opts in through the guest environment.
if (Environment.GetEnvironmentVariable("EMUMEE_TEST") != "virtual")
    return 2;

byte[] key = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
byte[] iv = Convert.FromBase64String("EBESExQVFhcYGRobHB0eHw==");
byte[] cipher = Convert.FromBase64String(
    "OZk7lxB0x9F9ZkorCqj5Zu8CckKT3e3ajxZ7BzU/aRVu8grkG977SiDlZ0Iq9c7zvgvh/DynYfWX6D5CZz/BJA==");
using var aes = Aes.Create();
aes.Key = key;
aes.IV = iv;
byte[] payload = aes.CreateDecryptor().TransformFinalBlock(cipher, 0, cipher.Length);

// The payload is a fixed JSON canary, never executable code or host data.
File.WriteAllBytes(@"C:\Users\Alex\Downloads\emumee-threat-canary.json", payload);

// The reserved .invalid domain makes this an observable network attempt without
// a reachable command server. Emumee's default offline policy denies the call.
try
{
    var client = new WebClient();
    client.DownloadString("https://example.invalid/emumee-canary");
    return 1;
}
catch (WebException)
{
    return 0;
}
