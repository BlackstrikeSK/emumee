using System;
using System.IO;
using System.IO.Compression;

byte[] packed = Convert.FromBase64String(
    "UEsDBBQAAAAIAAAAIVDGFiaOHQAAABsAAAALAAAAcGF5bG9hZC5iaW6ryixQSC9NLS5RKEiszMlPTFEoSy3KTMtMTVEEAFBLAwQUAAAACAAAACFQ90ft0hEAAAARAAAAEQAAAG5lc3RlZC9yZWFkbWUudHh0y0stLklNUUgvBdIKaZk5qQBQSwECFAAUAAAACAAAACFQxhYmjh0AAAAbAAAACwAAAAAAAAAAAAAAgAEAAAAAcGF5bG9hZC5iaW5QSwECFAAUAAAACAAAACFQ90ft0hEAAAARAAAAEQAAAAAAAAAAAAAAgAFGAAAAbmVzdGVkL3JlYWRtZS50eHRQSwUGAAAAAAIAAgB4AAAAhgAAAAAA");
string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string tag = "emumee-zipentry-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
string archivePath = Path.Combine(roaming, tag + ".zip");
File.WriteAllBytes(archivePath, packed);
using var archive = ZipFile.OpenRead(archivePath);
var entries = archive.Entries;
bool indexed = entries.Count == 2
    && entries[0].FullName == "payload.bin"
    && entries[1].FullName == "nested/readme.txt";
int enumerated = 0;
uint unsignedCount = uint.MaxValue - (uint)entries.Count;
bool unsignedOrder = unsignedCount > 2U;
ZipArchiveEntry? selected = null;
foreach (ZipArchiveEntry candidate in entries)
{
    if (candidate.FullName == "payload.bin" || candidate.FullName == "nested/readme.txt")
        enumerated++;
    if (candidate.FullName == "payload.bin")
        selected = candidate;
}
ZipArchiveEntry? entry = archive.GetEntry("payload.bin");
bool missing = archive.GetEntry("PAYLOAD.BIN") == null;
using var opened = selected!.Open();
using var target = new MemoryStream();
opened.CopyTo(target);
byte[] payload = target.ToArray();
File.WriteAllBytes(Path.Combine(roaming, tag + "-selected.bin"), payload);
using var memory = new MemoryStream(packed);
using var second = new ZipArchive(memory, ZipArchiveMode.Read, true);
ZipArchiveEntry? nested = second.GetEntry("nested/readme.txt");
using var nestedStream = nested!.Open();
using var nestedTarget = new MemoryStream();
nestedStream.CopyTo(nestedTarget);
File.WriteAllBytes(Path.Combine(roaming, tag + "-state.txt"),
    System.Text.Encoding.UTF8.GetBytes(
        indexed && enumerated == 2 && unsignedOrder && selected != null && missing
        && entry.FullName == "payload.bin" && entry.Name == "payload.bin"
        && entry.Length == payload.Length && nested != null
        && nestedTarget.Length == 17 && memory.CanRead
        ? "zip-entry-ok" : "zip-entry-bad"));
