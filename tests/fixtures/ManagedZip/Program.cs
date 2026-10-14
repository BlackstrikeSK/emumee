using System;
using System.IO;
using System.IO.Compression;

byte[] good = Convert.FromBase64String(
    "UEsDBBQAAAAIAAAAIVDGFiaOHQAAABsAAAALAAAAcGF5bG9hZC5iaW6ryixQSC9NLS5RKEiszMlPTFEoSy3KTMtMTVEEAFBLAwQUAAAACAAAACFQ90ft0hEAAAARAAAAEQAAAG5lc3RlZC9yZWFkbWUudHh0y0stLklNUUgvBdIKaZk5qQBQSwECFAAUAAAACAAAACFQxhYmjh0AAAAbAAAACwAAAAAAAAAAAAAAgAEAAAAAcGF5bG9hZC5iaW5QSwECFAAUAAAACAAAACFQ90ft0hEAAAARAAAAEQAAAAAAAAAAAAAAgAFGAAAAbmVzdGVkL3JlYWRtZS50eHRQSwUGAAAAAAIAAgB4AAAAhgAAAAAA");
byte[] bad = Convert.FromBase64String(
    "UEsDBBQAAAAIAAAAIVBbAbieEQAAAA8AAAANAAAALi4vZXNjYXBlLmJpbsstLS5RyMsvUUgtTk4sSAUAUEsBAhQAFAAAAAgAAAAhUFsBuJ4RAAAADwAAAA0AAAAAAAAAAAAAAIABAAAAAC4uL2VzY2FwZS5iaW5QSwUGAAAAAAEAAQA7AAAAPAAAAAAA");
string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string tag = "emumee-zip-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
string source = Path.Combine(roaming, tag + "-source.zip");
string badSource = Path.Combine(roaming, tag + "-bad.zip");
string destination = Path.Combine(roaming, tag);
File.WriteAllBytes(source, good);
ZipFile.ExtractToDirectory(source, destination);
string payload = File.ReadAllText(Path.Combine(destination, "payload.bin"));
string nested = File.ReadAllText(Path.Combine(destination, "nested", "readme.txt"));
bool collision = false;
try { ZipFile.ExtractToDirectory(source, destination); }
catch (IOException) { collision = true; }
ZipFile.ExtractToDirectory(source, destination, true);
using var memorySource = new MemoryStream(good);
ZipFile.ExtractToDirectory(memorySource, Path.Combine(roaming, tag + "-memory"));
bool memoryConsumed = memorySource.Position == memorySource.Length;
using var fileSource = File.OpenRead(source);
ZipFile.ExtractToDirectory(fileSource, Path.Combine(roaming, tag + "-filestream"));
bool fileConsumed = fileSource.Position == fileSource.Length;
File.WriteAllBytes(badSource, bad);
bool traversal = false;
try { ZipFile.ExtractToDirectory(badSource, destination); }
catch (IOException) { traversal = true; }
byte[] malformedArchive = new byte[good.Length];
for (int i = 0; i < good.Length; i++) malformedArchive[i] = good[i];
int endRecord = good.Length - 22;
malformedArchive[endRecord + 8] = 1;
malformedArchive[endRecord + 10] = 1;
string malformedSource = Path.Combine(roaming, tag + "-malformed.zip");
File.WriteAllBytes(malformedSource, malformedArchive);
bool malformed = false;
try { ZipFile.ExtractToDirectory(malformedSource, Path.Combine(roaming, tag + "-malformed")); }
catch (InvalidDataException) { malformed = true; }
File.WriteAllText(Path.Combine(roaming, tag + "-state.txt"),
    payload == "zip guest payload verified!" && nested == "nested guest file"
    && collision && traversal && malformed && memoryConsumed && fileConsumed
    && !File.Exists(Path.Combine(roaming, "escape.bin"))
    && Directory.Exists(Path.Combine(destination, "nested"))
        ? "zip-ok;nested;overwrite;streams;traversal-denied;malformed-denied"
        : "zip-bad");
