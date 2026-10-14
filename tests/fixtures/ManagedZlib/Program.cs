using System;
using System.IO;
using System.IO.Compression;

byte[] compressed = Convert.FromBase64String(
    "eJyryslMUkgvTS0uUShIrMzJT0xRKEstykzLTE1RZGBkYmZhZWPn4OTi5uHl4xcQFBIWERUTl5CUkpaRlZNXUFRSVlFVU9fQ1NLW0dXTNzA0MjYxNTO3sLSytrG1s3dwdHJ2cXVz9/D08vbx9fMPCAwKDgkNC4+IjIqOiY2LT0hMSk5JTUvPyMzKzsnNyy8oLCouKS0rr6isqq6prasHADu/KlM=");
string folder = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string tag = "emumee-zlib-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
string sourcePath = Path.Combine(folder, tag + "-source.bin");
File.WriteAllBytes(sourcePath, compressed);
using var input = File.OpenRead(sourcePath);
var zlib = new ZLibStream(input, CompressionMode.Decompress, true);
using var output = new MemoryStream();
byte[] first = new byte[1];
int firstRead = zlib.Read(first, 0, 1);
long sourcePosition = input.Position;
output.Write(first, 0, firstRead);
zlib.CopyTo(output);
byte[] decoded = output.ToArray();
File.WriteAllBytes(Path.Combine(folder, tag + "-payload.bin"), decoded);
bool eof = zlib.Read(first, 0, 1) == 0;
zlib.Dispose();
bool stillOpen = input.CanRead;
bool caught = false;
try
{
    using var brokenSource = new MemoryStream(new byte[] { 1, 2, 3 });
    using var broken = new ZLibStream(brokenSource, CompressionMode.Decompress);
    using var sink = new MemoryStream();
    broken.CopyTo(sink);
}
catch (InvalidDataException)
{
    caught = true;
}
File.WriteAllText(Path.Combine(folder, tag + "-state.txt"),
    firstRead == 1 && sourcePosition < compressed.Length && decoded.Length == 156
        && eof && stillOpen && caught
        ? "zlib-ok;partial-read;file;leave-open;invalid-catch"
        : "zlib-bad");
