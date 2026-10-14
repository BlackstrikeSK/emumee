using System.IO;

const string prefix = @"C:\Users\Alex\Downloads\managed-memory-";
byte[] original = new byte[] { (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F' };
using var working = new MemoryStream();
working.Write(original, 0, original.Length);
working.Position = 2;
working.WriteByte((byte)'Z');
working.SetLength(8);
working.Position = 1;
byte[] window = new byte[5];
int read = working.Read(window, 1, 3);
File.WriteAllBytes(prefix + "read.bin", window);

working.Position = 1;
using (var output = File.Create(prefix + "copy.bin"))
{
    working.CopyTo(output);
}

using var copied = new MemoryStream();
using (var input = File.OpenRead(prefix + "copy.bin"))
{
    input.Seek(2, SeekOrigin.Begin);
    input.CopyTo(copied);
}
File.WriteAllBytes(prefix + "roundtrip.bin", copied.ToArray());

byte[] backing = new byte[] { (byte)'L', (byte)'M', (byte)'N' };
using var fixedBuffer = new MemoryStream(backing);
fixedBuffer.WriteByte((byte)'Q');
bool blockedGrowth = false;
try
{
    fixedBuffer.SetLength(4);
}
catch (NotSupportedException)
{
    blockedGrowth = true;
}
fixedBuffer.Position = 1;
int middle = fixedBuffer.ReadByte();
File.WriteAllBytes(prefix + "backing.bin", backing);
File.WriteAllText(prefix + "state.txt",
    read == 3 && window[1] == 'B' && window[2] == 'Z' && window[3] == 'D'
    && working.Position == 8 && copied.Position == 5 && middle == 'M'
    && blockedGrowth && fixedBuffer.ToArray()[0] == 'Q'
        ? "copy-ok;fixed-ok" : "copy-bad");
