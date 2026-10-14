using System.IO;

const string file = @"C:\Users\Alex\Downloads\managed-stream.bin";
const string read = @"C:\Users\Alex\Downloads\managed-stream-read.bin";
const string final = @"C:\Users\Alex\Downloads\managed-stream-final.bin";
const string state = @"C:\Users\Alex\Downloads\managed-stream-state.txt";

byte[] body = Convert.FromBase64String("QUJDREVG"); // ABCDEF
FileStream output = File.Create(file);
output.Write(body, 0, body.Length);
output.Position = 2;
output.WriteByte((byte)'Z');
output.SetLength(8);
output.Close();

FileStream input = File.OpenRead(file);
byte[] buffer = new byte[10];
int count = input.Read(buffer, 1, 4);
long length = input.Length;
long position = input.Position;
long seek = input.Seek(-1, SeekOrigin.End);
int last = input.ReadByte();
input.Close();
File.WriteAllBytes(read, buffer);
File.WriteAllText(state, count == 4 && length == 8 && position == 4 && seek == 7 && last == 0
    ? "read-ok" : "read-bad");

FileStream writer = File.OpenWrite(file);
bool denied = false;
try
{
    File.ReadAllBytes(file);
}
catch (IOException)
{
    denied = true;
}
writer.WriteByte((byte)'Q');
writer.Close();
File.WriteAllBytes(final, File.ReadAllBytes(file));
File.AppendAllText(state, denied ? ";share-denied" : ";share-bad");

FileStream constructor = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
FileStream opened = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.Read);
int fromConstructor = constructor.ReadByte();
int fromOpen = opened.ReadByte();
constructor.Close();
opened.Close();
File.AppendAllText(state, fromConstructor == 'Q' && fromOpen == 'Q'
    ? ";constructors-ok" : ";constructors-bad");
