using System.IO;

const string source = @"C:\Users\Alex\Downloads\managed-array-source.bin";
const string edited = @"C:\Users\Alex\Downloads\managed-array-edited.bin";
const string state = @"C:\Users\Alex\Downloads\managed-array-state.txt";

File.WriteAllBytes(source, new byte[] { (byte)'A', (byte)'B', (byte)'C' });
byte[] first = File.ReadAllBytes(source);
first[1] = (byte)'Z';
byte[] second = File.ReadAllBytes(source);
File.WriteAllBytes(edited, first);
string outcome = second[1] == (byte)'B' ? "independent" : "aliased";
try
{
    first[-1] = (byte)'X';
}
catch (IndexOutOfRangeException)
{
    outcome += ";negative-index";
}
try
{
    _ = first[first.Length];
}
catch (IndexOutOfRangeException)
{
    outcome += ";upper-bound";
}
try
{
    ref byte bad = ref first[-1];
    bad = (byte)'X';
}
catch (IndexOutOfRangeException)
{
    outcome += ";negative-ref";
}
byte[]? absent = null;
try
{
    _ = absent!.Length;
}
catch (NullReferenceException)
{
    outcome += ";null-array";
}
File.WriteAllText(state, outcome);
