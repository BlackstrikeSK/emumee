using System.IO;

const string source = @"C:\Users\Alex\Documents\readme.txt";
const string copy = @"C:\Users\Alex\Downloads\managed-copy.txt";
const string moved = @"C:\Users\Alex\Downloads\managed-moved.txt";
const string target = @"C:\Users\Alex\Downloads\managed-target.txt";
const string status = @"C:\Users\Alex\Downloads\managed-transfer-state.txt";

File.Copy(source, copy);
try
{
    File.Copy(source, copy);
}
catch (IOException)
{
    File.WriteAllText(status, "copy collision");
}
File.WriteAllText(copy, "old copy");
File.Copy(source, copy, true);
File.Move(copy, moved);
File.WriteAllText(target, "old target");
try
{
    File.Move(moved, target);
}
catch (IOException)
{
    File.WriteAllText(status, "move collision");
}
File.Move(moved, target, true);
File.Move(target, target);
File.WriteAllText(@"C:\Users\Alex\Downloads\managed-transfer-output.txt",
                  File.ReadAllText(target));
File.WriteAllText(status,
                  File.Exists(source) && !File.Exists(copy) && !File.Exists(moved)
                      ? "transferred" : "unexpected");
