using System.IO;

const string source = @"C:\Users\Alex\Downloads\managed-attributes-source.txt";
const string copy = @"C:\Users\Alex\Downloads\managed-attributes-copy.txt";
const string directory = @"C:\Users\Alex\Downloads\managed-attributes-dir";
const string status = @"C:\Users\Alex\Downloads\managed-attributes-state.txt";

File.WriteAllText(source, "harmless attribute payload");
File.SetAttributes(source, FileAttributes.Hidden | FileAttributes.ReadOnly);
File.WriteAllText(status,
    File.GetAttributes(source) == (FileAttributes.Hidden | FileAttributes.ReadOnly)
        ? "source flags" : "wrong source flags");
try
{
    File.AppendAllText(source, "blocked");
}
catch (UnauthorizedAccessException)
{
    File.WriteAllText(status, "append denied");
}
try
{
    File.Delete(source);
}
catch (UnauthorizedAccessException)
{
    File.WriteAllText(status, "delete denied");
}
File.Copy(source, copy);
File.WriteAllText(status,
    File.GetAttributes(copy) == (FileAttributes.Hidden | FileAttributes.ReadOnly)
        ? "copy flags" : "wrong copy flags");
try
{
    File.WriteAllText(copy, "blocked");
}
catch (UnauthorizedAccessException)
{
    File.WriteAllText(status, "overwrite denied");
}
File.SetAttributes(copy, FileAttributes.Normal);
File.WriteAllText(copy, "writable copy");
File.Delete(copy);
File.SetAttributes(source, FileAttributes.Normal);
File.Delete(source);
Directory.CreateDirectory(directory);
File.SetAttributes(directory, FileAttributes.Hidden);
File.WriteAllText(status,
    File.GetAttributes(directory) == (FileAttributes.Directory | FileAttributes.Hidden)
        ? "directory hidden" : "wrong directory flags");
File.SetAttributes(directory, FileAttributes.Normal);
Directory.Delete(directory);
File.WriteAllText(status,
    !File.Exists(source) && !File.Exists(copy) && !Directory.Exists(directory)
        ? "cleared" : "still present");
