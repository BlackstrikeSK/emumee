using System.IO;

const string root = @"C:\Users\Alex\Downloads\managed-dir";
const string nested = root + @"\nested";
const string payload = nested + @"\payload.txt";
const string status = @"C:\Users\Alex\Downloads\managed-dir-state.txt";

if (!Directory.Exists(root)) File.WriteAllText(status, "missing");
try
{
    File.AppendAllText(payload, "too early");
}
catch (DirectoryNotFoundException)
{
    File.WriteAllText(status, "missing parent");
}

Directory.CreateDirectory(nested);
if (Directory.Exists(root) && Directory.Exists(nested))
    File.WriteAllText(status, "present");
File.WriteAllText(payload, "harmless managed directory marker");
try
{
    Directory.Delete(root);
}
catch (IOException)
{
    File.WriteAllText(status, "nonempty");
}

File.Delete(payload);
Directory.Delete(nested);
Directory.Delete(root);
File.WriteAllText(status, Directory.Exists(root) ? "unexpected" : "deleted");
