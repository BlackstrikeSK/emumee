using System.IO;

const string root = @"C:\Users\Alex\Downloads\managed-tree";
const string nested = root + @"\nested\deeper";
const string payload = nested + @"\payload.txt";
const string status = @"C:\Users\Alex\Downloads\managed-tree-state.txt";

Directory.CreateDirectory(nested);
File.WriteAllText(payload, "harmless recursive payload");
File.WriteAllText(status, "created");
try
{
    Directory.Delete(root);
}
catch (IOException)
{
    File.WriteAllText(status, "nonrecursive denied");
}
Directory.Delete(root, true);
File.WriteAllText(status,
    !Directory.Exists(root) && !Directory.Exists(nested) && !File.Exists(payload)
        ? "tree deleted" : "tree remained");
try
{
    Directory.Delete(root, true);
}
catch (DirectoryNotFoundException)
{
    File.WriteAllText(status, "missing denied");
}
Directory.CreateDirectory(root);
File.WriteAllText(root + @"\recreated.txt", "recreated guest file");
File.WriteAllText(status,
    Directory.Exists(root) && File.Exists(root + @"\recreated.txt")
        ? "recreated" : "recreate failed");
