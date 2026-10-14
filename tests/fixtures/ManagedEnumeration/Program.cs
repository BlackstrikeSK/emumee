using System.IO;

const string root = @"C:\Users\Alex\Downloads\EnumStage";
const string nested = root + @"\Nested";
const string deep = nested + @"\Deep";
const string prefix = @"C:\Users\Alex\Downloads\managed-enum-";

Directory.CreateDirectory(deep);
File.WriteAllText(root + @"\Alpha.bin", "alpha");
File.WriteAllText(root + @"\beta.TXT", "beta");
File.WriteAllText(nested + @"\Gamma.txt", "gamma");
File.WriteAllText(nested + @"\extensionless", "plain");
File.WriteAllText(deep + @"\delta.txt", "delta");

string[] top = Directory.GetFiles(root, "*.TXT");
File.WriteAllText(prefix + "top.txt", top.Length == 1 ? top[0] : "wrong top count");
string[] recursive = Directory.GetFiles(root, "*.txt", SearchOption.AllDirectories);
string fileList = "";
foreach (string entry in recursive) fileList += entry + "\n";
File.WriteAllText(prefix + "files.txt", fileList);

string[] directories = Directory.GetDirectories(root, "*", SearchOption.AllDirectories);
string directoryList = "";
foreach (string entry in directories) directoryList += entry + "\n";
File.WriteAllText(prefix + "directories.txt", directoryList);

string[] all = Directory.GetFileSystemEntries(root, "*.*", SearchOption.AllDirectories);
string allList = "";
foreach (string entry in all) allList += entry + "\n";
File.WriteAllText(prefix + "all.txt", allList);

File.Delete(root + @"\beta.TXT");
Directory.Delete(nested, true);
File.WriteAllText(prefix + "after.txt",
    Directory.GetFiles(root, "*", SearchOption.AllDirectories).Length == 1 &&
    Directory.GetDirectories(root).Length == 0 ? "cleaned" : "remaining");
