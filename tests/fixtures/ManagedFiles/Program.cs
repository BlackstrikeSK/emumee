using System.IO;

const string guest = @"C:\Users\Alex\Downloads\managed-append.txt";
const string marker = @"C:\Users\Alex\Downloads\managed-state.txt";
const string copy = @"C:\Users\Alex\Downloads\managed-persona-copy.txt";
const string source = @"C:\Users\Alex\Documents\readme.txt";

File.Delete(guest);
File.WriteAllText(marker, File.Exists(guest) ? "unexpected" : "missing");
File.AppendAllText(guest, "harmless ");
File.AppendAllText(guest, "managed append marker");
File.WriteAllText(marker, File.Exists(guest) ? "present" : "unexpected");
File.WriteAllText(copy, File.ReadAllText(source));
File.WriteAllText(@"C:\Users\Alex\Downloads\managed-content.txt", File.ReadAllText(guest));
File.Delete(guest);
File.Delete(source);
File.WriteAllText(marker, File.Exists(guest) || File.Exists(source) ? "unexpected" : "deleted");
