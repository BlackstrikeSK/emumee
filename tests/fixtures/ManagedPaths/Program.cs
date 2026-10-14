using System;
using System.IO;

string original = Directory.GetCurrentDirectory();
string temp = Path.GetTempPath();
string stage = Path.Combine(temp, "emumee-stage");
Directory.CreateDirectory(stage);
Directory.SetCurrentDirectory(stage);
File.WriteAllText("relative.txt", "harmless guest-relative marker");
File.WriteAllText(Path.Combine(original, "managed-temp-path.txt"), temp);
File.WriteAllText(Path.Combine(original, "managed-env-temp.txt"),
                  Environment.GetEnvironmentVariable("TEMP"));
File.WriteAllText(Path.Combine(original, "managed-current-dir.txt"),
                  Directory.GetCurrentDirectory());
File.WriteAllText(Path.Combine(original, "managed-relative-echo.txt"),
                  File.ReadAllText(Path.Combine(stage, "relative.txt")));
File.Delete("relative.txt");
Directory.SetCurrentDirectory(original);
Directory.Delete(stage);
