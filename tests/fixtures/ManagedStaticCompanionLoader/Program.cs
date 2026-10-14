using System;
using System.IO;
using Companion;

Stage.Run();
string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
File.WriteAllText(Path.Combine(roaming, "managed-static-companion-state.txt"), "static companion ran");
