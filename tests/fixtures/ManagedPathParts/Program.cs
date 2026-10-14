using System;
using System.IO;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string tag = "emumee-path-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
string input = Path.Combine(roaming, tag + ".bin");
string output = Path.ChangeExtension(input, "dat")!;
bool partsOk = Path.GetFileName(input) == tag + ".bin" &&
    Path.GetFileNameWithoutExtension(input) == tag &&
    Path.GetExtension(input) == ".bin" &&
    Path.HasExtension(input) && Path.GetDirectoryName(input) == roaming &&
    Path.IsPathRooted(input) && Path.GetPathRoot(input) == @"C:\" &&
    Path.GetFileName(@"C:\folder\") == "" &&
    Path.GetDirectoryName("loose.bin") == "" &&
    Path.GetExtension(".hidden") == ".hidden" &&
    Path.IsPathRooted("C:loose.bin") && !Path.IsPathRooted("loose.bin") &&
    Path.GetPathRoot("loose.bin") == "";
File.WriteAllText(output, "payload-path-parts");
File.WriteAllText(Path.Combine(roaming, tag + "-state.txt"),
    partsOk ? "parts-ok" : "parts-bad");
