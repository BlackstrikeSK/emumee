using System;
using System.IO;

string original = Directory.GetCurrentDirectory();
string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string tag = "emumee-full-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
string stage = Path.Combine(roaming, tag + "-stage");
Directory.CreateDirectory(stage);
Directory.SetCurrentDirectory(stage);
string relative = @"..\" + tag + ".bin";
string resolved = Path.GetFullPath(relative);
string explicitBase = Path.GetFullPath(tag + ".bin", roaming);
bool pathsOk = resolved == Path.Combine(roaming, tag + ".bin") &&
    explicitBase == resolved && Path.GetFullPath(resolved) == resolved &&
    Path.GetFullPath("", stage) == stage;
File.WriteAllText(resolved, "guest-full-path-payload");
bool nullError = false;
try
{
    Path.GetFullPath(null!);
}
catch (ArgumentNullException)
{
    nullError = true;
}
bool emptyError = false;
try
{
    Path.GetFullPath("");
}
catch (ArgumentException)
{
    emptyError = true;
}
bool baseError = false;
try
{
    Path.GetFullPath("file.bin", "relative-base");
}
catch (ArgumentException)
{
    baseError = true;
}
Directory.SetCurrentDirectory(original);
Directory.Delete(stage);
File.WriteAllText(Path.Combine(roaming, tag + "-state.txt"),
    pathsOk && nullError && emptyError && baseError
    ? "full-path-ok;null;empty;base" : "full-path-bad");
