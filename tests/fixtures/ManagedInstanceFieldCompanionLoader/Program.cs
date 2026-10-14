using System;
using System.IO;
using InstanceFieldPayload;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
Stage stage = new();
bool defaults = stage.Count == 0 && stage.Marker == "ready";
stage.Count = 9;
stage.Marker = "written";
bool changed = stage.Count == 9 && stage.Marker == "written";
Stage other = new();
bool independent = other.Count == 0 && other.Marker == "ready";
bool nullCaught = false;
try
{
    Stage? absent = null;
    _ = absent!.Count;
}
catch (NullReferenceException)
{
    nullCaught = true;
}
File.WriteAllText(Path.Combine(roaming, "managed-companion-instance-field.txt"),
                  defaults && changed && independent && nullCaught ? "instance-field-ok" : "wrong");
