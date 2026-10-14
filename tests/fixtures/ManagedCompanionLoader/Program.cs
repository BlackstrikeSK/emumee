using System;
using System.IO;
using System.Reflection;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
bool missingCaught = false;
try
{
    Assembly.Load("HostOnlyNeverLoad");
}
catch (FileNotFoundException)
{
    missingCaught = true;
}
Assembly companion = Assembly.Load("ManagedCompanionPayload");
companion.GetType("Companion.Stage")!.GetMethod("Run")!.Invoke(null, null);
File.WriteAllText(Path.Combine(roaming, "managed-companion-state.txt"),
                  missingCaught ? "loaded;missing" : "host-fallback");
