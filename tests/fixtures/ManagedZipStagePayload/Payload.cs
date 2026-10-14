using System;
using System.IO;

namespace Stage;

public static class Payload
{
    public static void Run()
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string name = "zip-stage-payload-" + Environment.GetEnvironmentVariable("COMPUTERNAME") + ".txt";
        File.WriteAllText(Path.Combine(roaming, name),
            "harmless ZIP-loaded stage");
    }
}
