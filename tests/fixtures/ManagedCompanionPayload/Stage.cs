using System;
using System.IO;

namespace Companion;

public static class Stage
{
    public static void Run()
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        File.WriteAllText(Path.Combine(roaming, "managed-companion-payload.txt"),
                          "guest companion ran");
    }
}
