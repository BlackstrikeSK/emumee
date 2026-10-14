using System;
using System.IO;

namespace StaticFieldPayload;

public static class SharedStage
{
    public static int Count;
    public static string? Marker;

    static SharedStage()
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        File.WriteAllText(Path.Combine(roaming, "managed-companion-static-init.txt"), "initialized");
        Count = 7;
        Marker = "ready";
    }
}
