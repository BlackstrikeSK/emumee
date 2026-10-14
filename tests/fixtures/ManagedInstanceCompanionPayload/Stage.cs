using System;
using System.IO;

namespace Companion;

public sealed class Stage
{
    private readonly string message;

    public Stage(string message)
    {
        this.message = message;
    }

    public string Run()
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        File.WriteAllText(Path.Combine(roaming, "managed-instance-companion-payload.txt"), message);
        return message;
    }
}
