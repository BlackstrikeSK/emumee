using System.IO;
using System.Reflection;

namespace ResourcePayload;

public static class Stage
{
    public static byte[] Recover()
    {
        Assembly assembly = Assembly.GetExecutingAssembly();
        using Stream source = assembly.GetManifestResourceStream("companion.dat")!;
        using MemoryStream destination = new();
        source.CopyTo(destination);
        return destination.ToArray();
    }
}
