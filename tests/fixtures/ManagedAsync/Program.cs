using System.IO;
using System.Threading.Tasks;

internal static class Program
{
    private static async Task Main()
    {
        await File.WriteAllTextAsync("async-marker.txt", "async reached");
    }
}
