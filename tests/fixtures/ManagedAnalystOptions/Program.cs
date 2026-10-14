using System;

internal static class Program
{
    private static int Main(string[] args)
    {
        Console.WriteLine(args.Length > 0 ? args[0] : "no-argument");
        Console.WriteLine(Environment.GetEnvironmentVariable("EMUMEE_TEST") ?? "no-environment");
        return args.Length;
    }
}
