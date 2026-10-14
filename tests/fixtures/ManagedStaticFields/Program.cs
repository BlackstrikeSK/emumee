using System;
using System.IO;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
bool first = ExplicitStage.Ready();
bool second = ExplicitStage.Ready();
bool defaults = DefaultStage.Number == 0 && DefaultStage.Text is null;
bool inline = InlineStage.Value == "inline";
File.WriteAllText(Path.Combine(roaming, "managed-static-state.txt"),
                  first && second && defaults && inline ? "static-ok" : "wrong");

public static class ExplicitStage
{
    public static string? Marker;
    public static int Count;

    static ExplicitStage()
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        File.WriteAllText(Path.Combine(roaming, "managed-static-cctor.txt"), "initialized");
        Marker = "ready";
        Count = 7;
    }

    public static bool Ready() => Marker == "ready" && Count == 7;
}

public static class DefaultStage
{
    public static int Number;
    public static string? Text;
}

public static class InlineStage
{
    public static string Value = "inline";
}
