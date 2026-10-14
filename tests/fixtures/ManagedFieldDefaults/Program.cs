using System;
using System.IO;

DefaultsStage stage = new();
string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
File.WriteAllText(Path.Combine(roaming, "managed-field-defaults.txt"), stage.Check());

public class BaseDefaults
{
    protected int baseCount;
    protected string? baseText;
}

public sealed class DefaultsStage : BaseDefaults
{
    private bool enabled;
    private int count;
    private long longCount;
    private double ratio;
    private char letter;
    private string? text;
    private byte[]? data;
    private object? handle;

    public string Check()
    {
        bool valid = baseCount == 0 && baseText is null && !enabled && count == 0 &&
                     longCount == 0 && ratio == 0.0 && letter == '\0' && text is null &&
                     data is null && handle is null;
        count = 42;
        return valid && count == 42 ? "defaults-ok" : "wrong";
    }
}
