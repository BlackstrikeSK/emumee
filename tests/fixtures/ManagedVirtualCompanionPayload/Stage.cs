using System;
using System.IO;

namespace Companion;

public class BaseStage
{
    protected readonly string message;

    public BaseStage(string message)
    {
        this.message = message;
    }

    public virtual string Run() => "base";

    public string Fixed() => "fixed";
}

public class ShadowStage : BaseStage
{
    public ShadowStage(string message) : base(message) { }

    public new virtual string Run() => "shadow";

    public new string Fixed() => "shadow-fixed";
}

public sealed class ShadowChildStage : ShadowStage
{
    public ShadowChildStage(string message) : base(message) { }

    public override string Run() => "shadow-child";
}

public sealed class DerivedStage : BaseStage
{
    public DerivedStage(string message) : base(message) { }

    public override string Run()
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        File.WriteAllText(Path.Combine(roaming, "managed-virtual-companion-payload.txt"), message);
        return message;
    }
}
