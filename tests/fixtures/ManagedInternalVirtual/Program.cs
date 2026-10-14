using System;
using System.IO;

BaseStage stage = new DerivedStage("derived");
string derived = stage.Run();
BaseStage shadow = new ShadowStage("shadow");
string baseSlot = shadow.Run();
string fixedResult = shadow.Fixed();
BaseStage shadowChild = new ShadowChildStage("shadow-child");
string childBaseSlot = shadowChild.Run();
bool nullCaught = false;
try
{
    BaseStage? absent = null;
    absent!.Run();
}
catch (NullReferenceException)
{
    nullCaught = true;
}
string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
File.WriteAllText(Path.Combine(roaming, "managed-internal-virtual-state.txt"),
                  derived + ";" + baseSlot + ";" + fixedResult + ";" + childBaseSlot +
                  (nullCaught ? ";null" : ";missing"));

public class BaseStage
{
    protected readonly string message;

    public BaseStage(string message) { this.message = message; }
    public virtual string Run() => "base";
    public string Fixed() => "fixed";
}

public sealed class DerivedStage : BaseStage
{
    public DerivedStage(string message) : base(message) { }

    public override string Run()
    {
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        File.WriteAllText(Path.Combine(roaming, "managed-internal-virtual-payload.txt"), message);
        return message + ":" + base.Run();
    }
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
