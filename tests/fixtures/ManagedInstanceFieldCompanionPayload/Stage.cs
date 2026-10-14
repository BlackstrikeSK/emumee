namespace InstanceFieldPayload;

public sealed class Stage
{
    public int Count;
    public string? Marker;

    public Stage() => Marker = "ready";
}
