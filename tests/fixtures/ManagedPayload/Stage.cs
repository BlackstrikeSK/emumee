using System.IO;

namespace Payload;

public class Stage
{
    private readonly string marker;

    public Stage()
    {
        marker = "harmless reflected";
    }

    public string Run(string suffix)
    {
        File.WriteAllText(@"C:\Users\Alex\Downloads\reflected-stage.txt", marker + suffix);
        return "instance returned";
    }

    public static string CreateAndRun()
    {
        return new Stage().Run(" internal");
    }
}
