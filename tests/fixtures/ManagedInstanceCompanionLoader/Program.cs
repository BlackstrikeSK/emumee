using System;
using System.IO;
using Companion;

bool nullCaught = false;
try
{
    Stage? absent = null;
    absent!.Run();
}
catch (NullReferenceException)
{
    nullCaught = true;
}
Stage stage = new("guest instance ran");
string result = stage.Run();
string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
File.WriteAllText(Path.Combine(roaming, "managed-instance-companion-state.txt"),
                  result + (nullCaught ? ";null" : ";missing"));
