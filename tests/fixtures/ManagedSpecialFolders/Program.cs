using System;
using System.IO;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
string startup = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
string documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
string common = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
string programs = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
string virtualFolder = Environment.GetFolderPath(Environment.SpecialFolder.MyComputer);
string created = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData,
    Environment.SpecialFolderOption.Create);
string unverified = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData,
    Environment.SpecialFolderOption.DoNotVerify);
string tag = "emumee-special-" + Environment.GetEnvironmentVariable("COMPUTERNAME");

File.WriteAllText(Path.Combine(roaming, tag + "-roaming.txt"), "roaming");
File.WriteAllText(Path.Combine(local, tag + "-local.txt"), "local");
File.WriteAllText(Path.Combine(startup, tag + "-startup.txt"), "startup");
File.WriteAllText(Path.Combine(desktop, tag + "-desktop.txt"), "desktop");
File.WriteAllText(Path.Combine(documents, tag + "-documents.txt"), "documents");
File.WriteAllText(Path.Combine(profile, tag + "-profile.txt"), "profile");
File.WriteAllText(Path.Combine(roaming, tag + "-created.txt"), created);
File.WriteAllText(Path.Combine(roaming, tag + "-unverified.txt"), unverified);
File.WriteAllText(Path.Combine(roaming, tag + "-system.txt"),
    common + "|" + windows + "|" + system + "|" + programs);

bool invalidFolder = false;
bool invalidOption = false;
try
{
    Environment.GetFolderPath((Environment.SpecialFolder)9999);
}
catch (ArgumentException)
{
    invalidFolder = true;
}
try
{
    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData,
        (Environment.SpecialFolderOption)1234);
}
catch (ArgumentException)
{
    invalidOption = true;
}
File.WriteAllText(Path.Combine(roaming, tag + "-state.txt"),
    Directory.Exists(roaming) && Directory.Exists(local) && Directory.Exists(startup)
    && Directory.Exists(desktop) && Directory.Exists(documents)
    && Directory.Exists(profile) && String.IsNullOrEmpty(virtualFolder)
    && invalidFolder && invalidOption ? "folders-ok;invalid-folder;invalid-option" : "folders-bad");
