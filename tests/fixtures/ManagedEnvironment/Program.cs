using System;
using System.IO;

string tag = "emumee-env-" + Environment.GetEnvironmentVariable("COMPUTERNAME");
string appdata = Environment.GetEnvironmentVariable("APPDATA")!;
Environment.SetEnvironmentVariable("EMUMEE_GUEST_ONLY", "guest-value");
Environment.SetEnvironmentVariable("USERNAME", "guest-user", EnvironmentVariableTarget.Process);
string path = Environment.ExpandEnvironmentVariables("%APPDATA%\\" + tag + ".txt");
string payload = Environment.ExpandEnvironmentVariables(
    "%EMUMEE_GUEST_ONLY%|%EMUMEE_MISSING%|%USERNAME%");
File.WriteAllText(path, payload);
bool getOk = Environment.GetEnvironmentVariable("EMUMEE_GUEST_ONLY",
    EnvironmentVariableTarget.Process) == "guest-value";
bool pathOk = path == Path.Combine(appdata, tag + ".txt") &&
    Environment.ExpandEnvironmentVariables("%SystemDrive%\\Windows") == @"C:\Windows";
Environment.SetEnvironmentVariable("EMUMEE_GUEST_ONLY", null,
    EnvironmentVariableTarget.Process);
bool deleted = Environment.GetEnvironmentVariable("EMUMEE_GUEST_ONLY") == null &&
    Environment.ExpandEnvironmentVariables("%EMUMEE_GUEST_ONLY%") == "%EMUMEE_GUEST_ONLY%";
bool nullError = false;
try
{
    Environment.ExpandEnvironmentVariables(null!);
}
catch (ArgumentNullException)
{
    nullError = true;
}
bool nameError = false;
try
{
    Environment.SetEnvironmentVariable("", "x");
}
catch (ArgumentException)
{
    nameError = true;
}
File.WriteAllText(Path.Combine(appdata, tag + "-state.txt"),
    getOk && pathOk && deleted && nullError && nameError
    ? "get-ok;path-ok;deleted;null-error;name-error" : "environment-bad");
