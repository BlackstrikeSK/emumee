using System;
using System.IO;
using System.Net.Http;
using System.Text;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string host = Environment.GetEnvironmentVariable("COMPUTERNAME")!;
using var client = new HttpClient();
client.BaseAddress = new Uri("http://" + host + "/api/v1/");
string first = "missing";
string root = "missing";
string sent = "missing";
try
{
    first = client.GetStringAsync("first").GetAwaiter().GetResult();
}
catch (HttpRequestException)
{
    first = "denied";
}
try
{
    root = client.GetStringAsync("/root").GetAwaiter().GetResult();
}
catch (HttpRequestException)
{
    root = "denied";
}
using (var request = new HttpRequestMessage(HttpMethod.Post, "../upload"))
{
    request.Content = new StringContent("PING", Encoding.UTF8, "text/plain");
    try
    {
        using var response = client.SendAsync(request).GetAwaiter().GetResult();
        sent = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    }
    catch (HttpRequestException)
    {
        sent = "denied";
    }
}
bool lateBlocked = false;
try
{
    client.BaseAddress = new Uri("http://" + host + "/changed/");
}
catch (InvalidOperationException)
{
    lateBlocked = true;
}
File.WriteAllText(Path.Combine(roaming, "managed-http-base-state.txt"),
                  first + ";" + root + ";" + sent + ";" +
                  (lateBlocked ? "locked" : "mutable"));
