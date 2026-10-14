using System;
using System.IO;
using System.Net.Http;
using System.Text;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string url = "http://" + Environment.GetEnvironmentVariable("COMPUTERNAME") + "/send";
using var client = new HttpClient();
client.DefaultRequestHeaders.Add("X-Client", "alpha");
using var request = new HttpRequestMessage(HttpMethod.Post, url);
request.Headers.Add("X-Request", "beta");
request.Headers.Add("X-Multi", "one");
request.Headers.Add("X-Multi", "two");
request.Content = new StringContent("PING", Encoding.UTF8, "text/plain");
bool denied = false;
bool success = false;
try
{
    using var response = client.SendAsync(request).GetAwaiter().GetResult();
    byte[] body = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
    success = response.IsSuccessStatusCode && (int)response.StatusCode == 201 &&
              body.Length == 4 && body[0] == (byte)'P' && body[3] == (byte)'G';
    File.WriteAllBytes(Path.Combine(roaming, "managed-send-response.bin"), body);
    bool reuseCaught = false;
    try
    {
        client.SendAsync(request);
    }
    catch (InvalidOperationException)
    {
        reuseCaught = true;
    }
    success = success && reuseCaught;
}
catch (HttpRequestException)
{
    denied = true;
}
File.WriteAllText(Path.Combine(roaming, "managed-send-state.txt"),
                  denied ? "denied" : success ? "sent" : "unexpected");
