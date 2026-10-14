using System;
using System.IO;
using System.Net.Http;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string baseUrl = "http://" + Environment.GetEnvironmentVariable("COMPUTERNAME");
using var client = new HttpClient();
bool denied = false;
bool success = false;
try
{
    using var response = client.GetAsync(baseUrl + "/payload").GetAwaiter().GetResult();
    byte[] data = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
    string text = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    success = response.IsSuccessStatusCode && (int)response.StatusCode == 200 &&
              data.Length == 6 && data[0] == (byte)'A' && text == "ABCDEF";
    response.EnsureSuccessStatusCode();
    data[0] = (byte)'Z';
    File.WriteAllBytes(Path.Combine(roaming, "managed-response-edited.bin"), data);

    using var missing = client.GetAsync(baseUrl + "/missing").GetAwaiter().GetResult();
    string missingText = missing.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    bool missingCaught = false;
    try
    {
        missing.EnsureSuccessStatusCode();
    }
    catch (HttpRequestException)
    {
        missingCaught = true;
    }
    success = success && !missing.IsSuccessStatusCode &&
              (int)missing.StatusCode == 404 && missingText == "MISSING" && missingCaught;
}
catch (HttpRequestException)
{
    denied = true;
}
File.WriteAllText(Path.Combine(roaming, "managed-response-state.txt"),
                  denied ? "denied" : success ? "downloaded" : "unexpected");
