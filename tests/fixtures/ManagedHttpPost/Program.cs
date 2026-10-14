using System;
using System.IO;
using System.Net.Http;
using System.Text;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string baseUrl = "http://" + Environment.GetEnvironmentVariable("COMPUTERNAME");
using var client = new HttpClient();
bool denied = false;
bool success = false;
try
{
    string json = "{\"safe\":\"é\"}";
    using var textContent = new StringContent(json, Encoding.UTF8, "application/json");
    using var first = client.PostAsync(baseUrl + "/json", textContent).GetAwaiter().GetResult();
    string echoed = first.Content.ReadAsStringAsync().GetAwaiter().GetResult();
    success = first.IsSuccessStatusCode && (int)first.StatusCode == 201 && echoed == json;

    byte[] data = { 0, (byte)'A', (byte)'B', (byte)'C', 0 };
    using var byteContent = new ByteArrayContent(data, 1, 3);
    data[2] = (byte)'Z';
    using var second = client.PostAsync(baseUrl + "/binary", byteContent).GetAwaiter().GetResult();
    byte[] received = second.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
    success = success && second.IsSuccessStatusCode && (int)second.StatusCode == 202 &&
              received.Length == 3 && received[0] == (byte)'A' &&
              received[1] == (byte)'Z' && received[2] == (byte)'C';
    File.WriteAllBytes(Path.Combine(roaming, "managed-post-binary.bin"), received);
}
catch (HttpRequestException)
{
    denied = true;
}
File.WriteAllText(Path.Combine(roaming, "managed-post-state.txt"),
                  denied ? "denied" : success ? "posted" : "unexpected");
