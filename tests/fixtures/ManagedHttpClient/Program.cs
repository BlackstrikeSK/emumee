using System;
using System.IO;
using System.Net.Http;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
string url = "http://" + Environment.GetEnvironmentVariable("COMPUTERNAME") + "/payload";
using var client = new HttpClient();
bool dataDenied = false;
bool stringDenied = false;
bool dataGood = false;
bool stringGood = false;
try
{
    byte[] bytes = client.GetByteArrayAsync(url).GetAwaiter().GetResult();
    dataGood = bytes.Length == 6 && bytes[0] == (byte)'A';
    bytes[0] = (byte)'Z';
    File.WriteAllBytes(Path.Combine(roaming, "managed-http-edited.bin"), bytes);
}
catch (HttpRequestException)
{
    dataDenied = true;
}
try
{
    string text = client.GetStringAsync(url).GetAwaiter().GetResult();
    stringGood = text == "ABCDEF";
}
catch (HttpRequestException)
{
    stringDenied = true;
}
File.WriteAllText(Path.Combine(roaming, "managed-http-state.txt"),
    dataDenied && stringDenied ? "denied" :
    !dataDenied && !stringDenied && dataGood && stringGood ? "downloaded" : "unexpected");
