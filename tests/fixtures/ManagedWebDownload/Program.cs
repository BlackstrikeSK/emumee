#pragma warning disable SYSLIB0014
using System.IO;
using System.Net;

const string downloaded = @"C:\Users\Alex\Downloads\managed-web-downloaded.bin";
const string edited = @"C:\Users\Alex\Downloads\managed-web-edited.bin";
const string state = @"C:\Users\Alex\Downloads\managed-web-state.txt";
string url = "http://" + System.Environment.GetEnvironmentVariable("COMPUTERNAME") + "/payload";
var client = new WebClient();
bool dataDenied = false;
bool fileDenied = false;
bool mutable = false;
try
{
    byte[] bytes = client.DownloadData(url);
    bytes[0] = (byte)'Z';
    mutable = bytes[0] == (byte)'Z';
    File.WriteAllBytes(edited, bytes);
}
catch (WebException)
{
    dataDenied = true;
}
try
{
    client.DownloadFile(new System.Uri(url), downloaded);
}
catch (WebException)
{
    fileDenied = true;
}
File.WriteAllText(state,
    dataDenied && fileDenied ? "denied" :
    !dataDenied && !fileDenied && mutable && File.ReadAllBytes(downloaded)[0] == (byte)'A'
        ? "downloaded;mutable;matched" : "unexpected");
