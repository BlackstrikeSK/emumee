#pragma warning disable SYSLIB0014
using System.IO;
using System.Net;

var client = new WebClient();
var text = client.DownloadString("https://example.com/");
File.WriteAllText(@"C:\Users\Alex\Downloads\network-response.txt", text);
