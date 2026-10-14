// See https://aka.ms/new-console-template for more information
using System;
using System.IO;
using System.Text;

Console.WriteLine("emumee managed fixture");
byte[] decoded = Convert.FromBase64String("bWFuYWdlZCBwYXlsb2FkIG1hcmtlcg==");
string text = Encoding.UTF8.GetString(decoded);
File.WriteAllText("C:\\Users\\Alex\\Downloads\\managed-output.txt", text);
