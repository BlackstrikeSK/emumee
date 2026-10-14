using System;
using System.IO;
using System.Reflection;

string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
using Stream source = Assembly.GetExecutingAssembly().GetManifestResourceStream("harmless-native.exe")!;
using MemoryStream destination = new();
source.CopyTo(destination);
byte[] payload = destination.ToArray();
File.WriteAllBytes(Path.Combine(roaming, "managed-resource-native.exe"), payload);
File.WriteAllText(Path.Combine(roaming, "managed-resource-native-state.txt"),
                  payload.Length > 512 && payload[0] == (byte)'M' && payload[1] == (byte)'Z'
                  ? "resource-pe-ok" : "wrong");
